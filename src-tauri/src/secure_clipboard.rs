use std::{
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

pub const SECURE_CLIPBOARD_CLEAR_AFTER_SECONDS: u64 = 30;

const SECURE_CLIPBOARD_CLEAR_AFTER: Duration =
    Duration::from_secs(SECURE_CLIPBOARD_CLEAR_AFTER_SECONDS);

const SECURE_CLIPBOARD_RETRY_AFTER: Duration = Duration::from_millis(250);

const OWNERSHIP_MARKER_BYTES: usize = 16;

#[derive(Debug, Error)]
pub enum SecureClipboardError {
    #[error("system clipboard is unavailable")]
    Unavailable,

    #[error("clipboard ownership sequence is unavailable")]
    SequenceUnavailable,

    #[error("clipboard privacy protection is unavailable")]
    PrivacyProtectionUnavailable,

    #[error("clipboard ownership marker is unavailable")]
    OwnershipMarkerUnavailable,

    #[error("secure clipboard state is unavailable")]
    StateUnavailable,

    #[error("secure clipboard is unsupported on this platform")]
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClipboardOwnership {
    sequence: u32,
    marker: [u8; OWNERSHIP_MARKER_BYTES],
}

#[derive(Clone)]
pub struct SecureClipboard {
    shared: Arc<ClipboardShared>,
}

struct ClipboardShared {
    state: Mutex<ClipboardState>,
    wake: Condvar,
}

#[derive(Default)]
struct ClipboardState {
    generation: u64,
    expected_ownership: Option<ClipboardOwnership>,
    deadline: Option<Instant>,
}

impl ClipboardState {
    fn record_copy(&mut self, ownership: ClipboardOwnership, deadline: Instant) -> u64 {
        self.generation = self.generation.wrapping_add(1);

        if self.generation == 0 {
            self.generation = 1;
        }

        self.expected_ownership = Some(ownership);

        self.deadline = Some(deadline);

        self.generation
    }

    fn task(&self) -> Option<(u64, ClipboardOwnership, Instant)> {
        Some((self.generation, self.expected_ownership?, self.deadline?))
    }

    fn finish_generation(&mut self, generation: u64) {
        if self.generation != generation {
            return;
        }

        self.expected_ownership = None;

        self.deadline = None;
    }

    fn retry_generation(&mut self, generation: u64, deadline: Instant) {
        if self.generation == generation && self.expected_ownership.is_some() {
            self.deadline = Some(deadline);
        }
    }
}

fn ownership_matches(
    expected: ClipboardOwnership,
    current_sequence: u32,
    current_marker: Option<&[u8]>,
) -> bool {
    if current_sequence == expected.sequence {
        return true;
    }

    current_marker.is_some_and(|marker| marker == expected.marker.as_slice())
}

impl Default for SecureClipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureClipboard {
    fn new() -> Self {
        let shared = Arc::new(ClipboardShared {
            state: Mutex::new(ClipboardState::default()),
            wake: Condvar::new(),
        });

        let worker_shared = Arc::clone(&shared);

        let _worker = thread::Builder::new()
            .name("localvault-secure-clipboard".to_owned())
            .spawn(move || {
                clipboard_worker(worker_shared);
            })
            .expect("failed to start LocalVault secure clipboard worker");

        Self { shared }
    }

    pub fn copy_secret(&self, secret: &str) -> Result<u64, SecureClipboardError> {
        let ownership = platform::write_secret(secret)?;

        let mut state = match self.shared.state.lock() {
            Ok(state) => state,

            Err(_) => {
                let _ = platform::clear_if_owned(ownership);

                return Err(SecureClipboardError::StateUnavailable);
            }
        };

        state.record_copy(ownership, Instant::now() + SECURE_CLIPBOARD_CLEAR_AFTER);

        self.shared.wake.notify_all();

        Ok(SECURE_CLIPBOARD_CLEAR_AFTER_SECONDS)
    }

    pub fn clear_owned(&self) -> Result<bool, SecureClipboardError> {
        let (generation, ownership) = {
            let state = self.lock_state()?;

            let Some((generation, ownership, _)) = state.task() else {
                return Ok(false);
            };

            (generation, ownership)
        };

        let result = platform::clear_if_owned(ownership);

        let mut state = self.lock_state()?;

        if state.generation == generation && state.expected_ownership == Some(ownership) {
            match &result {
                Ok(_) => {
                    state.finish_generation(generation);
                }

                Err(_) => {
                    state.retry_generation(
                        generation,
                        Instant::now() + SECURE_CLIPBOARD_RETRY_AFTER,
                    );
                }
            }

            self.shared.wake.notify_all();
        }

        result
    }

    pub fn clear_owned_best_effort(&self) {
        let _ = self.clear_owned();
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ClipboardState>, SecureClipboardError> {
        self.shared
            .state
            .lock()
            .map_err(|_| SecureClipboardError::StateUnavailable)
    }
}

fn clipboard_worker(shared: Arc<ClipboardShared>) {
    loop {
        let (generation, ownership) = {
            let mut state = match shared.state.lock() {
                Ok(state) => state,

                Err(poisoned) => poisoned.into_inner(),
            };

            loop {
                let Some((generation, ownership, deadline)) = state.task() else {
                    state = match shared.wake.wait(state) {
                        Ok(state) => state,

                        Err(poisoned) => poisoned.into_inner(),
                    };

                    continue;
                };

                let now = Instant::now();

                if now < deadline {
                    let wait_for = deadline.saturating_duration_since(now);

                    let (next_state, _) = match shared.wake.wait_timeout(state, wait_for) {
                        Ok(result) => result,

                        Err(poisoned) => poisoned.into_inner(),
                    };

                    state = next_state;

                    continue;
                }

                break (generation, ownership);
            }
        };

        let result = platform::clear_if_owned(ownership);

        let mut state = match shared.state.lock() {
            Ok(state) => state,

            Err(poisoned) => poisoned.into_inner(),
        };

        if state.generation != generation || state.expected_ownership != Some(ownership) {
            continue;
        }

        match result {
            Ok(_) => {
                state.finish_generation(generation);
            }

            Err(_) => {
                state.retry_generation(generation, Instant::now() + SECURE_CLIPBOARD_RETRY_AFTER);
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use clipboard_win::{raw, Clipboard};

    use super::{
        ownership_matches, ClipboardOwnership, SecureClipboardError, OWNERSHIP_MARKER_BYTES,
    };

    const EXCLUDE_FROM_MONITOR_FORMAT: &str = "ExcludeClipboardContentFromMonitorProcessing";

    const INCLUDE_IN_HISTORY_FORMAT: &str = "CanIncludeInClipboardHistory";

    const UPLOAD_TO_CLOUD_FORMAT: &str = "CanUploadToCloudClipboard";

    const OWNERSHIP_FORMAT: &str = "LocalVaultSecureClipboardOwnershipV1";

    struct ClipboardFormats {
        exclude_from_monitor: u32,
        include_in_history: u32,
        upload_to_cloud: u32,
        ownership: u32,
    }

    fn clipboard_formats() -> Result<ClipboardFormats, SecureClipboardError> {
        let exclude_from_monitor = raw::register_format(EXCLUDE_FROM_MONITOR_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        let include_in_history = raw::register_format(INCLUDE_IN_HISTORY_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        let upload_to_cloud = raw::register_format(UPLOAD_TO_CLOUD_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        let ownership = raw::register_format(OWNERSHIP_FORMAT)
            .ok_or(SecureClipboardError::OwnershipMarkerUnavailable)?
            .get();

        Ok(ClipboardFormats {
            exclude_from_monitor,
            include_in_history,
            upload_to_cloud,
            ownership,
        })
    }

    pub fn write_secret(secret: &str) -> Result<ClipboardOwnership, SecureClipboardError> {
        let formats = clipboard_formats()?;

        let mut marker = [0_u8; OWNERSHIP_MARKER_BYTES];

        getrandom::fill(&mut marker)
            .map_err(|_| SecureClipboardError::OwnershipMarkerUnavailable)?;

        let _clipboard =
            Clipboard::new_attempts(10).map_err(|_| SecureClipboardError::Unavailable)?;

        raw::empty().map_err(|_| SecureClipboardError::Unavailable)?;

        if raw::set_string(secret).is_err() {
            let _ = raw::empty();

            return Err(SecureClipboardError::Unavailable);
        }

        let exclude_marker = [1_u8];

        let disabled = 0_u32.to_ne_bytes();

        let write_result = raw::set_without_clear(formats.exclude_from_monitor, &exclude_marker)
            .and_then(|_| raw::set_without_clear(formats.include_in_history, &disabled))
            .and_then(|_| raw::set_without_clear(formats.upload_to_cloud, &disabled))
            .and_then(|_| raw::set_without_clear(formats.ownership, &marker));

        if write_result.is_err() {
            let _ = raw::empty();

            return Err(SecureClipboardError::PrivacyProtectionUnavailable);
        }

        let Some(sequence) = raw::seq_num() else {
            let _ = raw::empty();

            return Err(SecureClipboardError::SequenceUnavailable);
        };

        Ok(ClipboardOwnership {
            sequence: sequence.get(),
            marker,
        })
    }

    pub fn clear_if_owned(expected: ClipboardOwnership) -> Result<bool, SecureClipboardError> {
        let formats = clipboard_formats()?;

        let _clipboard =
            Clipboard::new_attempts(10).map_err(|_| SecureClipboardError::Unavailable)?;

        let Some(current_sequence) = raw::seq_num() else {
            return Err(SecureClipboardError::SequenceUnavailable);
        };

        if current_sequence.get() == expected.sequence {
            raw::empty().map_err(|_| SecureClipboardError::Unavailable)?;

            return Ok(true);
        }

        /*
         * Windows or clipboard services may legitimately alter
         * the sequence after our write. In that situation the
         * private random ownership format is the stronger proof
         * that the current clipboard still belongs to LocalVault.
         *
         * A normal user copy empties/replaces the clipboard and
         * removes this private format, so unrelated newer content
         * is preserved.
         */
        let mut current_marker = [0_u8; OWNERSHIP_MARKER_BYTES];

        let marker = match raw::get(formats.ownership, &mut current_marker) {
            Ok(read) if read == current_marker.len() => Some(current_marker.as_slice()),

            _ => None,
        };

        if !ownership_matches(expected, current_sequence.get(), marker) {
            return Ok(false);
        }

        raw::empty().map_err(|_| SecureClipboardError::Unavailable)?;

        Ok(true)
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{ClipboardOwnership, SecureClipboardError};

    pub fn write_secret(_secret: &str) -> Result<ClipboardOwnership, SecureClipboardError> {
        Err(SecureClipboardError::Unsupported)
    }

    pub fn clear_if_owned(_expected: ClipboardOwnership) -> Result<bool, SecureClipboardError> {
        Err(SecureClipboardError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ownership(sequence: u32, marker: u8) -> ClipboardOwnership {
        ClipboardOwnership {
            sequence,
            marker: [marker; OWNERSHIP_MARKER_BYTES],
        }
    }

    #[test]
    fn clipboard_state_starts_without_owned_content() {
        let state = ClipboardState::default();

        assert!(state.task().is_none());
    }

    #[test]
    fn newer_copy_supersedes_older_generation() {
        let mut state = ClipboardState::default();

        let now = Instant::now();

        let first = state.record_copy(ownership(101, 1), now + Duration::from_secs(10));

        let second = state.record_copy(ownership(202, 2), now + Duration::from_secs(20));

        assert_ne!(first, second);

        let (generation, current, _) = state.task().unwrap();

        assert_eq!(generation, second);

        assert_eq!(current, ownership(202, 2));
    }

    #[test]
    fn finishing_old_generation_does_not_disown_new_copy() {
        let mut state = ClipboardState::default();

        let now = Instant::now();

        let first = state.record_copy(ownership(101, 1), now + Duration::from_secs(10));

        let second = state.record_copy(ownership(202, 2), now + Duration::from_secs(20));

        state.finish_generation(first);

        let (generation, current, _) = state.task().unwrap();

        assert_eq!(generation, second);

        assert_eq!(current, ownership(202, 2));
    }

    #[test]
    fn same_sequence_proves_ownership_without_marker_fallback() {
        let expected = ownership(101, 7);

        assert!(ownership_matches(expected, 101, None,));
    }

    #[test]
    fn matching_private_marker_proves_ownership_after_sequence_change() {
        let expected = ownership(101, 7);

        assert!(ownership_matches(
            expected,
            202,
            Some(expected.marker.as_slice(),),
        ));
    }

    #[test]
    fn newer_unrelated_clipboard_is_not_owned() {
        let expected = ownership(101, 7);

        let different = ownership(202, 9);

        assert!(!ownership_matches(expected, 202, None,));

        assert!(!ownership_matches(
            expected,
            202,
            Some(different.marker.as_slice(),),
        ));
    }
}
