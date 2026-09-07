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

#[derive(Debug, Error)]
pub enum SecureClipboardError {
    #[error("system clipboard is unavailable")]
    Unavailable,

    #[error("clipboard ownership sequence is unavailable")]
    SequenceUnavailable,

    #[error("clipboard privacy protection is unavailable")]
    PrivacyProtectionUnavailable,

    #[error("secure clipboard state is unavailable")]
    StateUnavailable,

    #[error("secure clipboard is unsupported on this platform")]
    Unsupported,
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
    expected_sequence: Option<u32>,
    deadline: Option<Instant>,
}

impl ClipboardState {
    fn record_copy(&mut self, sequence: u32, deadline: Instant) -> u64 {
        self.generation = self.generation.wrapping_add(1);

        if self.generation == 0 {
            self.generation = 1;
        }

        self.expected_sequence = Some(sequence);

        self.deadline = Some(deadline);

        self.generation
    }

    fn task(&self) -> Option<(u64, u32, Instant)> {
        Some((self.generation, self.expected_sequence?, self.deadline?))
    }

    fn finish_generation(&mut self, generation: u64) {
        if self.generation != generation {
            return;
        }

        self.expected_sequence = None;
        self.deadline = None;
    }

    fn retry_generation(&mut self, generation: u64, deadline: Instant) {
        if self.generation == generation && self.expected_sequence.is_some() {
            self.deadline = Some(deadline);
        }
    }
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
        let sequence = platform::write_secret(secret)?;

        let mut state = match self.shared.state.lock() {
            Ok(state) => state,

            Err(_) => {
                let _ = platform::clear_if_sequence(sequence);

                return Err(SecureClipboardError::StateUnavailable);
            }
        };

        state.record_copy(sequence, Instant::now() + SECURE_CLIPBOARD_CLEAR_AFTER);

        self.shared.wake.notify_all();

        Ok(SECURE_CLIPBOARD_CLEAR_AFTER_SECONDS)
    }

    pub fn clear_owned(&self) -> Result<bool, SecureClipboardError> {
        let (generation, sequence) = {
            let state = self.lock_state()?;

            let Some((generation, sequence, _)) = state.task() else {
                return Ok(false);
            };

            (generation, sequence)
        };

        let result = platform::clear_if_sequence(sequence);

        let mut state = self.lock_state()?;

        if state.generation == generation && state.expected_sequence == Some(sequence) {
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
        let (generation, sequence) = {
            let mut state = match shared.state.lock() {
                Ok(state) => state,

                Err(poisoned) => poisoned.into_inner(),
            };

            loop {
                let Some((generation, sequence, deadline)) = state.task() else {
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

                break (generation, sequence);
            }
        };

        let result = platform::clear_if_sequence(sequence);

        let mut state = match shared.state.lock() {
            Ok(state) => state,

            Err(poisoned) => poisoned.into_inner(),
        };

        if state.generation != generation || state.expected_sequence != Some(sequence) {
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

    use super::SecureClipboardError;

    const EXCLUDE_FROM_MONITOR_FORMAT: &str = "ExcludeClipboardContentFromMonitorProcessing";

    const INCLUDE_IN_HISTORY_FORMAT: &str = "CanIncludeInClipboardHistory";

    const UPLOAD_TO_CLOUD_FORMAT: &str = "CanUploadToCloudClipboard";

    struct PrivacyFormats {
        exclude_from_monitor: u32,
        include_in_history: u32,
        upload_to_cloud: u32,
    }

    fn privacy_formats() -> Result<PrivacyFormats, SecureClipboardError> {
        let exclude_from_monitor = raw::register_format(EXCLUDE_FROM_MONITOR_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        let include_in_history = raw::register_format(INCLUDE_IN_HISTORY_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        let upload_to_cloud = raw::register_format(UPLOAD_TO_CLOUD_FORMAT)
            .ok_or(SecureClipboardError::PrivacyProtectionUnavailable)?
            .get();

        Ok(PrivacyFormats {
            exclude_from_monitor,
            include_in_history,
            upload_to_cloud,
        })
    }

    pub fn write_secret(secret: &str) -> Result<u32, SecureClipboardError> {
        let privacy = privacy_formats()?;

        let _clipboard =
            Clipboard::new_attempts(10).map_err(|_| SecureClipboardError::Unavailable)?;

        raw::empty().map_err(|_| SecureClipboardError::Unavailable)?;

        if raw::set_string(secret).is_err() {
            let _ = raw::empty();

            return Err(SecureClipboardError::Unavailable);
        }

        let exclude_marker = [1_u8];

        let disabled = 0_u32.to_ne_bytes();

        let privacy_result = raw::set_without_clear(privacy.exclude_from_monitor, &exclude_marker)
            .and_then(|_| raw::set_without_clear(privacy.include_in_history, &disabled))
            .and_then(|_| raw::set_without_clear(privacy.upload_to_cloud, &disabled));

        if privacy_result.is_err() {
            let _ = raw::empty();

            return Err(SecureClipboardError::PrivacyProtectionUnavailable);
        }

        let Some(sequence) = raw::seq_num() else {
            let _ = raw::empty();

            return Err(SecureClipboardError::SequenceUnavailable);
        };

        Ok(sequence.get())
    }

    pub fn clear_if_sequence(expected_sequence: u32) -> Result<bool, SecureClipboardError> {
        let _clipboard =
            Clipboard::new_attempts(10).map_err(|_| SecureClipboardError::Unavailable)?;

        let Some(current_sequence) = raw::seq_num() else {
            return Err(SecureClipboardError::SequenceUnavailable);
        };

        if current_sequence.get() != expected_sequence {
            return Ok(false);
        }

        raw::empty().map_err(|_| SecureClipboardError::Unavailable)?;

        Ok(true)
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::SecureClipboardError;

    pub fn write_secret(_secret: &str) -> Result<u32, SecureClipboardError> {
        Err(SecureClipboardError::Unsupported)
    }

    pub fn clear_if_sequence(_expected_sequence: u32) -> Result<bool, SecureClipboardError> {
        Err(SecureClipboardError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_state_starts_without_owned_content() {
        let state = ClipboardState::default();

        assert!(state.task().is_none());
    }

    #[test]
    fn newer_copy_supersedes_older_generation() {
        let mut state = ClipboardState::default();

        let now = Instant::now();

        let first = state.record_copy(101, now + Duration::from_secs(10));

        let second = state.record_copy(202, now + Duration::from_secs(20));

        assert_ne!(first, second);

        let (generation, sequence, _) = state.task().unwrap();

        assert_eq!(generation, second);

        assert_eq!(sequence, 202);
    }

    #[test]
    fn finishing_old_generation_does_not_disown_new_copy() {
        let mut state = ClipboardState::default();

        let now = Instant::now();

        let first = state.record_copy(101, now + Duration::from_secs(10));

        let second = state.record_copy(202, now + Duration::from_secs(20));

        state.finish_generation(first);

        let (generation, sequence, _) = state.task().unwrap();

        assert_eq!(generation, second);

        assert_eq!(sequence, 202);
    }
}
