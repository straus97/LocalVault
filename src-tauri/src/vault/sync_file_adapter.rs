//! Read-only Windows filesystem adapter for a future user-selected encrypted
//! synchronization artifact (Stage 1U-4, slice B1d).
//!
//! Infrastructure only. Nothing here is connected to unlock, save, a Tauri
//! command, the UI, the sync-state store, a provider or the network, and nothing
//! calls it yet. It never writes, creates, truncates, renames or removes
//! anything, and takes no lock that could block a synchronization client.
//!
//! # What a result means
//!
//! [`SyncFileTarget::read`] returns a [`SyncFileRead`]:
//!
//! * [`Present`](SyncFileRead::Present): a bounded read of a regular, non-reparse
//!   file completed through **one** opened handle, and the observable
//!   size/timestamp checks before and after the read agreed. The bytes are the
//!   *candidate* encrypted bytes. **They are not authenticated**: only
//!   `localvault_core::sync::inspect_remote_bytes` can do that, and reading a
//!   path proves nothing about who wrote it.
//! * [`AbsentOnDisk`](SyncFileRead::AbsentOnDisk): the immediate parent chain is
//!   a series of plain, readable directories and the target name was not found in
//!   it. This is a fact about **this machine's folder at this instant**. It is
//!   deliberately not convertible to `RemoteEvidence::Absent`: a synchronized
//!   folder may be offline, stale, delayed, unhydrated or incomplete, so a local
//!   miss is not the provider's authoritative statement and must never, by
//!   itself, authorize an initial publication. No `From`/`Into` to core remote
//!   evidence exists.
//! * [`Unavailable`](SyncFileRead::Unavailable): everything else, with a coarse
//!   reason. Unavailable is never absent.
//!
//! # Target and bytes cannot be mixed
//!
//! A [`SyncFileTarget`] is the only way to read, and the only way to obtain a
//! [`PresentFile`] is [`SyncFileTarget::read`]. A `PresentFile` owns the target
//! locator **and** the bytes read from that very path; its fields are private,
//! it has no public constructor and no way to take the bytes apart from the
//! locator. A caller therefore cannot label caller-supplied bytes as a verified
//! filesystem read, or pair the bytes of target A with the identity of target B.
//!
//! # Locator
//!
//! The locator is the exact string the caller supplied (or the retained
//! [`Locator`] it supplied) and is never canonicalized, lowercased or resolved:
//! canonicalizing would silently follow links and rewrite the retained identity.
//! The path is parsed from the locator, so the locator is the single source of
//! truth. Only forms that name one ordinary file are accepted (absolute, drive or
//! UNC, no `.`/`..`, no alternate data stream, no device namespace, no reserved
//! device name, no trailing dot or space).
//!
//! # Guards, and their limits
//!
//! * Every existing ancestor, the parent chain up to the filesystem root, must be
//!   a plain directory: a junction, symlink or other reparse point, a regular
//!   file or an unreadable component is `Unavailable`. Windows reports "not
//!   found" both for a missing component and for a component that is a regular
//!   file, so a missing path is classified only after every ancestor that does
//!   exist has been shown to be a plain directory.
//! * The target is inspected with `symlink_metadata`, opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` (never followed) and judged again **on the
//!   handle**. A cloud *placeholder* file carries a reparse point and is
//!   therefore rejected, not hydrated; whether to accept one is a provider
//!   decision this slice does not take.
//! * The size is checked from metadata before anything is allocated, the buffer
//!   is sized from the handle's length, and the number of bytes consumed is
//!   capped at that length plus one, independent of metadata, so a file that
//!   grows (to any size) cannot cause unbounded allocation. The limit is the
//!   core [`MAX_ENVELOPE_BYTES`].
//! * Afterwards the handle and the path are inspected again and must still be a
//!   plain file with the same length and the same creation and last-write times,
//!   and the ancestor chain must still be plain. A difference, or a byte count
//!   that differs from the length, is [`UnavailableReason::Changed`].
//!
//! `std::fs` offers **no snapshot isolation**, and stable `std` exposes neither
//! the NTFS file index nor the volume serial number. The read's own change
//! detection is therefore only length and creation/last-write timestamps; a
//! writer that changes content while restoring the same length and timestamps, or
//! a replacement that has the same length and timestamps, is not detectable by it.
//!
//! Separately, and only for initial synchronization binding, the physical facts
//! of the opened file (volume, 128-bit file identifier, link count, filesystem,
//! device locality; see `file_identity`) are queried through Windows FFI **on
//! the same handle that produced the bytes**, and stored privately in the
//! [`PresentFile`]. They never influence classification: a failed lookup is kept
//! as an error beside the bytes, not turned into `Unavailable`, and
//! [`observe_remote_target`](super::session::UnlockedVaultSession::observe_remote_target)
//! never reads them. They are not a snapshot either; they describe the handle at
//! the instant they were read. Every
//! check here is check-then-use: a completed read does not prove the path still
//! refers to the same object, and the ancestor guards do not stop a redirection
//! installed after they ran. The file is opened with the default share mode
//! (read, write and delete shared) so this adapter never blocks a sync client;
//! the price is that the file can change underneath it.
//!
//! # Integration boundary (not done here)
//!
//! A later slice must resolve the user-selected target, compare it with the
//! binding's retained target locator, read it with this adapter, pass
//! [`PresentFile::target`] and [`PresentFile::candidate_raw`] to the
//! session-bound `record_remote_observation`, re-check identity as the provider
//! requires and persist only a core-approved transition. This module must not be
//! reachable from the frontend.
//!
//! Errors and `Debug` output carry fixed categories and `io::ErrorKind` only:
//! never a path, locator, vault identifier or file content.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf, Prefix},
};

use localvault_core::{sync::MAX_ENVELOPE_BYTES, sync_state::Locator};
use thiserror::Error;

use super::file_identity::{HandleFacts, IdentityError};

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Why a path or locator cannot name a sync file. Categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TargetError {
    #[error("the sync target is not a valid locator")]
    InvalidLocator,
    #[error("the sync target is not a valid absolute file path")]
    InvalidPath,
}

/// A filesystem-backed synchronization target: a validated absolute file path
/// together with the exact [`Locator`] it was built from.
#[derive(Clone, PartialEq, Eq)]
pub struct SyncFileTarget {
    locator: Locator,
    path: PathBuf,
}

impl SyncFileTarget {
    /// From a retained locator (for example a binding's target locator). The
    /// locator is kept exactly as given.
    pub fn from_locator(locator: &Locator) -> Result<Self, TargetError> {
        let path = PathBuf::from(locator.as_str());
        validate_target_path(&path)?;

        Ok(Self {
            locator: locator.clone(),
            path,
        })
    }

    /// From a filesystem path. The locator is the path's exact string: no
    /// canonicalization, case change or link resolution happens.
    pub fn from_path(path: &Path) -> Result<Self, TargetError> {
        let text = path.to_str().ok_or(TargetError::InvalidPath)?;
        let locator = Locator::new(text).map_err(|_| TargetError::InvalidLocator)?;

        Self::from_locator(&locator)
    }

    /// The identity this target carries, exactly as supplied.
    pub fn locator(&self) -> &Locator {
        &self.locator
    }

    /// Read the target. Performs no write of any kind. See the module
    /// documentation for what each outcome does and does not establish.
    pub fn read(&self) -> SyncFileRead {
        self.read_with(&mut |_| {})
    }

    /// [`read`](Self::read) with a probe called at fixed stages. The production
    /// probe does nothing; tests use it to change the file at an exact point.
    /// Private, so no caller outside this module can influence a read.
    fn read_with(&self, probe: &mut dyn FnMut(Stage)) -> SyncFileRead {
        #[cfg(not(windows))]
        {
            let _ = probe;
            SyncFileRead::Unavailable(UnavailableReason::Unsupported)
        }

        #[cfg(windows)]
        {
            match self.read_inner(probe) {
                Ok(Outcome::Bytes(candidate, physical)) => SyncFileRead::Present(PresentFile {
                    target: self.locator.clone(),
                    candidate,
                    physical,
                }),
                Ok(Outcome::Absent) => SyncFileRead::AbsentOnDisk,
                Err(reason) => SyncFileRead::Unavailable(reason),
            }
        }
    }

    #[cfg(windows)]
    fn read_inner(&self, probe: &mut dyn FnMut(Stage)) -> Result<Outcome, UnavailableReason> {
        let chain = confirm_ancestors(&self.path)?;

        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return match chain {
                    // The same facts must hold once more: the parent chain was
                    // not swapped while the miss was being established.
                    Chain::Intact => match confirm_ancestors(&self.path)? {
                        Chain::Intact => Ok(Outcome::Absent),
                        Chain::MissingAncestor => Err(UnavailableReason::Changed),
                    },
                    Chain::MissingAncestor => Err(UnavailableReason::ParentMissing),
                };
            }
            Err(error) => return Err(UnavailableReason::Io(error.kind())),
        };

        // The target exists, so a missing ancestor now contradicts the earlier
        // inspection: something changed.
        if matches!(chain, Chain::MissingAncestor) {
            return Err(UnavailableReason::Changed);
        }
        if !is_plain_file(&metadata) {
            return Err(UnavailableReason::UnexpectedObject);
        }
        size_verdict(metadata.len())?;

        let file = open_no_follow(&self.path).map_err(|error| io_reason(&error))?;

        // Judge the opened handle, not the path that may have been swapped.
        let opened = file.metadata().map_err(|error| io_reason(&error))?;
        if !is_plain_file(&opened) {
            return Err(UnavailableReason::UnexpectedObject);
        }
        size_verdict(opened.len())?;

        let before = Stamp::of(&opened);
        if Stamp::of(&metadata) != before {
            return Err(UnavailableReason::Changed);
        }

        probe(Stage::Opened);

        let candidate = read_bounded(&file, before.len)?;

        probe(Stage::Read);

        // The handle, then the path, must still describe the same plain file.
        let after = file.metadata().map_err(|error| io_reason(&error))?;
        if !is_plain_file(&after) || Stamp::of(&after) != before {
            return Err(UnavailableReason::Changed);
        }

        // Physical facts from the very handle that produced `candidate`, while it
        // is still open. A failure is recorded, never turned into a different
        // classification.
        let physical = super::file_identity::facts_of(&file);

        let current = match fs::symlink_metadata(&self.path) {
            Ok(current) => current,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(UnavailableReason::Changed)
            }
            Err(error) => return Err(UnavailableReason::Io(error.kind())),
        };
        if !is_plain_file(&current) || Stamp::of(&current) != before {
            return Err(UnavailableReason::Changed);
        }

        match confirm_ancestors(&self.path)? {
            Chain::Intact => Ok(Outcome::Bytes(candidate, physical)),
            Chain::MissingAncestor => Err(UnavailableReason::Changed),
        }
    }
}

impl fmt::Debug for SyncFileTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncFileTarget(<redacted>)")
    }
}

/// Result of [`SyncFileTarget::read`]. Every variant is distinct; none is an
/// authenticated remote observation.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub enum SyncFileRead {
    /// A bounded read completed. Unauthenticated candidate bytes.
    Present(PresentFile),
    /// Not found in a valid, accessible local parent chain. **Not** a statement
    /// about the provider's remote state and not an authorization to publish.
    AbsentOnDisk,
    /// Nothing may be concluded about the target.
    Unavailable(UnavailableReason),
}

impl fmt::Debug for SyncFileRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present(_) => f.write_str("Present(<redacted>)"),
            Self::AbsentOnDisk => f.write_str("AbsentOnDisk"),
            Self::Unavailable(reason) => write!(f, "Unavailable({reason:?})"),
        }
    }
}

/// The exact bytes read from one filesystem target, inseparable from that
/// target's locator. Constructed only by [`SyncFileTarget::read`].
#[derive(Clone, PartialEq, Eq)]
pub struct PresentFile {
    target: Locator,
    candidate: Vec<u8>,
    /// Facts of the handle that produced `candidate`, or why there are none.
    /// Private, and only [`SyncFileTarget::read`] can set it.
    physical: Result<HandleFacts, IdentityError>,
}

impl PresentFile {
    /// The physical facts of the file these bytes were read from, if they could
    /// be established. Used only by initial binding.
    pub(crate) fn physical(&self) -> Result<&HandleFacts, IdentityError> {
        self.physical.as_ref().map_err(|error| *error)
    }

    /// Test-only seam: replaces the physical facts, to model a lookup failure or
    /// an unsupported volume. No production constructor exists.
    #[cfg(test)]
    pub(crate) fn with_physical_for_test(
        mut self,
        physical: Result<HandleFacts, IdentityError>,
    ) -> Self {
        self.physical = physical;

        self
    }

    /// The locator of the target these bytes were read from.
    pub fn target(&self) -> &Locator {
        &self.target
    }

    /// The encrypted bytes exactly as read. Unauthenticated: hand them, with
    /// [`target`](Self::target), to core inspection and nowhere else.
    pub fn candidate_raw(&self) -> &[u8] {
        &self.candidate
    }
}

// Neither the locator nor the bytes are printed.
impl fmt::Debug for PresentFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresentFile(<redacted>)")
    }
}

/// Why nothing could be concluded. A category only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// An I/O or permission failure, including a file held by another process.
    Io(io::ErrorKind),
    /// A directory, symlink, junction or other reparse point (including a cloud
    /// placeholder), a regular-file or reparse-point ancestor, or a special file.
    UnexpectedObject,
    /// An ancestor directory does not exist. The folder that should hold the
    /// target is not there; that is not the same as the file being absent.
    ParentMissing,
    /// Zero bytes. Not an envelope, and possibly a placeholder or a partial write.
    Empty,
    /// Larger than `MAX_ENVELOPE_BYTES`, by metadata or by the bounded read.
    TooLarge,
    /// Length, timestamps, object kind or ancestors changed during the read, or
    /// the number of bytes read differs from the length.
    Changed,
    /// Not a platform this adapter supports.
    Unsupported,
}

/// Probe points for the private test seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The handle is open and judged; nothing has been read.
    Opened,
    /// All bytes were read; the post-read checks have not run.
    Read,
}

#[cfg(windows)]
enum Outcome {
    Bytes(Vec<u8>, Result<HandleFacts, IdentityError>),
    Absent,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// Every ancestor exists and is a plain directory.
    Intact,
    /// Some ancestor is missing, and every ancestor that exists is a plain
    /// directory, with at least one confirmed.
    MissingAncestor,
}

/// What an observable snapshot of a file consists of on stable `std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    created: u64,
    modified: u64,
}

impl Stamp {
    fn of(metadata: &fs::Metadata) -> Self {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            Self {
                len: metadata.len(),
                created: metadata.creation_time(),
                modified: metadata.last_write_time(),
            }
        }

        #[cfg(not(windows))]
        {
            Self {
                len: metadata.len(),
                created: 0,
                modified: 0,
            }
        }
    }
}

// ---- guards and helpers --------------------------------------------------------

/// Accept only absolute, drive-or-UNC paths that name one ordinary file.
fn validate_target_path(path: &Path) -> Result<(), TargetError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(TargetError::InvalidPath);
    }

    // `Path::components` silently drops interior `.` segments, so the raw text
    // is scanned as well. Separators of both kinds split segments.
    let text = path.to_str().ok_or(TargetError::InvalidPath)?;
    if text
        .split(['\\', '/'])
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(TargetError::InvalidPath);
    }

    let mut components = path.components();

    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_)
            | Prefix::VerbatimDisk(_)
            | Prefix::UNC(..)
            | Prefix::VerbatimUNC(..) => {}
            // `\\.\` device namespace and `\\?\GLOBALROOT`-style prefixes can
            // name devices, not files.
            _ => return Err(TargetError::InvalidPath),
        },
        // Without a prefix only a non-Windows absolute path gets here; this
        // adapter does not read on such platforms, but the form is still sane.
        Some(Component::RootDir) => {}
        _ => return Err(TargetError::InvalidPath),
    }

    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = name.to_str().ok_or(TargetError::InvalidPath)?;
                if !is_plain_name(name) {
                    return Err(TargetError::InvalidPath);
                }
            }
            // Prefix mid-path, `.` and `..`.
            _ => return Err(TargetError::InvalidPath),
        }
    }

    Ok(())
}

/// One path component. Rejects what Windows would reinterpret: dot segments
/// (verbatim paths do not normalize them), alternate data streams and wildcard
/// characters, names with a trailing dot or space (silently stripped), and
/// reserved device names.
fn is_plain_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    if name.chars().any(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control()
    }) {
        return false;
    }

    !is_reserved_device_name(name)
}

fn is_reserved_device_name(name: &str) -> bool {
    // A reserved name is reserved with any extension: `NUL.txt` is `NUL`.
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let upper = stem.to_ascii_uppercase();

    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|rest| {
            let mut chars = rest.chars();

            // `COM1`-`COM9` and the superscript forms Windows also reserves.
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
}

/// Every existing ancestor must be a plain directory. A missing one is reported
/// as [`Chain::MissingAncestor`] only if at least one ancestor was confirmed to
/// be a plain directory (a path with nothing existing up to its root cannot be
/// reasoned about).
#[cfg(windows)]
fn confirm_ancestors(path: &Path) -> Result<Chain, UnavailableReason> {
    let mut confirmed = 0usize;
    let mut missing = false;

    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_plain_directory(&metadata) => confirmed += 1,
            Ok(_) => return Err(UnavailableReason::UnexpectedObject),
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing = true,
            Err(error) => return Err(UnavailableReason::Io(error.kind())),
        }
    }

    if confirmed == 0 {
        return Err(UnavailableReason::Io(io::ErrorKind::NotFound));
    }

    Ok(if missing {
        Chain::MissingAncestor
    } else {
        Chain::Intact
    })
}

fn size_verdict(len: u64) -> Result<(), UnavailableReason> {
    if len == 0 {
        Err(UnavailableReason::Empty)
    } else if len > MAX_ENVELOPE_BYTES as u64 {
        Err(UnavailableReason::TooLarge)
    } else {
        Ok(())
    }
}

/// Read exactly `expected_len` bytes from `reader`, allocating at most
/// `expected_len + 1` and consuming at most that many bytes however long the
/// source really is. A short or long source is [`UnavailableReason::Changed`].
fn read_bounded<R: Read>(reader: R, expected_len: u64) -> Result<Vec<u8>, UnavailableReason> {
    if expected_len > MAX_ENVELOPE_BYTES as u64 {
        return Err(UnavailableReason::TooLarge);
    }

    let probe_len = expected_len + 1;
    let mut bytes = Vec::with_capacity(probe_len as usize);

    reader
        .take(probe_len)
        .read_to_end(&mut bytes)
        .map_err(|error| io_reason(&error))?;

    if bytes.len() as u64 == expected_len {
        Ok(bytes)
    } else if bytes.len() as u64 > MAX_ENVELOPE_BYTES as u64 {
        Err(UnavailableReason::TooLarge)
    } else {
        Err(UnavailableReason::Changed)
    }
}

fn io_reason(error: &io::Error) -> UnavailableReason {
    UnavailableReason::Io(error.kind())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.file_type().is_symlink()
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn is_plain_file(metadata: &fs::Metadata) -> bool {
    !is_reparse_point(metadata) && metadata.is_file()
}

#[cfg(windows)]
fn is_plain_directory(metadata: &fs::Metadata) -> bool {
    !is_reparse_point(metadata) && metadata.is_dir()
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // Read access only; the default share mode is kept on purpose so a sync
    // client is never blocked by this adapter.
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        path::{Path, PathBuf},
        thread,
        time::Duration,
    };

    use super::*;
    use crate::vault::{
        file_identity,
        storage::MAX_VAULT_FILE_BYTES,
        sync_state_store::{SyncStateRoot, SyncStateStore},
    };

    const CONTENT: &[u8] = b"{\"synthetic\":\"SECRETCONTENT-encrypted-envelope-stand-in\"}";
    const LEAK_DIR: &str = "LEAKMARK-DIR";
    const LEAK_FILE: &str = "LEAKMARK-FILE.lvault";

    // ---- scratch and builders -----------------------------------------------

    /// A uniquely named scratch directory under the git-ignored
    /// `<repo>/.qa-local/sync-file-adapter-tests/` (never `%TEMP%`). Only that
    /// directory is removed on drop.
    struct Scratch {
        dir: tempfile::TempDir,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(".qa-local")
                .join("sync-file-adapter-tests");
            fs::create_dir_all(&base).unwrap();

            let ignore = base.parent().unwrap().join(".gitignore");
            if !ignore.exists() {
                fs::write(&ignore, "*\n").unwrap();
            }

            let dir = tempfile::Builder::new()
                .prefix(&format!("{name}-"))
                .tempdir_in(&base)
                .unwrap();

            // Absolute and without surprises; the repository itself may be
            // reached through a path the adapter would reject.
            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        fn file(&self, name: &str) -> PathBuf {
            self.root().join(name)
        }

        fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.file(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    fn target(path: &Path) -> SyncFileTarget {
        SyncFileTarget::from_path(path).unwrap()
    }

    fn present(read: SyncFileRead) -> PresentFile {
        match read {
            SyncFileRead::Present(file) => file,
            other => panic!("expected Present, got {other:?}"),
        }
    }

    fn unavailable(read: SyncFileRead) -> UnavailableReason {
        match read {
            SyncFileRead::Unavailable(reason) => reason,
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    type Entry = (String, bool, u64, Option<std::time::SystemTime>, Vec<u8>);

    /// Everything under `dir`, with kind, length, timestamps and content.
    fn snapshot(dir: &Path) -> Vec<Entry> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];

        while let Some(current) = stack.pop() {
            for entry in fs::read_dir(&current).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let rel = path
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();

                if metadata.is_dir() {
                    found.push((rel, true, 0, metadata.modified().ok(), Vec::new()));
                    stack.push(path);
                } else {
                    found.push((
                        rel,
                        false,
                        metadata.len(),
                        metadata.modified().ok(),
                        fs::read(&path).unwrap(),
                    ));
                }
            }
        }

        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    #[cfg(windows)]
    fn make_junction(link: &Path, destination: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(destination)
            .output()
            .unwrap();
        assert!(status.status.success(), "could not create a test junction");
    }

    // ---- 1-3. exact bytes and identity ---------------------------------------

    #[test]
    fn valid_small_file_returns_the_exact_bytes() {
        let scratch = Scratch::new("exact-bytes");
        let path = scratch.put("sync.lvault", CONTENT);

        let file = present(target(&path).read());

        assert_eq!(file.candidate_raw(), CONTENT);
    }

    #[test]
    fn binary_bytes_are_returned_unchanged_and_the_file_is_untouched() {
        let scratch = Scratch::new("binary-bytes");
        let content: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        let path = scratch.put("sync.lvault", &content);
        let before = snapshot(&scratch.root());

        let file = present(target(&path).read());

        assert_eq!(file.candidate_raw(), content.as_slice());
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_eq!(snapshot(&scratch.root()), before);
    }

    #[test]
    fn returned_target_identity_is_the_requested_locator_verbatim() {
        let scratch = Scratch::new("identity");
        let path = scratch.put("Sync.LVAULT", CONTENT);

        let requested = target(&path);
        let file = present(requested.read());

        assert_eq!(file.target(), requested.locator());
        // Never canonicalized or case-folded: the exact string supplied.
        assert_eq!(file.target().as_str(), path.to_str().unwrap());

        let retained = Locator::new(path.to_str().unwrap()).unwrap();
        let from_locator = SyncFileTarget::from_locator(&retained).unwrap();
        assert_eq!(from_locator.locator(), &retained);
        assert_eq!(present(from_locator.read()).target(), &retained);
    }

    #[test]
    fn different_targets_carry_their_own_bytes_and_identity() {
        let scratch = Scratch::new("two-targets");
        let a = scratch.put("a.lvault", b"bytes of target A");
        let b = scratch.put("b.lvault", b"bytes of target B");

        let read_a = present(target(&a).read());
        let read_b = present(target(&b).read());

        assert_eq!(read_a.candidate_raw(), b"bytes of target A");
        assert_eq!(read_a.target().as_str(), a.to_str().unwrap());
        assert_eq!(read_b.candidate_raw(), b"bytes of target B");
        assert_eq!(read_b.target().as_str(), b.to_str().unwrap());
        assert_ne!(read_a.target(), read_b.target());
        assert_ne!(read_a, read_b);
    }

    // ---- 5. empty --------------------------------------------------------------

    #[test]
    fn an_empty_file_is_unavailable_empty_and_not_absent() {
        let scratch = Scratch::new("empty");
        let path = scratch.put("sync.lvault", b"");

        assert_eq!(unavailable(target(&path).read()), UnavailableReason::Empty);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    // ---- 6-8. size bound, growth, shrinkage ------------------------------------

    #[test]
    fn the_size_limit_is_the_core_and_storage_envelope_limit() {
        assert_eq!(MAX_ENVELOPE_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAX_ENVELOPE_BYTES as u64, MAX_VAULT_FILE_BYTES);
    }

    #[test]
    fn an_oversized_file_is_refused_from_metadata_without_allocation() {
        let scratch = Scratch::new("oversized");
        let path = scratch.file("sync.lvault");
        let file = fs::File::create(&path).unwrap();
        // Sparse on NTFS: set_len does not write 32 MiB of data.
        file.set_len(MAX_ENVELOPE_BYTES as u64 + 1).unwrap();
        drop(file);

        assert_eq!(
            unavailable(target(&path).read()),
            UnavailableReason::TooLarge
        );
    }

    #[test]
    fn a_file_of_exactly_the_limit_is_accepted() {
        let scratch = Scratch::new("at-limit");
        let path = scratch.file("sync.lvault");
        let content = vec![b'x'; MAX_ENVELOPE_BYTES];
        fs::write(&path, &content).unwrap();

        let file = present(target(&path).read());

        assert_eq!(file.candidate_raw().len(), MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn the_bounded_reader_never_consumes_more_than_one_past_the_expected_length() {
        // An endless source: if the reader were not bounded this would not
        // terminate or would exhaust memory.
        assert_eq!(
            read_bounded(io::repeat(7), 1024),
            Err(UnavailableReason::Changed)
        );
        assert_eq!(
            read_bounded(io::repeat(7), MAX_ENVELOPE_BYTES as u64),
            Err(UnavailableReason::TooLarge)
        );
        assert_eq!(
            read_bounded(io::repeat(7), MAX_ENVELOPE_BYTES as u64 + 1),
            Err(UnavailableReason::TooLarge)
        );

        let mut counting = CountingReader::default();
        assert_eq!(
            read_bounded(&mut counting, 4096),
            Err(UnavailableReason::Changed)
        );
        assert_eq!(counting.consumed, 4097);

        // Exact, short.
        assert_eq!(read_bounded(&b"abc"[..], 3), Ok(b"abc".to_vec()));
        assert_eq!(read_bounded(&b"ab"[..], 3), Err(UnavailableReason::Changed));
    }

    #[derive(Default)]
    struct CountingReader {
        consumed: usize,
    }

    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(1);
            self.consumed += buf.len();
            Ok(buf.len())
        }
    }

    #[cfg(windows)]
    #[test]
    fn growth_after_the_handle_is_judged_is_bounded_and_unavailable() {
        let scratch = Scratch::new("growth");
        let path = scratch.put("sync.lvault", CONTENT);
        let grown = path.clone();

        let mut probed = false;
        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Opened {
                probed = true;
                let mut file = OpenOptions::new().append(true).open(&grown).unwrap();
                file.write_all(&vec![b'g'; 1_000_000]).unwrap();
            }
        });

        assert!(probed, "the growth probe did not run");
        assert_eq!(unavailable(read), UnavailableReason::Changed);
    }

    #[cfg(windows)]
    #[test]
    fn growth_of_a_limit_sized_file_stays_within_the_limit_plus_one() {
        let scratch = Scratch::new("growth-at-limit");
        let path = scratch.file("sync.lvault");
        fs::write(&path, vec![b'x'; MAX_ENVELOPE_BYTES]).unwrap();
        let grown = path.clone();

        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Opened {
                let mut file = OpenOptions::new().append(true).open(&grown).unwrap();
                file.write_all(&vec![b'g'; 1_000_000]).unwrap();
            }
        });

        // Only limit + 1 bytes are consumed, which already proves the file is
        // over the limit: `TooLarge`, never trusted bytes.
        assert_eq!(unavailable(read), UnavailableReason::TooLarge);
    }

    #[cfg(windows)]
    #[test]
    fn shrinkage_after_the_handle_is_judged_is_unavailable() {
        let scratch = Scratch::new("shrink");
        let path = scratch.put("sync.lvault", CONTENT);
        let shrunk = path.clone();

        let mut probed = false;
        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Opened {
                probed = true;
                OpenOptions::new()
                    .write(true)
                    .open(&shrunk)
                    .unwrap()
                    .set_len(5)
                    .unwrap();
            }
        });

        assert!(probed, "the shrink probe did not run");
        assert_eq!(unavailable(read), UnavailableReason::Changed);
    }

    #[cfg(windows)]
    #[test]
    fn a_rewrite_with_the_same_length_during_the_read_is_detected_by_timestamps() {
        let scratch = Scratch::new("rewrite-same-length");
        let path = scratch.put("sync.lvault", CONTENT);
        let rewritten = path.clone();

        // Make the post-write timestamp differ from the creation-time stamp.
        thread::sleep(Duration::from_millis(60));

        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Read {
                let replacement = vec![b'Z'; CONTENT.len()];
                OpenOptions::new()
                    .write(true)
                    .open(&rewritten)
                    .unwrap()
                    .write_all(&replacement)
                    .unwrap();
            }
        });

        assert_eq!(unavailable(read), UnavailableReason::Changed);
    }

    // ---- 9-12. object kinds and absence ----------------------------------------

    #[test]
    fn a_directory_target_is_unavailable() {
        let scratch = Scratch::new("directory-target");
        let path = scratch.file("sync.lvault");
        fs::create_dir(&path).unwrap();

        assert_eq!(
            unavailable(target(&path).read()),
            UnavailableReason::UnexpectedObject
        );
    }

    #[test]
    fn a_missing_file_in_an_accessible_directory_is_absent_on_disk() {
        let scratch = Scratch::new("missing-file");
        let path = scratch.file("sync.lvault");
        let before = snapshot(&scratch.root());

        let read = target(&path).read();

        assert_eq!(read, SyncFileRead::AbsentOnDisk);
        assert!(!path.exists(), "the adapter must not create the target");
        assert_eq!(snapshot(&scratch.root()), before);
    }

    #[test]
    fn a_missing_parent_directory_is_unavailable_not_absent() {
        let scratch = Scratch::new("missing-parent");
        let path = scratch.file("nowhere").join("deeper").join("sync.lvault");

        assert_eq!(
            unavailable(target(&path).read()),
            UnavailableReason::ParentMissing
        );
        assert!(!scratch.file("nowhere").exists());
    }

    #[test]
    fn a_nonexistent_drive_is_not_confirmed_absent() {
        // A drive letter that is not mounted: nothing up to the root can be
        // inspected, so no fact about the path is established.
        let letter = ('D'..='Z')
            .find(|letter| !Path::new(&format!("{letter}:\\")).exists())
            .expect("a free drive letter");
        let path = PathBuf::from(format!("{letter}:\\LocalVault\\sync.lvault"));

        let reason = unavailable(target(&path).read());

        assert!(
            matches!(
                reason,
                UnavailableReason::Io(_) | UnavailableReason::ParentMissing
            ),
            "{reason:?}"
        );
        assert_ne!(target(&path).read(), SyncFileRead::AbsentOnDisk);
    }

    #[test]
    fn a_regular_file_ancestor_is_unavailable() {
        let scratch = Scratch::new("file-ancestor");
        let blocker = scratch.put("blocker", b"i am a file");
        let path = blocker.join("sync.lvault");

        assert_eq!(
            unavailable(target(&path).read()),
            UnavailableReason::UnexpectedObject
        );

        // Deeper below a file: Windows says "not found" for these too.
        let deeper = blocker.join("a").join("sync.lvault");
        assert_eq!(
            unavailable(target(&deeper).read()),
            UnavailableReason::UnexpectedObject
        );
    }

    // ---- 13. reparse points ------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn a_junction_target_is_rejected() {
        let scratch = Scratch::new("junction-target");
        let destination = scratch.file("real-dir");
        fs::create_dir(&destination).unwrap();
        let link = scratch.file("sync.lvault");
        make_junction(&link, &destination);

        assert_eq!(
            unavailable(target(&link).read()),
            UnavailableReason::UnexpectedObject
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_ancestor_is_rejected_even_when_the_file_exists_behind_it() {
        let scratch = Scratch::new("junction-ancestor");
        let destination = scratch.file("real-dir");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sync.lvault"), CONTENT).unwrap();
        let link = scratch.file("link-dir");
        make_junction(&link, &destination);

        let through = link.join("sync.lvault");
        assert!(through.exists(), "the junction should resolve");

        assert_eq!(
            unavailable(target(&through).read()),
            UnavailableReason::UnexpectedObject
        );

        // A missing file behind a junction is not "absent" either.
        let missing = link.join("missing.lvault");
        assert_eq!(
            unavailable(target(&missing).read()),
            UnavailableReason::UnexpectedObject
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_file_symlink_target_is_rejected_when_symlinks_can_be_created() {
        let scratch = Scratch::new("file-symlink");
        let real = scratch.put("real.lvault", CONTENT);
        let link = scratch.file("sync.lvault");

        if std::os::windows::fs::symlink_file(&real, &link).is_err() {
            eprintln!(
                "SKIPPED a_file_symlink_target_is_rejected_when_symlinks_can_be_created: \
                 this account cannot create symlinks"
            );
            return;
        }

        assert_eq!(
            unavailable(target(&link).read()),
            UnavailableReason::UnexpectedObject
        );
    }

    // ---- 14-15. held and replaced ------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn a_file_held_without_sharing_is_unavailable() {
        use std::os::windows::fs::OpenOptionsExt;

        let scratch = Scratch::new("held");
        let path = scratch.put("sync.lvault", CONTENT);
        let _held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();

        assert!(matches!(
            unavailable(target(&path).read()),
            UnavailableReason::Io(_)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn replacement_with_a_different_length_during_the_read_is_unavailable() {
        let scratch = Scratch::new("replace-length");
        let path = scratch.put("sync.lvault", CONTENT);
        let other = scratch.put("other.lvault", b"a replacement of another length");
        let replaced = path.clone();

        let mut probed = false;
        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Read {
                probed = true;
                fs::rename(&other, &replaced).unwrap();
            }
        });

        assert!(probed, "the replacement probe did not run");
        assert_eq!(unavailable(read), UnavailableReason::Changed);
    }

    #[cfg(windows)]
    #[test]
    fn replacement_with_the_same_length_is_detected_by_creation_time() {
        let scratch = Scratch::new("replace-same-length");
        let path = scratch.put("sync.lvault", CONTENT);

        // The replacement is created well after the original, so its creation
        // time differs. Without that gap this check could not tell them apart:
        // that is the documented limit, not something this test claims away.
        thread::sleep(Duration::from_millis(60));
        let other = scratch.put("other.lvault", &vec![b'R'; CONTENT.len()]);
        let replaced = path.clone();

        let mut probed = false;
        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Read {
                probed = true;
                fs::rename(&other, &replaced).unwrap();
            }
        });

        assert!(probed, "the replacement probe did not run");
        assert_eq!(unavailable(read), UnavailableReason::Changed);
    }

    #[cfg(windows)]
    #[test]
    fn removal_during_the_read_is_unavailable() {
        let scratch = Scratch::new("removed-during-read");
        let path = scratch.put("sync.lvault", CONTENT);
        let removed = path.clone();

        let read = target(&path).read_with(&mut |stage| {
            if stage == Stage::Read {
                fs::remove_file(&removed).unwrap();
            }
        });

        // Depending on delete-pending semantics the path then reads as gone
        // (`Changed`) or as inaccessible (`Io`); never as trusted bytes.
        assert!(matches!(
            unavailable(read),
            UnavailableReason::Changed | UnavailableReason::Io(_)
        ));
    }

    // ---- 16-18. read-only --------------------------------------------------------

    #[test]
    fn reading_creates_truncates_and_removes_nothing_and_leaves_backup_alone() {
        let scratch = Scratch::new("read-only");
        let path = scratch.put("sync.lvault", CONTENT);
        scratch.put("sync.lvault.backup", b"BACKUP-BYTES");
        scratch.put("unrelated.tmp", b"unrelated");
        let before = snapshot(&scratch.root());

        let _ = target(&path).read();
        let _ = target(&scratch.file("missing.lvault")).read();
        let _ = target(&scratch.file("nowhere").join("x.lvault")).read();
        let _ = target(&scratch.file("sync.lvault.backup")).read();

        assert_eq!(snapshot(&scratch.root()), before);
        assert_eq!(
            fs::read(scratch.file("sync.lvault.backup")).unwrap(),
            b"BACKUP-BYTES"
        );
    }

    #[test]
    fn sync_state_storage_is_untouched() {
        let scratch = Scratch::new("state-untouched");
        let path = scratch.put("sync.lvault", CONTENT);
        let state_root = Scratch::new("state-root");

        // Absent: no sync-state directory appears.
        let _ = target(&path).read();
        let store_root = SyncStateRoot::for_test(state_root.root());
        let _ = SyncStateStore::new(store_root.path()).unwrap();
        assert!(snapshot(&state_root.root()).is_empty());

        // Present: a pre-existing sync-state directory is byte-for-byte unchanged.
        let directory = state_root.file(crate::vault::sync_state_store::SYNC_STATE_DIRECTORY);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("record.json"), b"RECORD").unwrap();
        let before = snapshot(&state_root.root());

        let _ = target(&path).read();
        let _ = target(&scratch.file("missing.lvault")).read();

        assert_eq!(snapshot(&state_root.root()), before);
    }

    // ---- 19. no leakage ----------------------------------------------------------

    #[test]
    fn debug_and_error_output_never_leak_paths_or_contents() {
        let scratch = Scratch::new("leak");
        let dir = scratch.file(LEAK_DIR);
        fs::create_dir(&dir).unwrap();
        let path = dir.join(LEAK_FILE);
        fs::write(&path, CONTENT).unwrap();

        let requested = target(&path);
        let read = requested.read();
        let file = present(read.clone());
        let absent = target(&dir.join("LEAKMARK-MISSING.lvault")).read();
        let unavailable_dir = target(&dir).read();
        let empty = {
            let p = dir.join("LEAKMARK-EMPTY.lvault");
            fs::write(&p, b"").unwrap();
            target(&p).read()
        };

        let invalid_path =
            SyncFileTarget::from_path(Path::new("LEAKMARK-relative\\x.lvault")).unwrap_err();

        let rendered = format!(
            "{requested:?} {read:?} {file:?} {absent:?} {unavailable_dir:?} {empty:?} \
             {:?} {:?} {invalid_path} {invalid_path:?} {:?} {:?}",
            requested.locator(),
            file.target(),
            UnavailableReason::Io(io::ErrorKind::PermissionDenied),
            TargetError::InvalidLocator,
        );

        for marker in [
            "LEAKMARK",
            "SECRETCONTENT",
            "sync-file-adapter-tests",
            "qa-local",
        ] {
            assert!(!rendered.contains(marker), "leaked {marker}: {rendered}");
        }
        assert!(rendered.contains("redacted"));
    }

    // ---- 20. unsupported and malformed targets fail closed -----------------------

    #[test]
    fn malformed_and_unsupported_targets_are_rejected_at_construction() {
        let rejected = [
            "",                                   // empty locator
            "sync.lvault",                        // relative
            "\\sync.lvault",                      // rooted but no drive
            "C:sync.lvault",                      // drive-relative
            "C:\\",                               // no file name
            "C:\\vaults\\..\\sync.lvault",        // parent segment
            "C:\\vaults\\.\\sync.lvault",         // current-dir segment
            "\\\\?\\C:\\vaults\\..\\sync.lvault", // verbatim does not normalize
            "C:\\vaults\\sync.lvault:stream",     // alternate data stream
            "C:\\vaults\\sync.lvault::$DATA",     // alternate data stream
            "C:\\vaults\\sync*.lvault",           // wildcard
            "C:\\vaults\\sync?.lvault",           // wildcard
            "C:\\vaults\\sync.lvault.",           // trailing dot is stripped by Windows
            "C:\\vaults\\sync.lvault ",           // trailing space is stripped by Windows
            "C:\\vaults\\NUL",                    // device
            "C:\\vaults\\nul.lvault",             // device with extension
            "C:\\vaults\\COM1.lvault",            // device
            "C:\\vaults\\LPT9",                   // device
            "C:\\vaults\\CON",                    // device
            "C:\\CON\\sync.lvault",               // device as a directory
            "\\\\.\\C:\\vaults\\sync.lvault",     // device namespace
            "\\\\.\\PhysicalDrive0",              // device namespace
            "\\\\?\\GLOBALROOT\\Device\\x",       // object-manager path
        ];

        for text in rejected {
            let result = match Locator::new(text) {
                Ok(locator) => SyncFileTarget::from_locator(&locator).map(|_| ()),
                Err(_) => Err(TargetError::InvalidLocator),
            };
            assert!(result.is_err(), "accepted {text:?}");
        }

        // Control characters never form a locator at all.
        assert_eq!(
            SyncFileTarget::from_path(Path::new("C:\\vaults\\a\u{1}b.lvault")),
            Err(TargetError::InvalidLocator)
        );
    }

    #[test]
    fn ordinary_targets_are_accepted_and_kept_verbatim() {
        let accepted = [
            "C:\\vaults\\sync.lvault",
            "c:\\Vaults With Spaces\\Sync.LVAULT",
            "\\\\?\\C:\\vaults\\sync.lvault",
            "\\\\server\\share\\vaults\\sync.lvault",
            "\\\\?\\UNC\\server\\share\\sync.lvault",
            "C:\\vaults\\console.lvault", // not the reserved CON
            "C:\\vaults\\COM10.lvault",   // only COM0-9 are reserved
            "C:\\vaults\\sync.v2.lvault",
        ];

        for text in accepted {
            let locator = Locator::new(text).unwrap();
            let target = SyncFileTarget::from_locator(&locator)
                .unwrap_or_else(|_| panic!("rejected {text:?}"));
            assert_eq!(target.locator().as_str(), text);
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_path_that_is_not_valid_unicode_is_rejected() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        // An unpaired surrogate cannot be represented in a locator string.
        let wide: Vec<u16> = "C:\\vaults\\a"
            .encode_utf16()
            .chain([0xD800])
            .chain("b.lvault".encode_utf16())
            .collect();
        let path = PathBuf::from(OsString::from_wide(&wide));

        assert_eq!(
            SyncFileTarget::from_path(&path),
            Err(TargetError::InvalidPath)
        );
    }

    #[test]
    fn there_is_no_conversion_from_a_local_miss_to_remote_evidence() {
        // `SyncFileRead` offers no accessor that yields core `RemoteEvidence`;
        // the absence result carries no data at all and cannot be turned into
        // `RemoteEvidence::Absent` without an explicit caller decision.
        let scratch = Scratch::new("no-evidence");
        let read = target(&scratch.file("sync.lvault")).read();

        assert_eq!(read, SyncFileRead::AbsentOnDisk);
        assert_ne!(
            read,
            SyncFileRead::Unavailable(UnavailableReason::ParentMissing)
        );
    }

    // ---- B1g: physical facts from the reading handle ---------------------------

    #[cfg(windows)]
    #[test]
    fn present_carries_the_physical_facts_of_the_file_it_read() {
        let scratch = Scratch::new("physical-facts");
        let path = scratch.put("sync.lvault", CONTENT);
        let present = present(target(&path).read());

        let expected = file_identity::facts_of(&File::open(&path).unwrap()).unwrap();

        assert_eq!(present.physical(), Ok(&expected));
        assert_eq!(present.candidate_raw(), CONTENT);

        // A second name for the same file is visible in the facts of the read.
        let alias = scratch.file("alias.lvault");

        fs::hard_link(&path, &alias).unwrap();

        let linked = self::present(target(&alias).read());

        assert_eq!(linked.physical().unwrap().identity(), expected.identity());
        assert_ne!(linked.physical(), Ok(&expected), "link count differs");
    }

    #[test]
    fn a_failed_identity_lookup_never_changes_the_classification() {
        let scratch = Scratch::new("physical-failure");
        let path = scratch.put("sync.lvault", CONTENT);
        let original = present(target(&path).read());
        let failed = original
            .clone()
            .with_physical_for_test(Err(IdentityError::Lookup));

        assert_eq!(failed.physical(), Err(IdentityError::Lookup));
        assert_eq!(failed.candidate_raw(), original.candidate_raw());
        assert_eq!(failed.target(), original.target());
        assert_eq!(format!("{failed:?}"), "PresentFile(<redacted>)");
    }
}
