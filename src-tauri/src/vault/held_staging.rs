//! A staging file that stays held from its creation to its publication (Stage 1U-4,
//! slice G12T-2, gate G12-temp for **create**).
//!
//! The legacy sync-state `create` used to write a staging file by path, close it,
//! link it to the record by path and remove it again by path. Every one of those
//! steps resolved a name again, so a different process able to write the directory
//! could substitute what the name referred to. This module is the replacement
//! building block: one file, created exclusively, **held open** with read, write and
//! delete access and read-only sharing, written, judged and published through that
//! very handle, and removed (if it must be) only through that handle.
//!
//! * [`StagingFile::create_new`]: exclusive creation (`create_new`), access
//!   `GENERIC_READ | GENERIC_WRITE | DELETE`, sharing `FILE_SHARE_READ`,
//!   `FILE_FLAG_OPEN_REPARSE_POINT`. While the handle lives, an ordinary process can
//!   neither write, delete nor rename the file (measured by the G12T-1 tests).
//! * [`StagingFile::judge`]: the physical facts of the handle (plain file, not a
//!   reparse point, not read-only, local NTFS, one name, not delete-pending, the
//!   expected length) and the bytes read back **through the same handle**.
//! * [`StagingFile::publish_no_replace`]: the handle-bound no-replace rename into a
//!   pinned directory (`handle_ops`). The staging path is never the source of a
//!   publication step.
//! * [`StagingFile::ownership`] and [`StagingFile::abandon`]: the only removal. It
//!   marks the file for deletion through the handle, and only after the handle has
//!   shown that it is still the one name that the staging path resolves to.
//!
//! This module knows nothing about record keys, file-name grammar or which
//! directory it is used in: the store decides that and passes paths. It adds no
//! native call, no foreign function and no dependency.
//!
//! # No automatic removal
//!
//! Dropping a [`StagingFile`] closes its handle and removes **nothing**. There is no
//! destructor; a file is removed only by the explicit, consuming
//! [`StagingFile::abandon`], and only when ownership was proven.
//!
//! # What this module does not claim
//!
//! * A successful no-replace rename does **not** prove that the destination name was
//!   absent before. On NTFS a destination that already names a hard link to the same
//!   file object can produce a successful rename. The caller must judge the physical
//!   result (identity, names, bytes) and never the status alone.
//! * Sharing modes bind ordinary processes only. Administrators, backup-privileged
//!   processes, kernel components and filter drivers can bypass them.
//! * Nothing here flushes a directory: nothing is claimed about power loss or an
//!   operating-system crash.
//! * After the handle closes, the file is ordinary user data.
//!
//! No path, name, identifier, native status or byte appears in any `Debug` output.

use std::{
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

#[cfg(windows)]
use std::{
    fs::OpenOptions,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    },
};

use super::{
    file_identity::{facts_of, FileIdentity, HandleFacts, IdentityError},
    handle_ops::{delete_by_handle, rename_into_directory_no_replace, RenameStatus},
    held_removal::{judge_mark, DirectoryPin, RemovalMark},
    sync_state_store::open_no_follow,
};

/// One staging file, held open. Move-only. `Debug` is redacted.
#[must_use]
pub(crate) struct StagingFile {
    handle: File,
}

impl fmt::Debug for StagingFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StagingFile(<redacted>)")
    }
}

/// Whether the staging handle still denotes a name that may be removed. See
/// [`StagingFile::ownership`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum Ownership {
    /// The handle shows exactly one name, not delete-pending, on local NTFS, and the
    /// staging path resolves to the very same file.
    Sole(HandleFacts),
    /// The handle shows two or more names: the file may be reachable under another
    /// name, possibly the record. Nothing may be removed.
    OtherNames,
    /// The handle has one name, but the staging path no longer resolves to it (it is
    /// absent or names another file): the name may have been consumed.
    NameNotOurs,
    /// The facts could not be established, are not local NTFS, are delete-pending or
    /// show no name, or the path could not be probed.
    Unknown,
}

/// What [`StagingFile::abandon`] established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum AbandonResult {
    /// The mark was proven through the handle **and**, after the handle closed, the
    /// staging name was confirmed absent.
    Clean,
    /// Ownership was not proven: no native call was made and the file is untouched.
    Retained,
    /// A mark was attempted (or the name could not be confirmed absent afterwards).
    /// No retry and no fallback.
    Uncertain,
}

/// What a fresh no-follow open of the staging path showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathProbe {
    /// The path opened and its handle has this identity.
    Identity(FileIdentity),
    /// The path does not exist.
    Absent,
    /// The open or the query failed for any other reason.
    Failed,
}

impl StagingFile {
    /// Create `path` exclusively and hold it. `AlreadyExists` when the name is taken;
    /// any other error is returned as it came. Off Windows: `Unsupported`.
    pub(crate) fn create_new(path: &Path) -> io::Result<Self> {
        Ok(Self {
            handle: open_new(path)?,
        })
    }

    /// Write exactly `bytes` through the handle and flush.
    pub(crate) fn write_exact(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.handle.write_all(bytes)?;

        self.handle.flush()
    }

    /// Flush the file to the device through the handle.
    pub(crate) fn sync(&self) -> io::Result<()> {
        self.handle.sync_all()
    }

    /// The physical facts of the handle, if and only if it is a plain file (not a
    /// reparse point, not read-only) on local NTFS with exactly one name, not
    /// delete-pending, of exactly the expected length, whose bytes read back through
    /// this same handle equal `expected`.
    pub(crate) fn judge(&self, expected: &[u8]) -> Option<HandleFacts> {
        let metadata = self.handle.metadata().ok()?;

        if !metadata.is_file()
            || is_reparse(&metadata)
            || is_read_only(&metadata)
            || metadata.len() != expected.len() as u64
        {
            return None;
        }

        let facts = facts_of(&self.handle).ok()?;

        if !facts.is_local_ntfs() || !facts.has_single_link() || facts.is_delete_pending() {
            return None;
        }

        let read = self.read_back(expected.len() as u64)?;

        (read == expected).then_some(facts)
    }

    /// A fresh query on the handle.
    pub(crate) fn facts(&self) -> Result<HandleFacts, IdentityError> {
        facts_of(&self.handle)
    }

    /// Rename the held file into the directory behind `pin` under `leaf`, replacing
    /// nothing (`handle_ops`). The staging path plays no part.
    pub(crate) fn publish_no_replace(&self, pin: &DirectoryPin, leaf: &OsStr) -> RenameStatus {
        rename_into_directory_no_replace(&self.handle, pin.handle(), leaf)
    }

    /// Whether this handle still denotes an owned staging name that `path` names.
    /// See [`Ownership`]. Reads facts from the handle and makes one read-only
    /// no-follow open of `path`; it changes nothing.
    pub(crate) fn ownership(&self, path: &Path) -> Ownership {
        decide_ownership(facts_of(&self.handle), || probe_path(path))
    }

    /// Remove the staging name, and only if [`ownership`](Self::ownership) is
    /// `Sole`: then mark it through this handle, query the same handle again, judge
    /// the mark, close the handle and require the name to be gone. Consumes the
    /// file. There is no retry, no fallback and no path-based removal.
    pub(crate) fn abandon(self, path: &Path) -> AbandonResult {
        let Ownership::Sole(saved) = self.ownership(path) else {
            return AbandonResult::Retained;
        };

        let native_ok = delete_by_handle(&self.handle).is_ok();
        let after = facts_of(&self.handle);
        let mark = judge_mark(native_ok, after, &saved);

        #[cfg(test)]
        run_after_mark_hook();

        // The handle closes here: the name stays visible until it does.
        drop(self);

        let gone = matches!(
            fs::symlink_metadata(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );

        if mark == RemovalMark::Marked && gone {
            AbandonResult::Clean
        } else {
            AbandonResult::Uncertain
        }
    }

    /// Close the handle. Removes nothing.
    pub(crate) fn release(self) {
        drop(self);
    }

    /// At most `limit` bytes from the start, through this handle. A longer file or a
    /// read error is `None`.
    fn read_back(&self, limit: u64) -> Option<Vec<u8>> {
        let mut file = &self.handle;

        file.seek(SeekFrom::Start(0)).ok()?;

        let mut bytes = Vec::new();

        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;

        (bytes.len() as u64 <= limit).then_some(bytes)
    }
}

/// The pure decision behind [`StagingFile::ownership`]: the handle's own facts first,
/// then (only for exactly one name) the probe of the path.
fn decide_ownership(
    facts: Result<HandleFacts, IdentityError>,
    probe: impl FnOnce() -> PathProbe,
) -> Ownership {
    let Ok(facts) = facts else {
        return Ownership::Unknown;
    };

    if !facts.is_local_ntfs() || facts.is_delete_pending() || facts.link_count() == 0 {
        return Ownership::Unknown;
    }

    if facts.link_count() >= 2 {
        return Ownership::OtherNames;
    }

    match probe() {
        PathProbe::Identity(identity) if identity == facts.identity() => Ownership::Sole(facts),
        PathProbe::Identity(_) | PathProbe::Absent => Ownership::NameNotOurs,
        PathProbe::Failed => Ownership::Unknown,
    }
}

/// One read-only no-follow open of `path`, judged on its own handle.
fn probe_path(path: &Path) -> PathProbe {
    match open_no_follow(path) {
        Ok(file) => match facts_of(&file) {
            Ok(facts) => PathProbe::Identity(facts.identity()),
            Err(_) => PathProbe::Failed,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => PathProbe::Absent,
        Err(_) => PathProbe::Failed,
    }
}

/// `create_new`, `GENERIC_READ | GENERIC_WRITE | DELETE`, `FILE_SHARE_READ` only,
/// `FILE_FLAG_OPEN_REPARSE_POINT`. Windows only; elsewhere there is no hold.
#[cfg(windows)]
fn open_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_new(_path: &Path) -> io::Result<File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.file_type().is_symlink()
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn is_read_only(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0
    }

    #[cfg(not(windows))]
    {
        metadata.permissions().readonly()
    }
}

/// Test-only: run `run` once, on this thread, after the next mark made by
/// [`StagingFile::abandon`] and before its handle closes.
#[cfg(test)]
pub(crate) fn set_after_mark_hook(run: impl FnOnce() + 'static) {
    AFTER_MARK.with(|slot| *slot.borrow_mut() = Some(Box::new(run)));
}

#[cfg(test)]
fn run_after_mark_hook() {
    let run = AFTER_MARK.with(|slot| slot.borrow_mut().take());

    if let Some(run) = run {
        run();
    }
}

#[cfg(test)]
type AfterMark = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
thread_local! {
    static AFTER_MARK: AfterMark = const { std::cell::RefCell::new(None) };
}

// ---- tests ---------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests {
    use std::fs::OpenOptions;

    use super::*;
    use crate::vault::{
        file_identity::FileSystemKind,
        handle_ops::{inject_delete_status, take_last_delete_status, test_support::*},
        new_copy_file::open_directory_pin,
    };

    const BYTES: &[u8] = b"synthetic-held-staging-bytes-0123456789";
    const OTHER: &[u8] = b"SYNTHETIC-OTHER-BYTES-NOT-A-REAL-RECORD";

    fn facts(links: u32, pending: bool, id: u8) -> HandleFacts {
        HandleFacts::for_test(7, [id; 16], links, pending, FileSystemKind::Ntfs, true)
    }

    fn identity(id: u8) -> FileIdentity {
        facts(1, false, id).identity()
    }

    // ---- PURE ---------------------------------------------------------------------

    #[test]
    fn pure_ownership_is_decided_from_the_handle_first_and_the_path_second() {
        // PURE. The probe is consulted only for exactly one name.
        let never = || -> PathProbe { panic!("the path must not be probed") };

        for refused in [
            Err(IdentityError::Lookup),
            Err(IdentityError::Unsupported),
            Ok(facts(0, false, 1)),
            Ok(facts(1, true, 1)),
            Ok(HandleFacts::for_test(
                7,
                [1; 16],
                1,
                false,
                FileSystemKind::Refs,
                true,
            )),
            Ok(HandleFacts::for_test(
                7,
                [1; 16],
                1,
                false,
                FileSystemKind::Ntfs,
                false,
            )),
        ] {
            assert_eq!(decide_ownership(refused, never), Ownership::Unknown);
        }

        for links in [2u32, 3, u32::MAX] {
            assert_eq!(
                decide_ownership(Ok(facts(links, false, 1)), never),
                Ownership::OtherNames,
                "{links} names"
            );
        }

        let one = facts(1, false, 1);

        assert_eq!(
            decide_ownership(Ok(one), || PathProbe::Identity(identity(1))),
            Ownership::Sole(one)
        );
        assert_eq!(
            decide_ownership(Ok(one), || PathProbe::Identity(identity(2))),
            Ownership::NameNotOurs
        );
        assert_eq!(
            decide_ownership(Ok(one), || PathProbe::Absent),
            Ownership::NameNotOurs
        );
        assert_eq!(
            decide_ownership(Ok(one), || PathProbe::Failed),
            Ownership::Unknown
        );
    }

    #[test]
    fn pure_nothing_printed_reveals_a_path_name_identity_or_status() {
        // PURE and REAL: the redaction of the value and of every outcome.
        let dir = scratch("staging-redaction");
        let path = dir.path().join("SECRET-NAME-MARK.bin");
        let staging = StagingFile::create_new(&path).unwrap();
        let mut shown = vec![format!("{staging:?}"), format!("{staging:#?}")];

        for ownership in [
            Ownership::Sole(facts(1, false, 1)),
            Ownership::OtherNames,
            Ownership::NameNotOurs,
            Ownership::Unknown,
        ] {
            shown.push(format!("{ownership:?}"));
        }
        for result in [
            AbandonResult::Clean,
            AbandonResult::Retained,
            AbandonResult::Uncertain,
        ] {
            shown.push(format!("{result:?}"));
        }
        shown.push(format!("{:?}", PathProbe::Identity(identity(9))));

        for text in &shown {
            for mark in ["SECRET", ".bin", "\\", "0x", ".qa-local"] {
                assert!(!text.contains(mark), "{mark} in {text}");
            }
        }
    }

    // ---- REAL NTFS -------------------------------------------------------------------

    #[test]
    fn a_staging_file_is_created_exclusively_written_judged_and_read_back_through_one_handle() {
        let dir = scratch("staging-basic");
        let path = dir.path().join("a.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        // The name is taken: a second exclusive creation is refused and changes nothing.
        assert_eq!(
            StagingFile::create_new(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        // An empty file is not what was expected.
        assert!(staging.judge(BYTES).is_none());

        staging.write_exact(BYTES).unwrap();
        staging.sync().unwrap();

        let judged = staging.judge(BYTES).expect("judged");

        assert_eq!(judged.link_count(), 1);
        assert!(judged.is_local_ntfs());
        assert_eq!(staging.facts().unwrap(), judged);

        // Different bytes of the same length, a shorter and a longer expectation.
        assert!(staging.judge(&vec![b'x'; BYTES.len()]).is_none());
        assert!(staging.judge(&BYTES[..BYTES.len() - 1]).is_none());
        assert!(staging.judge(&[BYTES, b"!"].concat()).is_none());

        assert_eq!(fs::read(&path).unwrap(), BYTES);
    }

    #[test]
    fn a_held_staging_refuses_every_substitution_and_only_a_compatible_reader_coexists() {
        let dir = scratch("staging-sharing");
        let path = dir.path().join("a.bin");
        let decoy = dir.path().join("decoy.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        staging.write_exact(BYTES).unwrap();
        fs::write(&decoy, OTHER).unwrap();

        let saved = staging.judge(BYTES).unwrap();

        for (label, result) in [
            ("remove", fs::remove_file(&path)),
            (
                "rename away",
                fs::rename(&path, dir.path().join("aside.bin")),
            ),
            ("rename over", fs::rename(&decoy, &path)),
            ("replace bytes", fs::write(&path, OTHER)),
        ] {
            assert!(result.is_err(), "{label} was not refused");
        }
        assert!(OpenOptions::new().write(true).open(&path).is_err());

        // The compatible reader: read access, the standard sharing.
        assert_eq!(fs::read(&path).unwrap(), BYTES);
        assert!(open_no_follow(&path).is_ok());

        assert_eq!(staging.facts().unwrap(), saved);
        assert_eq!(fs::read(&decoy).unwrap(), OTHER);
        assert_eq!(names(dir.path()), vec!["a.bin", "decoy.bin"]);
    }

    #[test]
    fn abandon_removes_only_the_owned_name_through_the_handle() {
        let dir = scratch("staging-abandon");
        let path = dir.path().join("a.bin");
        let unrelated = dir.path().join("unrelated.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        staging.write_exact(BYTES).unwrap();
        fs::write(&unrelated, OTHER).unwrap();

        let saved = staging.judge(BYTES).unwrap();

        assert_eq!(staging.ownership(&path), Ownership::Sole(saved));
        assert_eq!(staging.abandon(&path), AbandonResult::Clean);
        assert!(!path.exists());
        assert_eq!(fs::read(&unrelated).unwrap(), OTHER);
        assert_eq!(names(dir.path()), vec!["unrelated.bin"]);
    }

    #[test]
    fn abandon_retains_a_file_with_another_name_and_makes_no_native_call() {
        let dir = scratch("staging-other-names");
        let path = dir.path().join("a.bin");
        let alias = dir.path().join("alias.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        staging.write_exact(BYTES).unwrap();
        fs::hard_link(&path, &alias).unwrap();

        assert_eq!(staging.ownership(&path), Ownership::OtherNames);

        let _ = take_last_delete_status();

        assert_eq!(staging.abandon(&path), AbandonResult::Retained);
        assert_eq!(take_last_delete_status(), None, "no native call was made");
        assert_eq!(fs::read(&path).unwrap(), BYTES);
        assert_eq!(fs::read(&alias).unwrap(), BYTES);
    }

    #[test]
    fn abandon_never_removes_a_name_that_is_not_ours() {
        let dir = scratch("staging-not-ours");
        let path = dir.path().join("a.bin");
        let moved = dir.path().join("moved.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        staging.write_exact(BYTES).unwrap();

        // The name is consumed by a rename through the handle itself.
        let pin = DirectoryPin::acquire(dir.path()).unwrap();
        let status = staging.publish_no_replace(&pin, OsStr::new("moved.bin"));

        assert_eq!(status, RenameStatus::Renamed);
        assert!(!path.exists() && moved.exists());

        // A foreign file now sits at the staging name.
        fs::write(&path, OTHER).unwrap();

        let _ = take_last_delete_status();

        assert_eq!(staging.ownership(&path), Ownership::NameNotOurs);
        assert_eq!(staging.abandon(&path), AbandonResult::Retained);
        assert_eq!(take_last_delete_status(), None);
        assert_eq!(
            fs::read(&path).unwrap(),
            OTHER,
            "the foreign file is intact"
        );
        assert_eq!(fs::read(&moved).unwrap(), BYTES);
    }

    #[test]
    fn abandon_with_a_refused_or_unproven_mark_is_uncertain_and_never_retried() {
        for (label, status) in [
            ("refused", 0xC000_0022_u32 as i32),
            ("success without a mark", 0),
        ] {
            let dir = scratch(&format!("staging-uncertain-{}", label.len()));
            let path = dir.path().join("a.bin");
            let mut staging = StagingFile::create_new(&path).unwrap();

            staging.write_exact(BYTES).unwrap();

            let _ = take_last_delete_status();

            inject_delete_status(status);

            assert_eq!(staging.abandon(&path), AbandonResult::Uncertain, "{label}");
            assert_eq!(take_last_delete_status(), Some(status), "{label}");
            // One injected call; a retry would have made a real one and removed it.
            assert_eq!(fs::read(&path).unwrap(), BYTES, "{label}: not retried");
        }
    }

    #[test]
    fn the_pin_handle_is_the_directory_a_rename_lands_in() {
        let dir = scratch("staging-publish");
        let path = dir.path().join("a.bin");
        let target = dir.path().join("final.bin");
        let mut staging = StagingFile::create_new(&path).unwrap();

        staging.write_exact(BYTES).unwrap();

        let pin = DirectoryPin::acquire(dir.path()).unwrap();
        let saved = staging.judge(BYTES).unwrap();

        assert_eq!(
            staging.publish_no_replace(&pin, OsStr::new("final.bin")),
            RenameStatus::Renamed
        );
        assert_eq!(staging.facts().unwrap(), saved);
        assert_eq!(fs::read(&target).unwrap(), BYTES);
        assert!(!path.exists());

        // The pin handle is a directory handle.
        assert!(open_directory_pin(dir.path()).is_ok());
    }

    // ---- source -------------------------------------------------------------------------

    /// The production half of this file: everything before the unit tests.
    fn production() -> &'static str {
        let source = include_str!("held_staging.rs");

        &source[..source.find("\n#[cfg(all(test, windows))]").unwrap()]
    }

    #[test]
    fn pure_the_module_has_one_removal_one_rename_no_foreign_code_and_no_grammar() {
        // PURE source scan of the production text, comments included.
        let text = production();

        for forbidden in [
            "unsafe",
            "extern",
            "impl Drop",
            "Drop for",
            "allow(",
            "remove_file",
            "remove_dir",
            "fs::rename",
            "hard_link",
            "fs::write",
            "fs::copy",
            "std::process",
            "Command",
            "getrandom",
            "new_v4",
            // the store's grammar, which this module must not know
            "tmp",
            "json",
            "retired",
            "v3stage",
            "record_key",
            "Locator",
            ".qa-local",
        ] {
            assert!(
                !text.contains(forbidden),
                "{forbidden:?} in held_staging.rs"
            );
        }

        // Every native operation is the existing handle-bound one, in one place each.
        assert_eq!(text.matches("delete_by_handle(").count(), 1);
        assert_eq!(text.matches("rename_into_directory_no_replace(").count(), 1);
        assert_eq!(text.matches("create_new(").count(), 2);
    }
}
