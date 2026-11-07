//! Handle-bound removal of legacy sync-state files (Stage 1U-4, slice
//! B3c-3b-2d-1, gate G12 for **reset** only).
//!
//! The legacy reset used to compare an earlier observation of a file and then remove
//! "whatever is at the path". This module provides the two pieces that let the store
//! remove only a file object whose bytes were read through the very handle that
//! removes it:
//!
//! * [`DirectoryPin`]: the sync-state directory, opened without following a reparse
//!   point, judged a plain directory on local NTFS, and held for the whole reset so
//!   that it cannot be renamed or deleted meanwhile.
//! * [`HeldFile`]: one file opened with `GENERIC_READ | DELETE`, read-only sharing
//!   and `FILE_FLAG_OPEN_REPARSE_POINT`, judged **on the handle**, read through the
//!   handle, re-checked through the handle and finally marked for removal through
//!   the handle (`handle_ops::delete_by_handle`). There is no path-based fallback of
//!   any kind: when a handle cannot be had, nothing is removed.
//!
//! This module knows nothing about record keys, file-name grammar or which files a
//! reset may remove: the store decides that, and passes paths. It creates, moves,
//! links and writes nothing. It adds no native call, no foreign function and no
//! dependency: it composes `new_copy_file::open_directory_pin`,
//! `file_identity::{facts_of, directory_identity_of}` and `handle_ops::delete_by_handle`.
//!
//! # No automatic removal
//!
//! Dropping a [`HeldFile`] or a [`DirectoryPin`] closes its handle and removes
//! **nothing**; there is no `Drop` implementation. A file is removed only by the
//! explicit, consuming [`HeldFile::mark_for_removal`].
//!
//! # What a mark means
//!
//! [`RemovalMark::Marked`] is claimed only when the native call succeeded **and** a
//! fresh query on the same handle succeeded and shows the same physical file,
//! delete-pending, with a link count that is exactly **one less** than the (positive)
//! count it had before: the entry the handle was opened through no longer counts.
//! [`RemovalMark::NotMarked`] only when the native call failed **and** the same
//! handle still shows the same file with the same link count, not delete-pending.
//! Every other combination, including a failed follow-up query, is
//! [`RemovalMark::Unknown`]: neither success nor a proven non-event. The native
//! return code alone is never taken as success.
//!
//! The first version of this rule required an unchanged link count. Real NTFS
//! contradicts that (see below); the corrected rule was approved by the user.
//!
//! A mark removes the **one directory entry the handle was opened through**. The file
//! object survives while it has another name; a mark never means the bytes are gone.
//!
//! # Measured behaviour (Windows 10 build 19045, local NTFS on `D:`)
//!
//! Recorded by `observed_native_facts_around_a_mark` (`--nocapture` prints `OBSERVED`
//! lines) and pinned by the tests in this module:
//!
//! * An open of the file for `DELETE` fails with a sharing violation while any other
//!   handle exists without delete sharing, and fails for any other handle that wants
//!   write or delete access while this one is held. A reader that shares everything
//!   is compatible with both.
//! * At the mark the same handle reports `NumberOfLinks` one lower and
//!   `DeletePending` true, with the same identity: a single-link file goes `1 -> 0`
//!   and one of two names goes `2 -> 1`. The name stays visible until the handle
//!   closes. The other name of a two-name file survives with its bytes, one link, not
//!   pending, and the same identity.
//!
//! # Limits (not claimed away)
//!
//! * Sharing modes bind ordinary processes only. Administrators, backup-privileged
//!   processes, kernel components and filter drivers can bypass them. Writable
//!   mapped views created before the handle was opened are not addressed.
//! * A hard link created to a held file is **not** prevented. [`HeldFile::unchanged`]
//!   notices it; a link created in the single call gap between that check and the
//!   mark is not noticed, and the other name then keeps the file object.
//! * Facts and the filesystem name come from the driver stack and are trusted.
//! * Opens are by path (there is no handle-relative open here); the directory pin and
//!   the post-pin checks narrow, not close, a redirection installed before the pin.
//! * Nothing here flushes the directory: a removal is not claimed to survive a power
//!   loss.
//!
//! No path, name, identifier, native status or byte appears in any `Debug` output or
//! error value.

use std::{
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::ERROR_SHARING_VIOLATION,
    Storage::FileSystem::{FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT},
};

use super::{
    file_identity::{directory_identity_of, facts_of, FileIdentity, HandleFacts, IdentityError},
    handle_ops::delete_by_handle,
    new_copy_file::open_directory_pin,
    sync_state_store::RemovalRefusal,
};

// ---- the pinned directory ----------------------------------------------------

/// The sync-state directory, held open for the duration of one reset. Dropping it
/// closes the handle and removes nothing. `Debug` is redacted.
#[must_use]
pub(crate) struct DirectoryPin {
    handle: File,
    identity: FileIdentity,
}

impl fmt::Debug for DirectoryPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryPin(<redacted>)")
    }
}

impl DirectoryPin {
    /// Open `dir` as a pin (no reparse follow, no delete sharing) and judge the
    /// **handle**: a plain directory, not a reparse point, on local NTFS, not
    /// delete-pending, with a meaningful identity. Any failure is
    /// [`RemovalRefusal::DirectoryUnsupported`]; nothing has been touched.
    pub(crate) fn acquire(dir: &Path) -> Result<Self, RemovalRefusal> {
        let handle = open_directory_pin(dir).map_err(|_| RemovalRefusal::DirectoryUnsupported)?;

        match handle.metadata() {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => {}
            _ => return Err(RemovalRefusal::DirectoryUnsupported),
        }

        let identity = directory_identity_of(&handle)
            .map_err(|_: IdentityError| RemovalRefusal::DirectoryUnsupported)?;

        Ok(Self { handle, identity })
    }

    /// Whether the pin is still the same live directory **and** a fresh open of `dir`
    /// reaches that directory. This detects an observed substitution only; a
    /// directory replaced and put back is not noticed.
    pub(crate) fn still_names(&self, dir: &Path) -> bool {
        if directory_identity_of(&self.handle) != Ok(self.identity) {
            return false;
        }

        match open_directory_pin(dir) {
            Ok(fresh) => directory_identity_of(&fresh) == Ok(self.identity),
            Err(_) => false,
        }
    }
}

// ---- one held file -----------------------------------------------------------

/// One file held for removal: opened `GENERIC_READ | DELETE`, `FILE_SHARE_READ`
/// only, never following a reparse point, and judged on the handle. Move-only.
/// Dropping it closes the handle and removes **nothing**. `Debug` is redacted.
#[must_use]
pub(crate) struct HeldFile {
    handle: File,
    facts: HandleFacts,
}

impl fmt::Debug for HeldFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeldFile(<redacted>)")
    }
}

impl HeldFile {
    /// Hold the file at `path`.
    ///
    /// * the open reports a sharing violation: [`RemovalRefusal::Busy`];
    /// * the name does not exist: [`RemovalRefusal::PlanChanged`];
    /// * any other open failure, or a handle that is not a plain file, is read-only,
    ///   is not on local NTFS, is delete-pending or whose facts cannot be read:
    ///   [`RemovalRefusal::FileUnsuitable`].
    ///
    /// Nothing has been removed on any refusal.
    pub(crate) fn open(path: &Path) -> Result<Self, RemovalRefusal> {
        let handle = open_for_removal(path).map_err(|error| refusal_for_open_error(&error))?;

        Self::judge(handle)
    }

    /// Judge an opened handle: the facts are read from the handle, never the path.
    fn judge(handle: File) -> Result<Self, RemovalRefusal> {
        let metadata = handle
            .metadata()
            .map_err(|_| RemovalRefusal::FileUnsuitable)?;

        if !metadata.is_file() || is_reparse(&metadata) || is_read_only(&metadata) {
            return Err(RemovalRefusal::FileUnsuitable);
        }

        let facts = facts_of(&handle).map_err(|_| RemovalRefusal::FileUnsuitable)?;

        judge_facts(&facts)?;

        Ok(Self { handle, facts })
    }

    /// The physical identity this handle had when it was judged.
    pub(crate) fn identity(&self) -> FileIdentity {
        self.facts.identity()
    }

    /// The exact number of names the file had when it was judged.
    pub(crate) fn link_count(&self) -> u32 {
        self.facts.link_count()
    }

    /// Read the file's bytes **through this handle**, from the start: at most
    /// `limit` bytes. An empty file is `Some(vec![])`; a longer file, or a read
    /// error, is `None`. Nothing is read through a path.
    pub(crate) fn read_bounded(&self, limit: u64) -> Option<Vec<u8>> {
        let mut file = &self.handle;

        file.seek(SeekFrom::Start(0)).ok()?;

        let mut bytes = Vec::new();

        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;

        if bytes.len() as u64 > limit {
            None
        } else {
            Some(bytes)
        }
    }

    /// Whether a fresh query on this handle still reports exactly the facts it had
    /// when it was judged: the same file, link count, filesystem and a file that is
    /// not delete-pending. A failed query is "changed".
    pub(crate) fn unchanged(&self) -> bool {
        facts_of(&self.handle).is_ok_and(|now| now == self.facts)
    }

    /// Mark the one directory entry this handle was opened through for removal
    /// (`handle_ops::delete_by_handle`), query the same handle again, classify the
    /// result with [`judge_mark`] and close the handle. Consumes the file: it can be
    /// marked once. There is no retry and no other way to remove it.
    pub(crate) fn mark_for_removal(self) -> RemovalMark {
        let native_ok = delete_by_handle(&self.handle).is_ok();
        let after = facts_of(&self.handle);

        judge_mark(native_ok, after, &self.facts)
        // The handle closes here, when `self` is dropped.
    }
}

// ---- classification ----------------------------------------------------------

/// What marking a held file established. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum RemovalMark {
    /// The native call succeeded and the same handle shows the same file,
    /// delete-pending, with the same link count.
    Marked,
    /// The native call failed and the same handle shows the same file, not
    /// delete-pending.
    NotMarked,
    /// Anything else, including a follow-up query that failed.
    Unknown,
}

/// The pure decision behind [`HeldFile::mark_for_removal`]. `saved` are the facts the
/// handle had when it was judged, `after` the result of the query made on the same
/// handle after the native call. The identity and the physical invariants are
/// compared one by one: the whole facts are not compared, because the delete-pending
/// flag and the link count legitimately change at a mark.
fn judge_mark(
    native_ok: bool,
    after: Result<HandleFacts, IdentityError>,
    saved: &HandleFacts,
) -> RemovalMark {
    let Ok(now) = after else {
        return RemovalMark::Unknown;
    };

    // Whatever the native call said, a different file or a different filesystem
    // answer proves nothing.
    if now.identity() != saved.identity() || !now.is_local_ntfs() {
        return RemovalMark::Unknown;
    }

    if native_ok {
        let one_name_fewer =
            saved.link_count() > 0 && saved.link_count().checked_sub(1) == Some(now.link_count());

        if now.is_delete_pending() && one_name_fewer {
            RemovalMark::Marked
        } else {
            RemovalMark::Unknown
        }
    } else if !now.is_delete_pending() && now.link_count() == saved.link_count() {
        RemovalMark::NotMarked
    } else {
        RemovalMark::Unknown
    }
}

/// What a handle's facts must show for the file to be held: local NTFS and not
/// delete-pending. (A plain file and the read-only attribute are judged from the
/// handle's metadata.)
fn judge_facts(facts: &HandleFacts) -> Result<(), RemovalRefusal> {
    if facts.is_local_ntfs() && !facts.is_delete_pending() {
        Ok(())
    } else {
        Err(RemovalRefusal::FileUnsuitable)
    }
}

/// The only place an open failure becomes a refusal.
fn refusal_for_open_error(error: &io::Error) -> RemovalRefusal {
    if error.kind() == io::ErrorKind::NotFound {
        RemovalRefusal::PlanChanged
    } else if is_sharing_violation(error) {
        RemovalRefusal::Busy
    } else {
        RemovalRefusal::FileUnsuitable
    }
}

fn is_sharing_violation(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
    }

    #[cfg(not(windows))]
    {
        let _ = error;

        false
    }
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

/// `GENERIC_READ | DELETE`, `FILE_SHARE_READ` only, `FILE_FLAG_OPEN_REPARSE_POINT`:
/// the hold pattern of the exchange module. Windows only; elsewhere there is no hold
/// and so no removal.
#[cfg(windows)]
fn open_for_removal(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
    };

    fs::OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_for_removal(_path: &Path) -> io::Result<File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

// ---- tests ---------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::OpenOptionsExt,
    };

    use super::*;
    use crate::vault::{
        file_identity::{FileSystemKind, VolumeFacts},
        handle_ops::{inject_delete_status, take_last_delete_status, test_support::*},
    };

    const BYTES: &[u8] = b"held-removal-synthetic-bytes-0123456789";

    fn facts(links: u32, pending: bool, id: u8) -> HandleFacts {
        HandleFacts::for_test(7, [id; 16], links, pending, FileSystemKind::Ntfs, true)
    }

    fn put(path: &Path, bytes: &[u8]) {
        let mut file = fs::File::create(path).unwrap();

        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    // ---- PURE ---------------------------------------------------------------------

    #[test]
    fn pure_the_mark_decision_table_is_exact() {
        // PURE / INJECTED facts. The corrected rule: Marked needs success, a
        // successful query, the same file, delete-pending and links == before - 1.
        let ok = |links, pending, id| Ok(facts(links, pending, id));

        // Marked: single link 1 -> 0, and one of two names 2 -> 1, 3 -> 2.
        for (before, after) in [(1u32, 0u32), (2, 1), (3, 2)] {
            assert_eq!(
                judge_mark(true, ok(after, true, 1), &facts(before, false, 1)),
                RemovalMark::Marked,
                "{before} -> {after}"
            );
        }

        // NotMarked: failure, same file, same link count, not delete-pending.
        for links in [1u32, 2] {
            assert_eq!(
                judge_mark(false, ok(links, false, 1), &facts(links, false, 1)),
                RemovalMark::NotMarked
            );
        }

        let saved = facts(1, false, 1);

        // Everything else is Unknown.
        for (native, after, why) in [
            (
                true,
                ok(0, false, 1),
                "success, links 1 -> 0 but not delete-pending",
            ),
            (true, ok(1, false, 1), "success without any deletion mark"),
            (
                true,
                ok(1, true, 1),
                "success, pending, link count unchanged (old rule)",
            ),
            (true, ok(2, true, 1), "success, pending, link count rose"),
            (
                true,
                ok(0, true, 2),
                "success, pending, 1 -> 0 but another file",
            ),
            (true, ok(0, false, 2), "success, another file"),
            (false, ok(1, true, 1), "failure but delete-pending"),
            (
                false,
                ok(0, true, 1),
                "failure, pending, link count dropped",
            ),
            (
                false,
                ok(0, false, 1),
                "failure with an unexpected link count drop",
            ),
            (
                false,
                ok(2, false, 1),
                "failure with an unexpected link count rise",
            ),
            (false, ok(1, false, 2), "failure, another file"),
            (false, ok(1, true, 2), "failure, pending, another file"),
            (
                true,
                Err(IdentityError::Lookup),
                "success, post-mark query failed",
            ),
            (
                false,
                Err(IdentityError::Lookup),
                "failure, post-mark query failed",
            ),
            (
                true,
                Err(IdentityError::Unsupported),
                "success, unsupported",
            ),
        ] {
            assert_eq!(
                judge_mark(native, after, &saved),
                RemovalMark::Unknown,
                "{why}"
            );
        }

        // An invalid zero link count before the mark can never be Marked, whatever
        // the wrapped arithmetic would give.
        assert_eq!(
            judge_mark(true, ok(0, true, 1), &facts(0, false, 1)),
            RemovalMark::Unknown
        );
        assert_eq!(
            judge_mark(true, ok(u32::MAX, true, 1), &facts(0, false, 1)),
            RemovalMark::Unknown
        );

        // A filesystem answer that is no longer local NTFS is Unknown.
        let other = HandleFacts::for_test(7, [1; 16], 0, true, FileSystemKind::Other, true);

        assert_eq!(
            judge_mark(true, Ok(other), &facts(1, false, 1)),
            RemovalMark::Unknown
        );
    }

    #[test]
    fn pure_a_mark_is_judged_against_the_saved_link_count() {
        // PURE. An alias pair is held with two links; the mark must leave one.
        let saved = facts(2, false, 1);

        assert_eq!(
            judge_mark(true, Ok(facts(1, true, 1)), &saved),
            RemovalMark::Marked
        );
        assert_eq!(
            judge_mark(true, Ok(facts(2, true, 1)), &saved),
            RemovalMark::Unknown
        );
        assert_eq!(
            judge_mark(true, Ok(facts(0, true, 1)), &saved),
            RemovalMark::Unknown
        );
    }

    #[test]
    fn pure_only_local_ntfs_that_is_not_delete_pending_may_be_held() {
        // PURE, including non-NTFS facts a real volume here cannot produce.
        let make =
            |kind, local, pending| HandleFacts::for_test(7, [1; 16], 1, pending, kind, local);

        assert_eq!(
            judge_facts(&make(FileSystemKind::Ntfs, true, false)),
            Ok(())
        );

        for refused in [
            make(FileSystemKind::Refs, true, false),
            make(FileSystemKind::Other, true, false),
            make(FileSystemKind::Ntfs, false, false),
            make(FileSystemKind::Ntfs, true, true),
        ] {
            assert_eq!(judge_facts(&refused), Err(RemovalRefusal::FileUnsuitable));
        }

        // The volume policy this module relies on is the existing one.
        assert!(VolumeFacts::for_test(FileSystemKind::Ntfs, true).is_local_ntfs());
        assert!(!VolumeFacts::for_test(FileSystemKind::Refs, true).is_local_ntfs());
    }

    #[test]
    fn pure_open_failures_are_classified_by_one_function() {
        // PURE.
        let raw = |code| io::Error::from_raw_os_error(code);

        assert_eq!(refusal_for_open_error(&raw(32)), RemovalRefusal::Busy);
        assert_eq!(refusal_for_open_error(&raw(2)), RemovalRefusal::PlanChanged);
        assert_eq!(refusal_for_open_error(&raw(3)), RemovalRefusal::PlanChanged);
        assert_eq!(
            refusal_for_open_error(&raw(5)),
            RemovalRefusal::FileUnsuitable
        );
        assert_eq!(
            refusal_for_open_error(&raw(1224)),
            RemovalRefusal::FileUnsuitable
        );
        assert_eq!(
            refusal_for_open_error(&io::Error::from(io::ErrorKind::Unsupported)),
            RemovalRefusal::FileUnsuitable
        );
    }

    // ---- REAL NTFS: the native contract ---------------------------------------------

    /// REAL NTFS. The contract the approved decision table rests on: what the same
    /// handle reports after `delete_by_handle`. Prints `OBSERVED` lines.
    #[test]
    fn observed_native_facts_around_a_mark() {
        let dir = scratch("held-observe");
        let single = dir.path().join("single.bin");

        put(&single, BYTES);

        let held = HeldFile::open(&single).unwrap();
        let saved = held.facts;

        assert_eq!(saved.link_count(), 1);
        assert!(!saved.is_delete_pending());

        let native = delete_by_handle(&held.handle);
        let after = facts_of(&held.handle).unwrap();
        let name_visible = single.exists();

        println!(
            "OBSERVED single link: native_ok={} links {}->{} pending {}->{} same_identity={} name_visible_while_held={}",
            native.is_ok(),
            saved.link_count(),
            after.link_count(),
            saved.is_delete_pending(),
            after.is_delete_pending(),
            after.identity() == saved.identity(),
            name_visible
        );

        drop(held);

        println!(
            "OBSERVED single link: name_visible_after_close={}",
            single.exists()
        );

        // Asserted AFTER everything was printed, so a contradiction shows the facts.
        assert!(native.is_ok());
        assert!(after.is_delete_pending());
        assert_eq!(after.identity(), saved.identity());
        assert!(!single.exists());
        assert_eq!((saved.link_count(), after.link_count()), (1, 0));
        assert_eq!(judge_mark(true, Ok(after), &saved), RemovalMark::Marked);
    }

    /// REAL NTFS. Two names of one file: the mark removes only the name it was
    /// opened through, and the survivor keeps its bytes and ends with one link.
    #[test]
    fn observed_native_facts_around_a_mark_of_one_of_two_names() {
        let dir = scratch("held-observe-alias");
        let primary = dir.path().join("primary.bin");
        let alias = dir.path().join("alias.bin");

        put(&primary, BYTES);
        fs::hard_link(&primary, &alias).unwrap();

        let held = HeldFile::open(&alias).unwrap();
        let saved = held.facts;

        assert_eq!(saved.link_count(), 2);

        let native = delete_by_handle(&held.handle);
        let after = facts_of(&held.handle).unwrap();

        println!(
            "OBSERVED two names: native_ok={} links {}->{} pending={} same_identity={}",
            native.is_ok(),
            saved.link_count(),
            after.link_count(),
            after.is_delete_pending(),
            after.identity() == saved.identity()
        );

        drop(held);

        let alias_gone = !alias.exists();
        let primary_bytes = fs::read(&primary).unwrap();
        let survivor = HeldFile::open(&primary).unwrap();

        println!(
            "OBSERVED two names: alias_name_gone_after_close={} survivor links_after_close={} pending={} same_identity={}",
            alias_gone,
            survivor.link_count(),
            survivor.facts.is_delete_pending(),
            survivor.identity() == saved.identity()
        );

        // Asserted AFTER everything was printed; see the single-link test.
        assert_eq!((saved.link_count(), after.link_count()), (2, 1));
        assert!(alias_gone);
        assert_eq!(primary_bytes, BYTES);
        assert_eq!(survivor.link_count(), 1);
        assert_eq!(survivor.identity(), saved.identity());
        assert_eq!(
            judge_mark(native.is_ok(), Ok(after), &saved),
            RemovalMark::Marked
        );
    }

    /// REAL NTFS. A genuine native failure (a handle opened without `DELETE`):
    /// `NotMarked`, with the raw status recorded.
    #[test]
    fn observed_a_genuine_native_failure_is_not_marked() {
        let dir = scratch("held-observe-failure");
        let path = dir.path().join("plain.bin");

        put(&path, BYTES);

        let handle = fs::File::open(&path).unwrap();
        let saved = facts_of(&handle).unwrap();
        let _ = take_last_delete_status();
        let native = delete_by_handle(&handle);
        let status = take_last_delete_status();
        let after = facts_of(&handle);

        println!(
            "OBSERVED handle without DELETE access: native_ok={} status={:?} pending={:?}",
            native.is_ok(),
            status.map(|code| format!("0x{:08X}", code as u32)),
            after.map(|facts| facts.is_delete_pending())
        );

        assert!(native.is_err());
        assert_eq!(judge_mark(false, after, &saved), RemovalMark::NotMarked);
        assert!(path.exists());
    }

    /// REAL NTFS. The sharing contract of a hold, from this process.
    #[test]
    fn sharing_contract_of_a_hold() {
        let dir = scratch("held-sharing");
        let path = dir.path().join("held.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();

        // Compatible: a reader that shares everything.
        let reader = OpenOptions::new().read(true).open(&path);
        assert!(
            reader.is_ok(),
            "a read-only fully sharing reader is compatible"
        );

        // Refused while held: a writer, a delete-access open, a delete, a rename away.
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        assert_eq!(fs::remove_file(&path).unwrap_err().raw_os_error(), Some(32));
        assert!(fs::rename(&path, dir.path().join("moved.bin")).is_err());
        assert_eq!(fs::read(&path).unwrap(), BYTES);

        // A second hold of the same name is refused as Busy.
        assert_eq!(HeldFile::open(&path).unwrap_err(), RemovalRefusal::Busy);

        drop(reader);
        drop(held);

        // Once released, the file is an ordinary file again and nothing was removed.
        assert_eq!(fs::read(&path).unwrap(), BYTES);
    }

    #[test]
    fn a_hold_is_refused_when_someone_else_has_the_file_open_without_delete_sharing() {
        // REAL NTFS.
        let dir = scratch("held-busy");
        let path = dir.path().join("busy.bin");

        put(&path, BYTES);

        for (label, share) in [
            ("exclusive", 0u32),
            ("read-share only", 1u32),
            ("read+write", 3u32),
        ] {
            let other = OpenOptions::new()
                .read(true)
                .share_mode(share)
                .open(&path)
                .unwrap();

            assert_eq!(
                HeldFile::open(&path).unwrap_err(),
                RemovalRefusal::Busy,
                "{label}"
            );

            drop(other);
        }

        // A writer that allows everything else still blocks a hold: ours shares reads only.
        let writer = OpenOptions::new()
            .write(true)
            .share_mode(7)
            .open(&path)
            .unwrap();

        assert_eq!(HeldFile::open(&path).unwrap_err(), RemovalRefusal::Busy);

        drop(writer);

        assert!(HeldFile::open(&path).is_ok());
        assert_eq!(fs::read(&path).unwrap(), BYTES);
    }

    #[test]
    fn a_hold_is_compatible_with_a_reader_that_shares_everything() {
        // REAL NTFS.
        let dir = scratch("held-reader");
        let path = dir.path().join("shared.bin");

        put(&path, BYTES);

        let reader = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(&path)
            .unwrap();
        let held = HeldFile::open(&path).unwrap();

        assert_eq!(held.read_bounded(1024).unwrap(), BYTES);
        assert_eq!(held.mark_for_removal(), RemovalMark::Marked);

        drop(reader);

        assert!(!path.exists());
    }

    #[test]
    fn refusals_for_missing_and_unsuitable_objects() {
        // REAL NTFS.
        let dir = scratch("held-unsuitable");

        // Missing: the plan changed.
        assert_eq!(
            HeldFile::open(&dir.path().join("absent.bin")).unwrap_err(),
            RemovalRefusal::PlanChanged
        );

        // A directory is not a file.
        let folder = dir.path().join("folder");

        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("inner.txt"), b"keep").unwrap();
        assert_eq!(
            HeldFile::open(&folder).unwrap_err(),
            RemovalRefusal::FileUnsuitable
        );
        assert_eq!(fs::read(folder.join("inner.txt")).unwrap(), b"keep");

        // A junction is a reparse point and is never followed or removed.
        let target = dir.path().join("junction-target");
        let junction = dir.path().join("junction");

        fs::create_dir(&target).unwrap();
        fs::write(target.join("inner.txt"), b"keep").unwrap();
        make_junction(&junction, &target);

        assert_eq!(
            HeldFile::open(&junction).unwrap_err(),
            RemovalRefusal::FileUnsuitable
        );
        assert_eq!(fs::read(target.join("inner.txt")).unwrap(), b"keep");

        // A read-only file is refused (a mark would fail on it).
        let read_only = dir.path().join("read-only.bin");

        put(&read_only, BYTES);

        let mut permissions = fs::metadata(&read_only).unwrap().permissions();

        permissions.set_readonly(true);
        fs::set_permissions(&read_only, permissions.clone()).unwrap();

        assert_eq!(
            HeldFile::open(&read_only).unwrap_err(),
            RemovalRefusal::FileUnsuitable
        );

        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&read_only, permissions).unwrap();
        assert_eq!(fs::read(&read_only).unwrap(), BYTES);
    }

    #[test]
    fn a_hold_reads_the_exact_bounded_bytes_through_its_own_handle() {
        // REAL NTFS.
        let dir = scratch("held-read");
        let path = dir.path().join("bytes.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();

        assert_eq!(held.read_bounded(BYTES.len() as u64).unwrap(), BYTES);
        // Repeatable: every read starts at the beginning.
        assert_eq!(held.read_bounded(1024).unwrap(), BYTES);
        // One byte over the limit is None, never a truncated read.
        assert!(held.read_bounded(BYTES.len() as u64 - 1).is_none());
        assert!(held.read_bounded(0).is_none());

        drop(held);

        let empty = dir.path().join("empty.bin");

        put(&empty, b"");

        let held = HeldFile::open(&empty).unwrap();

        assert_eq!(held.read_bounded(0).unwrap(), Vec::<u8>::new());
        assert_eq!(held.read_bounded(8).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unchanged_notices_a_new_hard_link_and_dropping_removes_nothing() {
        // REAL NTFS. A hard link to a held file is NOT prevented (measured); it is
        // noticed by the recheck.
        let dir = scratch("held-unchanged");
        let path = dir.path().join("linked.bin");
        let link = dir.path().join("linked-alias.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();

        assert!(held.unchanged());

        fs::hard_link(&path, &link).unwrap();

        assert!(!held.unchanged(), "a second name must be noticed");
        assert_eq!(held.link_count(), 1, "the saved count is what was judged");

        drop(held);

        // Dropping a hold never removes anything.
        assert_eq!(fs::read(&path).unwrap(), BYTES);
        assert_eq!(fs::read(&link).unwrap(), BYTES);
    }

    #[test]
    fn marking_removes_only_the_held_name_and_the_survivor_keeps_its_bytes() {
        // REAL NTFS.
        let dir = scratch("held-mark");
        let doomed = dir.path().join("doomed.bin");
        let neighbour = dir.path().join("neighbour.bin");

        put(&doomed, BYTES);
        put(&neighbour, b"other synthetic bytes");

        let before = snapshot(dir.path());
        let held = HeldFile::open(&doomed).unwrap();

        assert_eq!(held.mark_for_removal(), RemovalMark::Marked);
        assert!(!doomed.exists());
        assert_eq!(fs::read(&neighbour).unwrap(), b"other synthetic bytes");
        assert_eq!(snapshot(dir.path()).len(), before.len() - 1);
    }

    #[test]
    fn an_injected_native_failure_is_not_marked_and_a_silent_success_is_unknown() {
        // INJECTED. The next handle delete on this thread reports a chosen status
        // without making the native call.
        let dir = scratch("held-injected");
        let path = dir.path().join("injected.bin");

        put(&path, BYTES);

        // An error status with no marking: NotMarked.
        let held = HeldFile::open(&path).unwrap();

        inject_delete_status(0xC000_0022_u32 as i32);

        assert_eq!(held.mark_for_removal(), RemovalMark::NotMarked);
        assert_eq!(fs::read(&path).unwrap(), BYTES);

        // Native success with no marking: Unknown, never Marked.
        let held = HeldFile::open(&path).unwrap();

        inject_delete_status(0);

        assert_eq!(held.mark_for_removal(), RemovalMark::Unknown);
        assert_eq!(fs::read(&path).unwrap(), BYTES);
    }

    #[test]
    fn real_a_hard_link_introduced_after_the_last_check_is_never_a_plain_success() {
        // REAL NTFS. A link to a held file is NOT prevented (measured). When it
        // appears after the last `unchanged()` check, the mark removes only the held
        // name, the count goes 2 -> 1 instead of 1 -> 0, and the result is Unknown:
        // never Marked. The other name keeps the file object and its bytes.
        let dir = scratch("held-late-link");
        let path = dir.path().join("late.bin");
        let link = dir.path().join("late-alias.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();

        assert!(held.unchanged());

        fs::hard_link(&path, &link).unwrap();

        // (no unchanged() call here: this is the call gap)
        assert_eq!(held.mark_for_removal(), RemovalMark::Unknown);
        assert!(!path.exists());
        assert_eq!(fs::read(&link).unwrap(), BYTES);
    }

    #[test]
    fn injected_native_success_without_a_mark_is_unknown_and_changes_nothing() {
        // INJECTED. The native call is replaced by a bare success: nothing was marked,
        // so the facts show no pending delete and the count is unchanged.
        let dir = scratch("held-silent-success");
        let path = dir.path().join("silent.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();

        inject_delete_status(0);

        assert_eq!(held.mark_for_removal(), RemovalMark::Unknown);
        assert_eq!(fs::read(&path).unwrap(), BYTES);
    }

    #[test]
    fn real_child_process_attempts_against_a_held_file_and_its_other_name() {
        // REAL NTFS, real child cmd.exe. OBSERVED on this machine (build 19045) with
        // an alias pair held through ONE name:
        //   * through the HELD name: overwrite, rename and delete are all refused;
        //   * through the OTHER name of the same file: an overwrite is refused (the
        //     data is protected) but a RENAME and a DELETE of that name SUCCEED.
        // So the sharing model protects the file's bytes and the held name, not the
        // other name. Callers must re-verify the other name (identity, link count,
        // bytes) after the held one is removed, and never assume it was protected.
        let dir = scratch("held-child");
        let primary = dir.path().join("primary.bin");
        let alias = dir.path().join("alias.bin");

        put(&primary, BYTES);
        fs::hard_link(&primary, &alias).unwrap();

        let held = HeldFile::open(&alias).unwrap();
        let os = std::ffi::OsStr::new;
        let cmd = |args: &[&std::ffi::OsStr]| {
            std::process::Command::new("cmd")
                .arg("/C")
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        };

        // The held name.
        let _ = cmd(&[os("copy"), os("/Y"), os("NUL"), alias.as_os_str()]);
        assert_eq!(
            fs::read(&alias).unwrap(),
            BYTES,
            "overwrite via the held name"
        );
        assert!(
            !cmd(&[os("ren"), alias.as_os_str(), os("renamed.bin")]),
            "rename of the held name"
        );
        // (`del` reports success to its caller even when it fails: judge it by what is left.)
        let _ = cmd(&[os("del"), os("/F"), alias.as_os_str()]);
        assert!(alias.exists(), "delete of the held name");
        assert!(held.unchanged());

        // The other name: the data is protected, the entry is not.
        let _ = cmd(&[os("copy"), os("/Y"), os("NUL"), primary.as_os_str()]);
        assert_eq!(
            fs::read(&primary).unwrap(),
            BYTES,
            "overwrite via the other name"
        );

        let _ = cmd(&[os("del"), os("/F"), primary.as_os_str()]);
        assert!(
            !primary.exists(),
            "OBSERVED: the other name can be unlinked"
        );
        assert!(
            !held.unchanged(),
            "and the held handle notices it (links 2 -> 1)"
        );
        assert_eq!(fs::read(&alias).unwrap(), BYTES);
    }

    // NOT VERIFIED (UNAVAILABLE): an unlink or link race inside the call gap between
    // `unchanged()` and the native call cannot be reproduced reliably under the
    // sharing model (another unlink is refused for the whole hold; a link is not).
    // The late-link test above covers the physical consequence; no prevention is
    // claimed.

    // ---- directory pin -----------------------------------------------------------------

    #[test]
    fn a_pin_holds_a_plain_local_ntfs_directory_and_blocks_its_rename_and_removal() {
        // REAL NTFS.
        let dir = scratch("held-pin");
        let watched = dir.path().join("watched");

        fs::create_dir(&watched).unwrap();
        fs::write(watched.join("inside.bin"), BYTES).unwrap();

        let pin = DirectoryPin::acquire(&watched).unwrap();

        assert!(pin.still_names(&watched));
        assert!(fs::rename(&watched, dir.path().join("renamed")).is_err());
        assert!(fs::remove_dir(&watched).is_err());
        assert!(watched.exists());

        // Files inside may still be created and removed: the pin is not a lock on them.
        fs::write(watched.join("extra.bin"), b"x").unwrap();
        fs::remove_file(watched.join("extra.bin")).unwrap();

        drop(pin);

        // Dropping removes nothing.
        assert_eq!(fs::read(watched.join("inside.bin")).unwrap(), BYTES);
    }

    #[test]
    fn a_pin_refuses_a_missing_directory_a_file_and_a_junction() {
        // REAL NTFS.
        let dir = scratch("held-pin-refusals");

        assert_eq!(
            DirectoryPin::acquire(&dir.path().join("absent")).unwrap_err(),
            RemovalRefusal::DirectoryUnsupported
        );

        let file = dir.path().join("file.bin");

        put(&file, BYTES);

        assert_eq!(
            DirectoryPin::acquire(&file).unwrap_err(),
            RemovalRefusal::DirectoryUnsupported
        );

        let target = dir.path().join("target");
        let junction = dir.path().join("junction");

        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside.bin"), BYTES).unwrap();
        make_junction(&junction, &target);

        assert_eq!(
            DirectoryPin::acquire(&junction).unwrap_err(),
            RemovalRefusal::DirectoryUnsupported
        );
        assert_eq!(fs::read(target.join("inside.bin")).unwrap(), BYTES);
    }

    // ---- source and redaction ----------------------------------------------------------

    /// The production half of this file: everything before the unit tests.
    fn production() -> &'static str {
        let source = include_str!("held_removal.rs");

        &source[..source.find("\n#[cfg(all(test, windows))]").unwrap()]
    }

    fn code_only(text: &str) -> String {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn pure_the_module_has_no_path_based_mutation_no_foreign_code_and_no_grammar() {
        // PURE source scan.
        let code = code_only(production());

        for forbidden in [
            "remove_file",
            "remove_dir",
            "fs::rename",
            "hard_link",
            "fs::write",
            "fs::copy",
            "create_new",
            "set_len",
            "unsafe",
            "extern",
            "getrandom",
            "new_v4",
            "impl Drop",
            "Drop for",
            "allow(",
            "std::process",
            "Command",
            // the store's grammar, which this module must not know
            "tmp",
            "json",
            "retired",
            "v3stage",
            "ARTIFACT",
            "record_key",
            "Locator",
            ".qa-local",
        ] {
            assert!(
                !code.contains(forbidden),
                "{forbidden:?} in held_removal.rs"
            );
        }

        // The only removal is the handle-bound one, in one place.
        assert_eq!(code.matches("delete_by_handle(").count(), 1);
    }

    #[test]
    fn pure_nothing_printed_reveals_a_path_name_identity_or_status() {
        // PURE.
        let dir = scratch("held-redaction");
        let path = dir.path().join("SECRET-NAME-MARK.bin");

        put(&path, BYTES);

        let held = HeldFile::open(&path).unwrap();
        let pin = DirectoryPin::acquire(dir.path()).unwrap();
        let mut shown = vec![
            format!("{held:?}"),
            format!("{held:#?}"),
            format!("{pin:?}"),
            format!("{pin:#?}"),
        ];

        for refusal in [
            RemovalRefusal::Busy,
            RemovalRefusal::DirectoryUnsupported,
            RemovalRefusal::FileUnsuitable,
            RemovalRefusal::ExtraNames,
            RemovalRefusal::PlanChanged,
        ] {
            shown.push(format!("{refusal:?}"));
        }
        for mark in [
            RemovalMark::Marked,
            RemovalMark::NotMarked,
            RemovalMark::Unknown,
        ] {
            shown.push(format!("{mark:?}"));
        }

        for text in &shown {
            for needle in [
                "SECRET-NAME-MARK",
                ".bin",
                ".qa-local",
                "held-redaction",
                "\\",
                "0x",
            ] {
                assert!(!text.contains(needle), "{needle:?} leaked in {text}");
            }
        }
    }
}
