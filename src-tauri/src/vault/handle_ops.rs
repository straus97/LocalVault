//! Handle-bound rename-without-replace and handle-bound delete (Stage 1U-4,
//! slice B2a).
//!
//! Exists for one purpose: publishing a freshly written, still-open staging file
//! under its final name in an already-pinned directory, **without ever replacing
//! anything** and without a second, path-based resolution of either name; and
//! removing that staging file again through the very handle that created it.
//! `std` offers neither (its rename, hard-link and remove all resolve a path at
//! the instant of the call), so this module makes exactly two native calls to one
//! `ntdll` function, `NtSetInformationFile`:
//!
//! * [`rename_into_directory_no_replace`]: information class
//!   `FileRenameInformation` (10) with `ReplaceIfExists` FALSE, `RootDirectory` the
//!   caller's **live, pinned directory handle** and `FileName` one validated leaf.
//!   The kernel resolves the leaf relative to the directory *object* behind that
//!   handle, not relative to the process working directory and not through any path
//!   string. The staging file itself is named by its handle.
//! * [`delete_by_handle`]: information class `FileDispositionInformationEx` (64)
//!   with `DELETE | POSIX_SEMANTICS`, applied to the open staging handle: it marks
//!   for deletion the one directory entry the handle was opened through, and
//!   nothing else. **Observed on this machine (Windows 10 build 19045):** the file
//!   becomes delete-pending but its name stays visible until the handle is closed,
//!   so the caller closes the handle and then checks the result; the effect is
//!   never assumed to be immediate.
//!
//! Everything else (the pin, the staging file, the identity and the verification)
//! is safe code in `new_copy_file`. No raw handle, pointer or `unsafe fn` leaves
//! this module.
//!
//! # What an NTSTATUS means here
//!
//! Only exactly `STATUS_SUCCESS` (0) is "renamed". A non-zero status is **not**
//! success, and not every error status proves that nothing happened: the listed
//! refusals are statuses NTFS returns *without performing the rename*; every other
//! status, including every informational or warning status (zero or positive but
//! not zero) and `STATUS_PENDING`, is [`RenameStatus::Unknown`]. The caller decides
//! what a refusal permits (it must still show that the target is not ours) and
//! never deletes after `Renamed` or `Unknown`.
//!
//! # Limits (not claimed away)
//!
//! * Whether a given NTSTATUS was really returned without side effects is the
//!   filesystem driver's behavior; this module classifies conservatively and does
//!   not prove it. Privileged actors and filter drivers are out of scope.
//! * Nothing here flushes the directory: the published name is not claimed to be
//!   power-loss durable.
//!
//! No path, handle value, status code or file content appears in any error or
//! `Debug` output.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(windows), allow(dead_code))]

use std::{ffi::OsStr, fs::File, io};

#[cfg(test)]
use std::cell::Cell;

/// `NTSTATUS` values that mean "the rename was refused and not performed". The
/// fixed set the B2 design relies on; anything else is [`RenameStatus::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefiniteRefusal {
    /// `STATUS_OBJECT_NAME_COLLISION`: the leaf already exists in the directory.
    NameCollision,
    /// `STATUS_NOT_SAME_DEVICE`: the directory is on another volume.
    NotSameDevice,
    /// `STATUS_OBJECT_NAME_INVALID`.
    NameInvalid,
    /// `STATUS_INVALID_PARAMETER`.
    InvalidParameter,
    /// `STATUS_ACCESS_DENIED`.
    AccessDenied,
    /// `STATUS_SHARING_VIOLATION`.
    SharingViolation,
}

/// The classified result of a rename request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum RenameStatus {
    /// Exactly `STATUS_SUCCESS`: the staging file now has the leaf name in the
    /// pinned directory.
    Renamed,
    /// A status NTFS returns without performing the rename.
    Refused(DefiniteRefusal),
    /// Any other status: whether the rename happened is not established.
    Unknown,
    /// The leaf was not one plain name, so **no native call was made**.
    Rejected,
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_NOT_SAME_DEVICE: i32 = 0xC000_00D4_u32 as i32;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033_u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043_u32 as i32;

/// The one place an `NTSTATUS` becomes a [`RenameStatus`]. Exactly zero is
/// success; only the six listed error statuses are definite refusals.
pub(crate) fn classify_rename_status(status: i32) -> RenameStatus {
    match status {
        STATUS_SUCCESS => RenameStatus::Renamed,
        STATUS_OBJECT_NAME_COLLISION => RenameStatus::Refused(DefiniteRefusal::NameCollision),
        STATUS_NOT_SAME_DEVICE => RenameStatus::Refused(DefiniteRefusal::NotSameDevice),
        STATUS_OBJECT_NAME_INVALID => RenameStatus::Refused(DefiniteRefusal::NameInvalid),
        STATUS_INVALID_PARAMETER => RenameStatus::Refused(DefiniteRefusal::InvalidParameter),
        STATUS_ACCESS_DENIED => RenameStatus::Refused(DefiniteRefusal::AccessDenied),
        STATUS_SHARING_VIOLATION => RenameStatus::Refused(DefiniteRefusal::SharingViolation),
        _ => RenameStatus::Unknown,
    }
}

/// Move the open `file` into the directory behind `directory` under the name
/// `leaf`, and **never replace anything**. Both handles are borrowed for the call
/// only. `file` must have been opened with `DELETE` access; `directory` must be
/// the live, pinned, verified destination.
///
/// A `leaf` that is not one plain name (empty, containing `\`, `/`, `:` or NUL, or
/// too long for the native structure) is [`RenameStatus::Rejected`] and no native
/// call is made.
pub(crate) fn rename_into_directory_no_replace(
    file: &File,
    directory: &File,
    leaf: &OsStr,
) -> RenameStatus {
    #[cfg(test)]
    if let Some(injected) = INJECTED_RENAME.take() {
        LAST_RENAME_STATUS.set(Some(injected));

        return classify_rename_status(injected);
    }

    match imp::rename(file, directory, leaf) {
        imp::Native::Status(status) => {
            #[cfg(test)]
            LAST_RENAME_STATUS.set(Some(status));

            classify_rename_status(status)
        }
        imp::Native::Rejected => RenameStatus::Rejected,
        imp::Native::Unsupported => RenameStatus::Unknown,
    }
}

/// Mark for deletion, through `file` alone, the one directory entry it was opened
/// through (`FileDispositionInformationEx`, `DELETE | POSIX_SEMANTICS`). `file`
/// must have been opened with `DELETE` access. The deletion is **not** observed to
/// be immediate (see the module documentation): the caller must drop the handle
/// and verify. Anything other than exactly `STATUS_SUCCESS` is an error, and there
/// is no fallback to another disposition class or to a path-based delete.
pub(crate) fn delete_by_handle(file: &File) -> io::Result<()> {
    #[cfg(test)]
    if let Some(injected) = INJECTED_DELETE.take() {
        LAST_DELETE_STATUS.set(Some(injected));

        return if injected == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(delete_refused())
        };
    }

    match imp::delete(file) {
        imp::Native::Status(status) => {
            #[cfg(test)]
            LAST_DELETE_STATUS.set(Some(status));

            if status == STATUS_SUCCESS {
                Ok(())
            } else {
                Err(delete_refused())
            }
        }
        imp::Native::Rejected | imp::Native::Unsupported => {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

fn delete_refused() -> io::Error {
    io::Error::other("the handle-bound delete was refused")
}

#[cfg(test)]
thread_local! {
    static INJECTED_RENAME: Cell<Option<i32>> = const { Cell::new(None) };
    static INJECTED_DELETE: Cell<Option<i32>> = const { Cell::new(None) };
    static LAST_RENAME_STATUS: Cell<Option<i32>> = const { Cell::new(None) };
    static LAST_DELETE_STATUS: Cell<Option<i32>> = const { Cell::new(None) };
}

/// Test-only: the next rename on **this thread** returns `status` instead of
/// making the native call. One-shot.
#[cfg(test)]
pub(crate) fn inject_rename_status(status: i32) {
    INJECTED_RENAME.set(Some(status));
}

/// Test-only: the next [`delete_by_handle`] on this thread reports `status`
/// without making the native call. One-shot.
#[cfg(test)]
pub(crate) fn inject_delete_status(status: i32) {
    INJECTED_DELETE.set(Some(status));
}

/// Test-only: the raw `NTSTATUS` of the last rename on this thread, injected or
/// real. Taken (reset) by the call.
#[cfg(test)]
pub(crate) fn take_last_rename_status() -> Option<i32> {
    LAST_RENAME_STATUS.take()
}

/// Test-only: the raw `NTSTATUS` of the last handle delete on this thread.
#[cfg(test)]
pub(crate) fn take_last_delete_status() -> Option<i32> {
    LAST_DELETE_STATUS.take()
}

#[cfg(windows)]
mod imp {
    //! The FFI safety boundary. Exactly two `unsafe` blocks, one per native call.

    use std::{
        ffi::{c_void, OsStr},
        fs::File,
        mem::{offset_of, size_of},
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
    };

    use windows_sys::{
        Wdk::Storage::FileSystem::{
            FileDispositionInformationEx, FileRenameInformation, NtSetInformationFile,
            FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION_EX,
            FILE_DISPOSITION_POSIX_SEMANTICS, FILE_RENAME_INFORMATION,
        },
        Win32::{Foundation::HANDLE, System::IO::IO_STATUS_BLOCK},
    };

    pub(super) enum Native {
        /// The raw `NTSTATUS` the native call returned.
        Status(i32),
        /// Rejected before any native call.
        Rejected,
        #[allow(dead_code)]
        Unsupported,
    }

    // The buffer below stores the directory handle as a pointer-sized integer.
    const _: () = assert!(size_of::<HANDLE>() == size_of::<usize>());

    /// The `FILE_RENAME_INFORMATION` image for `leaf`, as 8-byte-aligned words, and
    /// the exact byte length to pass. Built with safe code only: every field is
    /// written as bytes at its `offset_of!` position into a zeroed buffer (so the
    /// union, `ReplaceIfExists` included, is zero), then packed into `u64` words so
    /// the buffer is aligned for the structure.
    ///
    /// `None` if `leaf` is not one plain name or does not fit the structure.
    pub(super) fn rename_buffer(root: usize, leaf: &OsStr) -> Option<(Vec<u64>, u32)> {
        let name: Vec<u16> = leaf.encode_wide().collect();

        if name.is_empty()
            || name
                .iter()
                .any(|&unit| matches!(unit, 0 | 0x2F | 0x3A | 0x5C))
        {
            return None;
        }

        let name_bytes = name.len().checked_mul(2)?;
        let name_length = u32::try_from(name_bytes).ok()?;
        let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let used = name_offset.checked_add(name_bytes)?;
        let length = u32::try_from(used).ok()?;

        // Never smaller than the structure itself; padded to whole words.
        let words = used.max(size_of::<FILE_RENAME_INFORMATION>()).div_ceil(8);
        let mut bytes = vec![0u8; words.checked_mul(8)?];

        let root_offset = offset_of!(FILE_RENAME_INFORMATION, RootDirectory);
        let length_offset = offset_of!(FILE_RENAME_INFORMATION, FileNameLength);

        bytes[root_offset..root_offset + size_of::<usize>()].copy_from_slice(&root.to_ne_bytes());
        bytes[length_offset..length_offset + size_of::<u32>()]
            .copy_from_slice(&name_length.to_ne_bytes());

        for (index, unit) in name.iter().enumerate() {
            let at = name_offset + index * 2;

            bytes[at..at + 2].copy_from_slice(&unit.to_ne_bytes());
        }

        let buffer = (0..words)
            .map(|index| {
                let word = &bytes[index * 8..index * 8 + 8];

                u64::from_ne_bytes(word.try_into().expect("eight bytes"))
            })
            .collect();

        Some((buffer, length))
    }

    pub(super) fn rename(file: &File, directory: &File, leaf: &OsStr) -> Native {
        let root = directory.as_raw_handle() as usize;

        let Some((buffer, length)) = rename_buffer(root, leaf) else {
            return Native::Rejected;
        };

        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: `file` and `directory` are borrowed from live `&File` values for
        // the whole call, so both handles are valid; `file` is a synchronous handle
        // (opened by `std`, never overlapped), so the call completes before it
        // returns and `STATUS_PENDING` cannot leave the kernel referring to this
        // stack frame. `buffer` is a live, 8-byte-aligned `Vec<u64>` holding a fully
        // initialised `FILE_RENAME_INFORMATION` whose `FileNameLength` and trailing
        // UTF-16 name were written within the allocation, and `length` is exactly
        // the offset of `FileName` plus the name's byte length, which never exceeds
        // the allocation. The class constant is the one defined for this layout.
        // `io_status` is a default-initialised local. The kernel copies the request
        // and retains neither pointer, and the `RootDirectory` handle is only read.
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io_status,
                buffer.as_ptr().cast::<c_void>(),
                length,
                FileRenameInformation,
            )
        };

        Native::Status(status)
    }

    pub(super) fn delete(file: &File) -> Native {
        let information = FILE_DISPOSITION_INFORMATION_EX {
            Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
        };
        let size = u32::try_from(size_of::<FILE_DISPOSITION_INFORMATION_EX>())
            .expect("a four-byte structure");
        let mut io_status = IO_STATUS_BLOCK::default();

        // SAFETY: `file` is borrowed from a live `&File` for the whole call and is
        // a synchronous handle (see `rename`). `information` is a live, properly
        // aligned, fully initialised `#[repr(C)]` local of exactly `size` bytes,
        // paired with the `FileDispositionInformationEx` class defined for it, and
        // `io_status` is a default-initialised local. Nothing is retained after the
        // call.
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io_status,
                std::ptr::from_ref(&information).cast::<c_void>(),
                size,
                FileDispositionInformationEx,
            )
        };

        Native::Status(status)
    }
}

#[cfg(not(windows))]
mod imp {
    use std::{ffi::OsStr, fs::File};

    pub(super) enum Native {
        Status(i32),
        Rejected,
        Unsupported,
    }

    pub(super) fn rename(_file: &File, _directory: &File, _leaf: &OsStr) -> Native {
        Native::Unsupported
    }

    pub(super) fn delete(_file: &File) -> Native {
        Native::Unsupported
    }
}

/// Shared scaffolding for the B2 tests (this module, `new_copy_file` and the
/// session's `copy_creation`). All scratch lives under
/// `.qa-local/sync-copy-b2-tests/`, never `%TEMP%`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::{fs, path::Path, time::SystemTime};

    use localvault_core::sync::EnvelopeFingerprint;

    use crate::vault::file_identity::volume_facts_of;

    /// A unique, test-owned directory under the B2 scratch base. Removed only by
    /// its `TempDir` guard.
    pub(crate) fn scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-copy-b2-tests");

        fs::create_dir_all(&base).unwrap();

        let dir = tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap();

        assert_local_ntfs(dir.path());

        dir
    }

    /// Fails loudly (never skips) unless `dir` is on a local NTFS volume.
    pub(crate) fn assert_local_ntfs(dir: &Path) {
        let handle = crate::vault::new_copy_file::open_directory_pin(dir)
            .expect("the scratch directory can be opened");
        let facts = volume_facts_of(&handle).expect("the scratch volume can be queried");

        assert!(
            facts.is_local_ntfs(),
            "the scratch volume is not local NTFS: the B2 tests cannot run here"
        );
    }

    /// Everything beneath `dir` without following reparse points: kind, name and,
    /// for plain files, length, modification time and content hash.
    pub(crate) fn snapshot(dir: &Path) -> Vec<String> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
            let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();

            entries.sort_by_key(|entry| entry.file_name());

            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let kind = metadata.file_type();

                if kind.is_symlink() {
                    out.push(format!("L {relative}"));
                } else if kind.is_dir() && is_reparse(&metadata) {
                    out.push(format!("J {relative}"));
                } else if kind.is_dir() {
                    out.push(format!("D {relative}"));
                    walk(&path, base, out);
                } else if relative.ends_with(".lock") {
                    out.push(format!("K {relative}"));
                } else {
                    let modified: SystemTime = metadata.modified().unwrap();
                    let hash = EnvelopeFingerprint::of_bytes(&fs::read(&path).unwrap());

                    out.push(format!(
                        "F {relative} {} {modified:?} {}",
                        metadata.len(),
                        hash.to_hex()
                    ));
                }
            }
        }

        let mut out = Vec::new();

        walk(dir, dir, &mut out);

        out
    }

    fn is_reparse(metadata: &fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt;

        metadata.file_attributes() & 0x400 != 0
    }

    /// Sorted names of the direct children of `dir`.
    pub(crate) fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();

        found.sort();

        found
    }

    /// Top-level entry names of the process working directory, `target` excluded.
    pub(crate) fn cwd_names() -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(std::env::current_dir().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "target")
            .collect();

        found.sort();

        found
    }

    pub(crate) fn make_junction(link: &Path, destination: &Path) {
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

    /// Whether any entry beneath `dir` has a name containing `needle`.
    pub(crate) fn any_name_contains(dir: &Path, needle: &str) -> bool {
        fn walk(dir: &Path, needle: &str) -> bool {
            fs::read_dir(dir).unwrap().any(|entry| {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();

                entry.file_name().to_string_lossy().contains(needle)
                    || (metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && !is_reparse(&metadata)
                        && walk(&entry.path(), needle))
            })
        }

        walk(dir, needle)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        mem::{align_of, offset_of, size_of},
        os::windows::fs::OpenOptionsExt,
        path::Path,
    };

    use windows_sys::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION;

    use super::{test_support::*, *};
    use crate::vault::{
        file_identity::{facts_of, volume_facts_of},
        new_copy_file::{create_staging, open_directory_pin},
    };

    const BYTES: &[u8] = b"b2a-handle-ops-test-bytes-0123456789";

    fn leaf() -> &'static OsStr {
        OsStr::new("target.lvault")
    }

    /// A pinned `pinned` directory beside an empty `other`, a staging file with
    /// `BYTES` in `pinned`, and the staging path.
    struct Rig {
        // The handles are declared first so they close before the scratch
        // directory guard (declared last) tries to remove the directory.
        pin: File,
        staging: File,
        pinned: std::path::PathBuf,
        staging_path: std::path::PathBuf,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn new(name: &str) -> Self {
            let dir = scratch(name);
            let pinned = dir.path().join("pinned");

            fs::create_dir(&pinned).unwrap();
            fs::create_dir(dir.path().join("other")).unwrap();

            let pin = open_directory_pin(&pinned).unwrap();
            let (mut staging, staging_path) = create_staging(&pinned, leaf()).unwrap();

            staging.write_all(BYTES).unwrap();
            staging.sync_all().unwrap();

            Self {
                dir,
                pinned,
                pin,
                staging,
                staging_path,
            }
        }

        fn rename(&self) -> (RenameStatus, i32) {
            let _ = take_last_rename_status();

            let status = rename_into_directory_no_replace(&self.staging, &self.pin, leaf());
            let raw = take_last_rename_status().expect("a native status was recorded");

            (status, raw)
        }
    }

    fn hex(status: i32) -> String {
        format!("0x{:08X}", status as u32)
    }

    // ---- layout ---------------------------------------------------------------

    #[test]
    fn the_rename_buffer_matches_the_native_layout() {
        // x64 layout of FILE_RENAME_INFORMATION (the target of this build).
        assert_eq!(align_of::<FILE_RENAME_INFORMATION>(), 8);
        assert_eq!(size_of::<FILE_RENAME_INFORMATION>(), 24);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, Anonymous), 0);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, RootDirectory), 8);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, FileNameLength), 16);
        assert_eq!(offset_of!(FILE_RENAME_INFORMATION, FileName), 20);

        let (buffer, length) = imp::rename_buffer(0x1234_5678, OsStr::new("a.lvault")).unwrap();
        let bytes: Vec<u8> = buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();

        // 20 bytes up to the name, plus 8 UTF-16 units.
        assert_eq!(length, 20 + 16);
        // Whole 8-byte words, never smaller than the structure.
        assert_eq!(bytes.len() % 8, 0);
        assert!(bytes.len() >= size_of::<FILE_RENAME_INFORMATION>());
        assert!(bytes.len() >= length as usize);

        // ReplaceIfExists / Flags are zero.
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
        assert_eq!(&bytes[8..16], &0x1234_5678usize.to_ne_bytes());
        // FileNameLength is the byte length of the name, without a terminator.
        assert_eq!(&bytes[16..20], &16u32.to_ne_bytes());

        let name: Vec<u16> = bytes[20..36]
            .chunks(2)
            .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
            .collect();

        assert_eq!(String::from_utf16(&name).unwrap(), "a.lvault");
    }

    #[test]
    fn a_leaf_that_is_not_one_plain_name_builds_no_buffer() {
        for bad in ["", "a\\b", "a/b", "C:x", "a:b", "..\\x", "x\0y"] {
            assert!(imp::rename_buffer(1, OsStr::new(bad)).is_none(), "{bad:?}");
        }

        assert!(imp::rename_buffer(1, OsStr::new("ok.lvault")).is_some());
        assert!(imp::rename_buffer(1, OsStr::new("ünï-ключ.lvault")).is_some());
    }

    #[test]
    fn statuses_are_classified_conservatively() {
        use DefiniteRefusal::*;

        assert_eq!(classify_rename_status(0), RenameStatus::Renamed);
        assert_eq!(
            classify_rename_status(0xC000_0035_u32 as i32),
            RenameStatus::Refused(NameCollision)
        );
        assert_eq!(
            classify_rename_status(0xC000_00D4_u32 as i32),
            RenameStatus::Refused(NotSameDevice)
        );
        assert_eq!(
            classify_rename_status(0xC000_0033_u32 as i32),
            RenameStatus::Refused(NameInvalid)
        );
        assert_eq!(
            classify_rename_status(0xC000_000D_u32 as i32),
            RenameStatus::Refused(InvalidParameter)
        );
        assert_eq!(
            classify_rename_status(0xC000_0022_u32 as i32),
            RenameStatus::Refused(AccessDenied)
        );
        assert_eq!(
            classify_rename_status(0xC000_0043_u32 as i32),
            RenameStatus::Refused(SharingViolation)
        );

        // Nothing else is a refusal and nothing non-zero is success: an
        // unsuccessful, an informational, a warning and a pending status.
        for other in [
            0xC000_0001_u32 as i32,
            0x4000_0000,
            0x8000_0005_u32 as i32,
            0x0000_0103,
            1,
            -1,
        ] {
            assert_eq!(classify_rename_status(other), RenameStatus::Unknown);
        }
    }

    #[test]
    fn injected_statuses_replace_the_native_call_once() {
        let rig = Rig::new("handle-ops-inject");

        inject_rename_status(0xC000_0001_u32 as i32);

        assert_eq!(
            rename_into_directory_no_replace(&rig.staging, &rig.pin, leaf()),
            RenameStatus::Unknown
        );
        assert_eq!(
            super::take_last_rename_status(),
            Some(0xC000_0001_u32 as i32)
        );
        // Nothing was renamed by the injected call.
        assert!(rig.staging_path.exists());
        assert!(!rig.pinned.join(leaf()).exists());

        inject_delete_status(0xC000_0001_u32 as i32);

        assert!(delete_by_handle(&rig.staging).is_err());
        assert!(rig.staging_path.exists());
    }

    // ---- 1-3, 5, 6: the real rename -------------------------------------------

    #[test]
    fn the_rename_publishes_into_the_pinned_directory_and_keeps_identity() {
        let cwd = std::env::current_dir().unwrap();
        let rig = Rig::new("handle-ops-rename");

        // 2. the working directory is neither the scratch directory nor an ancestor.
        assert!(!rig.dir.path().starts_with(&cwd));
        assert!(!cwd.starts_with(rig.dir.path()));

        let cwd_before = cwd_names();
        let before = facts_of(&rig.staging).unwrap();

        assert!(before.is_local_ntfs());
        assert!(before.has_single_link());

        let (status, raw) = rig.rename();

        eprintln!("OBSERVED rename into pinned directory: {}", hex(raw));

        // GO/NO-GO: any other result stops the slice and is reported.
        assert_eq!(
            status,
            RenameStatus::Renamed,
            "the native rename was not accepted: NTSTATUS {}",
            hex(raw)
        );
        assert_eq!(raw, 0);

        // 1. it arrived under the target name, in the pinned directory only.
        let published = rig.pinned.join(leaf());

        assert_eq!(fs::read(&published).unwrap(), BYTES);
        assert!(!rig.staging_path.exists());
        assert_eq!(names(&rig.pinned), vec!["target.lvault".to_owned()]);

        // 3. nothing appeared in the working directory.
        assert_eq!(cwd_names(), cwd_before);
        assert!(!cwd.join(leaf()).exists());

        // 5. the same physical file, still one link.
        let after = facts_of(&rig.staging).unwrap();
        let independent = facts_of(&File::open(&published).unwrap()).unwrap();

        assert_eq!(before, after);
        assert_eq!(before.identity(), independent.identity());

        // 6. exactly one hard link.
        assert!(independent.has_single_link());
        assert!(after.has_single_link());
    }

    #[test]
    fn only_the_pinned_directory_receives_the_file_not_a_sibling() {
        let rig = Rig::new("handle-ops-sibling");
        let other = rig.dir.path().join("other");

        fs::write(other.join(leaf()), b"decoy in the sibling directory").unwrap();

        let decoy_before = snapshot(&other);
        let (status, raw) = rig.rename();

        assert_eq!(status, RenameStatus::Renamed, "{}", hex(raw));
        assert_eq!(snapshot(&other), decoy_before);
        assert_eq!(fs::read(rig.pinned.join(leaf())).unwrap(), BYTES);
    }

    // ---- 4: collisions never replace ------------------------------------------

    fn collide_with(name: &str, make: impl FnOnce(&Path, &Path)) {
        let rig = Rig::new(name);
        let existing = rig.pinned.join(leaf());
        let aside = rig.dir.path().join("aside");

        fs::create_dir(&aside).unwrap();
        fs::write(aside.join("inner.txt"), b"inside the junction target").unwrap();

        make(&existing, &aside);

        let before = snapshot(rig.dir.path());
        let (status, raw) = rig.rename();

        eprintln!("OBSERVED rename onto an existing {name}: {}", hex(raw));

        assert_eq!(
            status,
            RenameStatus::Refused(DefiniteRefusal::NameCollision),
            "NTSTATUS {}",
            hex(raw)
        );
        assert_eq!(raw, 0xC000_0035_u32 as i32);

        // Nothing was replaced, and the staging file still has its own name.
        let after = snapshot(rig.dir.path());

        assert_eq!(after, before);
        assert!(rig.staging_path.exists());
    }

    #[test]
    fn an_existing_file_is_never_replaced() {
        collide_with("file", |existing, _| {
            fs::write(existing, b"someone else's file").unwrap();
        });
    }

    #[test]
    fn an_existing_directory_is_never_replaced() {
        collide_with("directory", |existing, _| {
            fs::create_dir(existing).unwrap();
            fs::write(existing.join("child.txt"), b"child").unwrap();
        });
    }

    #[test]
    fn an_existing_junction_is_never_replaced() {
        collide_with("junction", |existing, aside| {
            make_junction(existing, aside);
        });
    }

    #[test]
    fn a_bad_leaf_is_rejected_before_any_native_call() {
        let rig = Rig::new("handle-ops-bad-leaf");
        let before = snapshot(rig.dir.path());

        let _ = super::take_last_rename_status();

        for bad in ["", "a\\b", "a/b", "a:b", "..\\target.lvault", "x\0y"] {
            assert_eq!(
                rename_into_directory_no_replace(&rig.staging, &rig.pin, OsStr::new(bad)),
                RenameStatus::Rejected,
                "{bad:?}"
            );
        }

        assert_eq!(super::take_last_rename_status(), None);
        assert_eq!(snapshot(rig.dir.path()), before);
    }

    // ---- 7: handle-bound delete touches only the opened name --------------------

    #[test]
    fn delete_by_handle_marks_only_the_name_it_was_opened_through() {
        let dir = scratch("handle-ops-delete");
        let first = dir.path().join("first.bin");
        let second = dir.path().join("second.bin");
        let bystander = dir.path().join("bystander.bin");

        fs::write(&first, b"shared content").unwrap();
        fs::write(&bystander, b"bystander").unwrap();
        fs::hard_link(&first, &second).unwrap();

        let bystander_before = snapshot(dir.path())
            .into_iter()
            .filter(|line| line.contains("bystander"))
            .collect::<Vec<_>>();

        // DELETE access, opened through the first name only.
        let handle = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(0x8000_0000 | 0x4000_0000 | 0x0001_0000)
            .share_mode(1)
            .open(&first)
            .unwrap();

        assert!(!facts_of(&handle).unwrap().is_delete_pending());

        let _ = super::take_last_delete_status();

        delete_by_handle(&handle).expect("the handle-bound delete is accepted");

        eprintln!(
            "OBSERVED delete_by_handle: {}",
            hex(super::take_last_delete_status().unwrap())
        );

        // OBSERVED on this machine: accepted, the file is delete-pending, and the
        // name stays visible until the handle closes.
        assert!(facts_of(&handle).unwrap().is_delete_pending());

        drop(handle);

        // Only the name it was opened through is gone.
        assert!(!first.exists());
        assert_eq!(fs::read(&second).unwrap(), b"shared content");
        assert_eq!(fs::read(&bystander).unwrap(), b"bystander");

        let survivor = facts_of(&File::open(&second).unwrap()).unwrap();

        assert!(survivor.has_single_link());
        assert!(!survivor.is_delete_pending());

        let bystander_after = snapshot(dir.path())
            .into_iter()
            .filter(|line| line.contains("bystander"))
            .collect::<Vec<_>>();

        assert_eq!(bystander_after, bystander_before);
    }

    // ---- sharing while the staging handle is held -------------------------------

    #[test]
    fn the_sharing_mode_blocks_ordinary_operations_on_the_staging_path() {
        let rig = Rig::new("handle-ops-sharing");
        let elsewhere = rig.pinned.join("moved-away.tmp");
        let primary = rig.dir.path().join("primary.lvault");

        fs::write(&primary, b"stands in for the primary vault").unwrap();

        let describe = |label: &str, result: std::io::Result<()>| -> std::io::Error {
            let error = result.expect_err(label);

            eprintln!(
                "OBSERVED sharing {label}: kind={:?} os={:?}",
                error.kind(),
                error.raw_os_error()
            );

            error
        };

        // Deletion.
        describe("remove_file", fs::remove_file(&rig.staging_path));
        // Rename away.
        describe("rename away", fs::rename(&rig.staging_path, &elsewhere));
        // Replacement of the staging name by another file.
        describe(
            "rename over staging",
            fs::rename(&primary, &rig.staging_path),
        );
        // Write access.
        describe(
            "open for write",
            fs::OpenOptions::new()
                .write(true)
                .open(&rig.staging_path)
                .map(|_| ()),
        );
        // Truncation.
        describe(
            "truncate",
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&rig.staging_path)
                .map(|_| ()),
        );
        // A hard link occupying the staging name.
        describe(
            "hard_link onto staging name",
            fs::hard_link(&primary, &rig.staging_path),
        );
        // Delete access (what a path-based delete-on-close needs).
        describe(
            "open for delete",
            fs::OpenOptions::new()
                .read(true)
                .access_mode(0x0001_0000)
                .open(&rig.staging_path)
                .map(|_| ()),
        );

        // Reading is allowed (share-read), and the content is untouched.
        let mut read_back = Vec::new();

        File::open(&rig.staging_path)
            .expect("share-read allows readers")
            .read_to_end(&mut read_back)
            .unwrap();

        assert_eq!(read_back, BYTES);
        assert!(rig.staging_path.exists());
        assert!(!elsewhere.exists());
        assert_eq!(
            fs::read(&primary).unwrap(),
            b"stands in for the primary vault"
        );
    }

    // ---- pinned parent directory ------------------------------------------------

    #[test]
    fn a_pinned_directory_cannot_be_renamed_or_deleted_by_ordinary_operations() {
        let rig = Rig::new("handle-ops-pin");
        let moved = rig.dir.path().join("pinned-renamed");
        let empty = rig.dir.path().join("empty-pinned");

        fs::create_dir(&empty).unwrap();

        let empty_pin = open_directory_pin(&empty).unwrap();

        let rename_error = fs::rename(&rig.pinned, &moved).expect_err("rename of a pinned dir");

        eprintln!(
            "OBSERVED pinned parent rename: kind={:?} os={:?}",
            rename_error.kind(),
            rename_error.raw_os_error()
        );

        let delete_error = fs::remove_dir(&empty).expect_err("delete of an empty pinned dir");

        eprintln!(
            "OBSERVED pinned parent delete: kind={:?} os={:?}",
            delete_error.kind(),
            delete_error.raw_os_error()
        );

        let rename_empty_error =
            fs::rename(&empty, rig.dir.path().join("empty-renamed")).expect_err("rename empty");

        eprintln!(
            "OBSERVED pinned empty parent rename: kind={:?} os={:?}",
            rename_empty_error.kind(),
            rename_empty_error.raw_os_error()
        );

        assert!(rig.pinned.is_dir());
        assert!(empty.is_dir());
        assert!(!moved.exists());

        drop(empty_pin);
    }

    #[test]
    fn the_grandparent_rename_result_is_reported_not_assumed() {
        // Reported, not asserted: whether NTFS lets an ancestor of a pinned
        // directory be renamed on this machine.
        let rig = Rig::new("handle-ops-grandparent");
        let parent = rig.dir.path().join("pinned");
        let grand = rig.dir.path().join("outer");
        let inner = grand.join("pinned");

        fs::create_dir(&grand).unwrap();
        fs::create_dir(&inner).unwrap();

        let inner_pin = open_directory_pin(&inner).unwrap();
        let renamed = grand.with_file_name("outer-renamed");

        match fs::rename(&grand, &renamed) {
            Ok(()) => {
                eprintln!("OBSERVED grandparent rename: SUCCEEDED while a descendant is pinned");

                // Put it back so the guard removes everything.
                fs::rename(&renamed, &grand).unwrap();
            }
            Err(error) => eprintln!(
                "OBSERVED grandparent rename: FAILED kind={:?} os={:?}",
                error.kind(),
                error.raw_os_error()
            ),
        }

        drop(inner_pin);

        assert!(parent.is_dir());
    }

    #[test]
    fn the_scratch_volume_and_pin_report_local_ntfs() {
        let rig = Rig::new("handle-ops-volume");

        assert!(volume_facts_of(&rig.pin).unwrap().is_local_ntfs());
        assert!(facts_of(&rig.staging).unwrap().is_local_ntfs());
    }
}
