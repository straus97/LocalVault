//! Physical file identity of an open handle (Stage 1U-4, slice B1g).
//!
//! Exists for one purpose: initial synchronization binding must not accept, as
//! its target, a second *name* for the local primary vault (for example an NTFS
//! hard link), because such an alias is byte-identical to the vault by
//! construction and would authenticate. Path strings cannot see that; the
//! volume and the file identifier of an **open handle** can.
//!
//! This is one of two modules in the crate that contain `unsafe` (the other is
//! `handle_ops`, which performs the handle-bound rename and delete of B2): three
//! small Windows FFI calls behind a safe, sealed interface. No raw handle,
//! pointer or `unsafe fn` leaves it.
//!
//! # What the facts are
//!
//! [`facts_of`] reads, from **one** open [`File`]:
//!
//! * the volume serial number and the 128-bit file identifier
//!   (`GetFileInformationByHandleEx(FileIdInfo)`). Microsoft documents the pair as
//!   identifying a file on a single computer: to decide whether two open handles
//!   are the same file, compare both. The 128-bit form is required for ReFS; the
//!   64-bit file index is deliberately not used;
//! * the number of hard links and the delete-pending flag
//!   (`GetFileInformationByHandleEx(FileStandardInfo)`);
//! * the name of the handle's filesystem
//!   (`GetVolumeInformationByHandleW`), matched exactly against `NTFS` and `ReFS`;
//! * whether the handle's volume is a local, non-virtual disk device
//!   (`NtQueryVolumeInformationFile(FileFsDeviceInformation)`).
//!
//! Any query that fails fails the whole lookup. There is no path-based or drive-
//! type fallback and no 64-bit-only fallback.
//!
//! # What a verdict means
//!
//! [`compare`] is fail-closed:
//!
//! * equal volume and file identifier is [`PhysicalVerdict::Same`];
//! * [`PhysicalVerdict::Distinct`] is returned only if **both** files are on a
//!   local NTFS or ReFS volume, both identifiers are non-degenerate, neither file
//!   is delete-pending, and the *target* has exactly one hard link;
//! * everything else is [`PhysicalVerdict::Uncertain`]. A lookup failure is never
//!   evidence that two files differ.
//!
//! # Limits (not claimed away)
//!
//! * The facts hold at the instants they were read. A hard link or redirection
//!   created later is not prevented, and there is no snapshot isolation.
//! * The filesystem name and the device characteristics are reported by the
//!   driver stack. A local filesystem driver that reports `NTFS` or `ReFS` on a
//!   local disk device cannot be told apart by these APIs, and its identifiers are
//!   not independently verified.
//! * ReFS is accepted on Microsoft's documentation; it has not been exercised on a
//!   ReFS volume.
//! * FAT/exFAT (identifiers derived from directory position), SMB and other
//!   network redirectors, virtual volumes and unidentified filesystems are
//!   refused, including legitimate ones.
//! * Identity is an initial-binding guard only. Every vault save replaces the
//!   primary file, so identifiers are never persisted.
//!
//! # Directory identity (Stage 1U-4, slice B3b-2p)
//!
//! [`directory_identity_of`] is a **separate** API for the identity of an open
//! *directory* handle. [`facts_of`] is unchanged: it still refuses every directory
//! handle (`Err(Lookup)`), so a directory can never become a candidate-file handle,
//! and nothing about the candidate-file rules (local NTFS/ReFS, hard links,
//! delete-pending, no-follow) is relaxed. The directory API
//!
//! * reads the same 128-bit `FileIdInfo` pair through the existing private
//!   `query_by_handle` helper (no new FFI, no new `unsafe`, no new `windows-sys`
//!   feature);
//! * requires, on the supplied handle, a directory by both the standard-info
//!   `Directory` flag and the handle's attributes, and refuses any reparse point
//!   (so a junction or symlink directory is refused when the handle was opened
//!   with `FILE_FLAG_OPEN_REPARSE_POINT`, as the caller must do; a handle that
//!   already followed a link is the link *target* and cannot be told apart);
//! * requires verifiable local NTFS (stricter than the binding policy: ReFS is
//!   refused), a non-delete-pending directory and a non-degenerate identifier;
//! * never opens, writes, renames or deletes anything: it only queries the handle
//!   it is given, which needs ordinary read access and full (default) sharing;
//!   write or `DELETE` access is neither required nor used.
//!
//! Directory identity comparison detects **observed** substitutions only. It does
//! not eliminate time-of-check/time-of-use races: a directory replaced and put back
//! between two observations (ABA) is not detected; file identifiers can be reused
//! after deletion; the volume serial and identifier are driver-reported and trusted;
//! and an equal identity says nothing about the directory's contents. It is not
//! cloud-provider authority, does not authenticate any sync state and authorizes no
//! file replacement.
//!
//! `Debug` output of every type here is redacted: volume serials and file
//! identifiers are never printed.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs::File;

/// Volume serial number and 128-bit file identifier. `Debug` is redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    volume: u64,
    id: [u8; 16],
}

impl std::fmt::Debug for FileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileIdentity(<redacted>)")
    }
}

impl FileIdentity {
    /// Whether the identifier is usable at all: a zero volume serial or an
    /// all-zero file identifier is what an uninitialised answer looks like.
    fn is_meaningful(&self) -> bool {
        self.volume != 0 && self.id != [0u8; 16]
    }
}

/// The filesystems whose identifiers this policy trusts, and everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileSystemKind {
    Ntfs,
    Refs,
    Other,
}

/// Facts read from ONE open handle. `Debug` is redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandleFacts {
    identity: FileIdentity,
    links: u32,
    delete_pending: bool,
    filesystem: FileSystemKind,
    local_device: bool,
}

impl std::fmt::Debug for HandleFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandleFacts(<redacted>)")
    }
}

impl HandleFacts {
    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Whether the identifier is usable at all: a zero volume serial or an
    /// all-zero file identifier is what an uninitialised answer looks like.
    fn identity_is_meaningful(&self) -> bool {
        self.identity.is_meaningful()
    }

    /// Exactly the `NTFS` filesystem on a local, non-remote, non-virtual disk
    /// device. Stricter than the binding policy ([`compare`] also accepts ReFS):
    /// this is the B2 publication allowlist.
    pub(crate) fn is_local_ntfs(&self) -> bool {
        self.filesystem == FileSystemKind::Ntfs && self.local_device
    }

    /// Exactly one hard link (one name).
    pub(crate) fn has_single_link(&self) -> bool {
        self.links == 1
    }

    pub(crate) fn is_delete_pending(&self) -> bool {
        self.delete_pending
    }

    /// Local NTFS/ReFS, meaningful identifier, not delete-pending.
    fn is_trustworthy(&self) -> bool {
        matches!(self.filesystem, FileSystemKind::Ntfs | FileSystemKind::Refs)
            && self.local_device
            && self.identity_is_meaningful()
            && !self.delete_pending
    }

    /// Test-only: the same facts, reported with another file's identity.
    #[cfg(test)]
    pub(crate) fn with_identity_of(mut self, other: &HandleFacts) -> Self {
        self.identity = other.identity;

        self
    }

    /// Test-only constructor, so the pure decision can be exercised with
    /// facts a real volume here cannot produce. Not available in production.
    #[cfg(test)]
    pub(crate) fn for_test(
        volume: u64,
        id: [u8; 16],
        links: u32,
        delete_pending: bool,
        filesystem: FileSystemKind,
        local_device: bool,
    ) -> Self {
        Self {
            identity: FileIdentity { volume, id },
            links,
            delete_pending,
            filesystem,
            local_device,
        }
    }
}

/// What a directory (or any) handle says about its volume, and nothing about
/// the object itself: no identifier is read, so a directory handle is fine.
/// Carries no identifier, so a derived `Debug` is not a leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VolumeFacts {
    filesystem: FileSystemKind,
    local_device: bool,
}

impl VolumeFacts {
    /// Exactly `NTFS` on a local, non-remote, non-virtual disk device.
    pub(crate) fn is_local_ntfs(&self) -> bool {
        self.filesystem == FileSystemKind::Ntfs && self.local_device
    }

    /// Test-only constructor, for volumes this machine cannot produce.
    #[cfg(test)]
    pub(crate) fn for_test(filesystem: FileSystemKind, local_device: bool) -> Self {
        Self {
            filesystem,
            local_device,
        }
    }
}

/// Why the facts could not be established. Categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityError {
    /// A query failed or returned something unusable.
    Lookup,
    /// This platform has no implementation (constructed only off Windows).
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Lookup => "the file identity could not be established",
            Self::Unsupported => "file identity is not supported on this platform",
        })
    }
}

impl std::error::Error for IdentityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalVerdict {
    /// The same volume and file identifier: one physical file.
    Same,
    /// Two different files, established under the conditions in the module
    /// documentation.
    Distinct,
    /// Nothing may be concluded.
    Uncertain,
}

/// All queries on the same handle. Any failure is `Err(Lookup)`; non-Windows is
/// `Err(Unsupported)`.
pub(crate) fn facts_of(file: &File) -> Result<HandleFacts, IdentityError> {
    #[cfg(windows)]
    {
        windows::facts_of(file)
    }

    #[cfg(not(windows))]
    {
        let _ = file;

        Err(IdentityError::Unsupported)
    }
}

/// The volume facts of one open handle, which may be a directory handle. Any
/// failed query is `Err(Lookup)`; non-Windows is `Err(Unsupported)`.
pub(crate) fn volume_facts_of(file: &File) -> Result<VolumeFacts, IdentityError> {
    #[cfg(windows)]
    {
        windows::volume_facts_of(file)
    }

    #[cfg(not(windows))]
    {
        let _ = file;

        Err(IdentityError::Unsupported)
    }
}

/// The identity of one open **directory** handle, or why none can be given.
///
/// Separate from [`facts_of`], which keeps refusing directories. `directory` must
/// have been opened by the caller with `FILE_FLAG_BACKUP_SEMANTICS` and
/// `FILE_FLAG_OPEN_REPARSE_POINT` (so a link is judged as the link), read-only and
/// with the default full sharing; this function only queries it. Every refusal is
/// `Err(Lookup)`: the handle is not a plain directory (a regular file, a reparse
/// point, anything uncertain), is delete-pending, is not on a verifiable local NTFS
/// volume, a query failed, or the identifier is degenerate. A refusal never
/// produces a value. Non-Windows is `Err(Unsupported)`.
///
/// Unused until the read-only exchange classifier (B3b-2a) calls it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn directory_identity_of(directory: &File) -> Result<FileIdentity, IdentityError> {
    #[cfg(windows)]
    {
        windows::directory_observation_of(directory).and_then(judge_directory)
    }

    #[cfg(not(windows))]
    {
        let _ = directory;

        Err(IdentityError::Unsupported)
    }
}

/// What the directory decision looks at, gathered from one handle.
#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
struct DirectoryObservation {
    /// A directory by both the handle's standard information and its attributes.
    is_directory: bool,
    /// Carries a reparse point (junction, symlink, mount point, placeholder, ...).
    is_reparse_point: bool,
    delete_pending: bool,
    volume: VolumeFacts,
    identity: FileIdentity,
}

/// The pure, fail-closed directory decision: a value only for a plain,
/// live directory on a local NTFS volume with a meaningful identifier.
#[cfg_attr(not(test), allow(dead_code))]
fn judge_directory(observed: DirectoryObservation) -> Result<FileIdentity, IdentityError> {
    if !observed.is_directory
        || observed.is_reparse_point
        || observed.delete_pending
        || !observed.volume.is_local_ntfs()
        || !observed.identity.is_meaningful()
    {
        return Err(IdentityError::Lookup);
    }

    Ok(observed.identity)
}

/// The pure, fail-closed decision. In order:
///
/// 1. equal identity is `Same`, whatever else is known;
/// 2. `Distinct` only if both files are trustworthy (local NTFS/ReFS,
///    meaningful identifier, not delete-pending) and the target has exactly one
///    hard link;
/// 3. otherwise `Uncertain`.
///
/// A primary with several names is allowed: only the target must have exactly
/// one.
pub(crate) fn compare(primary: &HandleFacts, target: &HandleFacts) -> PhysicalVerdict {
    if primary.identity == target.identity {
        return PhysicalVerdict::Same;
    }

    if primary.is_trustworthy() && target.is_trustworthy() && target.links == 1 {
        PhysicalVerdict::Distinct
    } else {
        PhysicalVerdict::Uncertain
    }
}

#[cfg(windows)]
mod windows {
    //! The FFI safety boundary. Three `unsafe` blocks, one per foreign function.

    use std::{
        ffi::c_void,
        fs::File,
        mem::size_of,
        os::windows::{fs::MetadataExt, io::AsRawHandle},
        ptr,
    };

    use windows_sys::{
        Wdk::{
            Storage::FileSystem::{FileFsDeviceInformation, NtQueryVolumeInformationFile},
            System::SystemServices::{
                FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
                FILE_VIRTUAL_VOLUME,
            },
        },
        Win32::{
            Foundation::MAX_PATH,
            Storage::FileSystem::{
                FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
                GetVolumeInformationByHandleW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_DEVICE_DISK, FILE_ID_INFO,
                FILE_INFO_BY_HANDLE_CLASS, FILE_STANDARD_INFO,
            },
            System::IO::IO_STATUS_BLOCK,
        },
    };

    use super::{
        DirectoryObservation, FileIdentity, FileSystemKind, HandleFacts, IdentityError, VolumeFacts,
    };

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::FILE_ID_INFO {}
        impl Sealed for super::FILE_STANDARD_INFO {}
    }

    /// An output structure paired with the information class that fills it, so a
    /// buffer can never be passed with a class of a different layout. Sealed:
    /// only the two structures below implement it.
    trait ByHandleClass: Copy + Default + sealed::Sealed {
        const CLASS: FILE_INFO_BY_HANDLE_CLASS;
    }

    impl ByHandleClass for FILE_ID_INFO {
        const CLASS: FILE_INFO_BY_HANDLE_CLASS = FileIdInfo;
    }

    impl ByHandleClass for FILE_STANDARD_INFO {
        const CLASS: FILE_INFO_BY_HANDLE_CLASS = FileStandardInfo;
    }

    pub(super) fn facts_of(file: &File) -> Result<HandleFacts, IdentityError> {
        let id = query_by_handle::<FILE_ID_INFO>(file)?;
        let standard = query_by_handle::<FILE_STANDARD_INFO>(file)?;

        // A directory is never a candidate file.
        if standard.Directory {
            return Err(IdentityError::Lookup);
        }

        Ok(HandleFacts {
            identity: FileIdentity {
                volume: id.VolumeSerialNumber,
                id: id.FileId.Identifier,
            },
            links: standard.NumberOfLinks,
            delete_pending: standard.DeletePending,
            filesystem: filesystem_kind(file)?,
            local_device: local_device(file)?,
        })
    }

    pub(super) fn volume_facts_of(file: &File) -> Result<VolumeFacts, IdentityError> {
        Ok(VolumeFacts {
            filesystem: filesystem_kind(file)?,
            local_device: local_device(file)?,
        })
    }

    /// Everything the directory decision needs, read from ONE handle with the
    /// same helpers as [`facts_of`]; any failed query fails the whole lookup.
    pub(super) fn directory_observation_of(
        file: &File,
    ) -> Result<DirectoryObservation, IdentityError> {
        let attributes = file
            .metadata()
            .map_err(|_| IdentityError::Lookup)?
            .file_attributes();
        let id = query_by_handle::<FILE_ID_INFO>(file)?;
        let standard = query_by_handle::<FILE_STANDARD_INFO>(file)?;

        Ok(DirectoryObservation {
            is_directory: standard.Directory && attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            is_reparse_point: attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            delete_pending: standard.DeletePending,
            volume: volume_facts_of(file)?,
            identity: FileIdentity {
                volume: id.VolumeSerialNumber,
                id: id.FileId.Identifier,
            },
        })
    }

    fn query_by_handle<T: ByHandleClass>(file: &File) -> Result<T, IdentityError> {
        let mut out = T::default();
        let size = u32::try_from(size_of::<T>()).map_err(|_| IdentityError::Lookup)?;

        // SAFETY: the handle is borrowed from a live `&File` and stays valid for
        // the whole call. `out` is a properly aligned, default-initialised
        // `#[repr(C)]` local, and exactly `size_of::<T>()` bytes are offered; the
        // class constant is the one defined for this very type. The call writes
        // only into `out` and retains neither pointer.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                T::CLASS,
                ptr::from_mut(&mut out).cast::<c_void>(),
                size,
            )
        };

        if ok != 0 {
            Ok(out)
        } else {
            Err(IdentityError::Lookup)
        }
    }

    fn filesystem_kind(file: &File) -> Result<FileSystemKind, IdentityError> {
        let mut name = [0u16; MAX_PATH as usize + 1];
        let capacity = u32::try_from(name.len()).map_err(|_| IdentityError::Lookup)?;

        // SAFETY: the handle is borrowed from a live `&File` for the call. The
        // filesystem-name buffer is a local of exactly `capacity` UTF-16 units; every
        // other output pointer is null, which this API permits for the values the
        // caller does not want. Nothing is retained after the call.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                name.as_mut_ptr(),
                capacity,
            )
        };

        if ok == 0 {
            return Err(IdentityError::Lookup);
        }

        // A name with no terminator is not trusted.
        let length = name
            .iter()
            .position(|&unit| unit == 0)
            .ok_or(IdentityError::Lookup)?;
        let name = &name[..length];

        let is = |expected: &str| name.iter().copied().eq(expected.encode_utf16());

        Ok(if is("NTFS") {
            FileSystemKind::Ntfs
        } else if is("ReFS") {
            FileSystemKind::Refs
        } else {
            FileSystemKind::Other
        })
    }

    fn local_device(file: &File) -> Result<bool, IdentityError> {
        let mut status = IO_STATUS_BLOCK::default();
        let mut info = FILE_FS_DEVICE_INFORMATION::default();
        let size = u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
            .map_err(|_| IdentityError::Lookup)?;

        // SAFETY: the handle is borrowed from a live `&File` for the call (opened
        // synchronously by `std`, so the call completes before it returns). The
        // status block and the output structure are properly aligned, default-
        // initialised `#[repr(C)]` locals, and exactly the structure's size is
        // offered with the matching `FileFsDeviceInformation` class. Nothing is
        // retained after the call.
        let status_code = unsafe {
            NtQueryVolumeInformationFile(
                file.as_raw_handle(),
                &mut status,
                ptr::from_mut(&mut info).cast::<c_void>(),
                size,
                FileFsDeviceInformation,
            )
        };

        // STATUS_SUCCESS only: any warning, informational or pending status leaves
        // the structure unproven.
        if status_code != 0 {
            return Err(IdentityError::Lookup);
        }

        let remote_or_virtual = FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB | FILE_VIRTUAL_VOLUME;

        Ok(info.DeviceType == FILE_DEVICE_DISK && info.Characteristics & remote_or_virtual == 0)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write, path::Path};

    use super::*;

    const LEAK_MARK: &str = "LEAKMARK-IDENTITY";

    fn scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("file-identity-b1g-tests");

        fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap()
    }

    fn facts(volume: u64, id: u8, links: u32) -> HandleFacts {
        HandleFacts::for_test(volume, [id; 16], links, false, FileSystemKind::Ntfs, true)
    }

    // ---- 6b. the pure decision ------------------------------------------------

    #[test]
    fn equal_identity_is_the_same_file_whatever_else_is_known() {
        let primary = facts(7, 1, 2);

        assert_eq!(compare(&primary, &facts(7, 1, 2)), PhysicalVerdict::Same);

        // Even where nothing else about the files is trustworthy.
        let odd = HandleFacts::for_test(7, [1; 16], 9, true, FileSystemKind::Other, false);

        assert_eq!(compare(&primary, &odd), PhysicalVerdict::Same);
        assert_eq!(compare(&odd, &primary), PhysicalVerdict::Same);

        // A degenerate identifier that is equal on both sides is still one file.
        let zero = HandleFacts::for_test(0, [0; 16], 1, false, FileSystemKind::Ntfs, true);

        assert_eq!(compare(&zero, &zero), PhysicalVerdict::Same);
    }

    #[test]
    fn two_trustworthy_local_files_with_different_identities_are_distinct() {
        assert_eq!(
            compare(&facts(7, 1, 1), &facts(7, 2, 1)),
            PhysicalVerdict::Distinct
        );
        // Another volume with the same file identifier is another file.
        assert_eq!(
            compare(&facts(7, 1, 1), &facts(8, 1, 1)),
            PhysicalVerdict::Distinct
        );
        // ReFS is accepted on a local disk.
        let refs = |id| HandleFacts::for_test(9, [id; 16], 1, false, FileSystemKind::Refs, true);

        assert_eq!(compare(&refs(1), &refs(2)), PhysicalVerdict::Distinct);
        assert_eq!(
            compare(&facts(7, 1, 1), &refs(2)),
            PhysicalVerdict::Distinct
        );
        // The primary may have several names; only the target must have one.
        assert_eq!(
            compare(&facts(7, 1, 3), &facts(7, 2, 1)),
            PhysicalVerdict::Distinct
        );
    }

    #[test]
    fn every_uncertain_fact_refuses_to_call_two_files_distinct() {
        let good = facts(7, 1, 1);
        let with = |change: fn(&mut HandleFacts)| {
            let mut changed = facts(7, 2, 1);

            change(&mut changed);

            changed
        };

        type Change = fn(&mut HandleFacts);

        let bad: Vec<(&str, Change)> = vec![
            ("other filesystem", |f| f.filesystem = FileSystemKind::Other),
            ("not a local device", |f| f.local_device = false),
            ("zero volume", |f| f.identity.volume = 0),
            ("zero file id", |f| f.identity.id = [0; 16]),
            ("delete pending", |f| f.delete_pending = true),
            ("no links", |f| f.links = 0),
            ("several links", |f| f.links = 2),
        ];

        for (name, change) in &bad {
            // Bad on the target.
            assert_eq!(
                compare(&good, &with(*change)),
                PhysicalVerdict::Uncertain,
                "target: {name}"
            );
        }

        // Bad on the primary. Its link count is not a condition (only the
        // target must have exactly one name).
        for (name, change) in &bad {
            if name.contains("links") {
                continue;
            }

            let mut primary = facts(7, 1, 1);

            change(&mut primary);

            assert_eq!(
                compare(&primary, &facts(7, 2, 1)),
                PhysicalVerdict::Uncertain,
                "primary: {name}"
            );
        }
    }

    // ---- B2a. volume facts and the NTFS-only publication predicate --------------

    #[test]
    fn publication_accepts_only_local_ntfs() {
        let handle =
            |filesystem, local| HandleFacts::for_test(7, [1; 16], 1, false, filesystem, local);

        assert!(handle(FileSystemKind::Ntfs, true).is_local_ntfs());
        // Everything the binding policy may accept but publication must not.
        assert!(!handle(FileSystemKind::Refs, true).is_local_ntfs());
        assert!(!handle(FileSystemKind::Other, true).is_local_ntfs());
        assert!(!handle(FileSystemKind::Ntfs, false).is_local_ntfs());
        assert!(!handle(FileSystemKind::Refs, false).is_local_ntfs());
        assert!(!handle(FileSystemKind::Other, false).is_local_ntfs());

        let volume = |filesystem, local| VolumeFacts::for_test(filesystem, local);

        assert!(volume(FileSystemKind::Ntfs, true).is_local_ntfs());
        assert!(!volume(FileSystemKind::Refs, true).is_local_ntfs());
        assert!(!volume(FileSystemKind::Other, true).is_local_ntfs());
        assert!(!volume(FileSystemKind::Ntfs, false).is_local_ntfs());

        // The binding policy (B1g) is unchanged: ReFS is still distinct-capable.
        assert_eq!(
            compare(
                &handle(FileSystemKind::Refs, true),
                &HandleFacts::for_test(7, [2; 16], 1, false, FileSystemKind::Refs, true)
            ),
            PhysicalVerdict::Distinct
        );
    }

    #[test]
    fn single_link_and_delete_pending_accessors_report_the_facts() {
        let facts = |links, pending| {
            HandleFacts::for_test(7, [1; 16], links, pending, FileSystemKind::Ntfs, true)
        };

        assert!(facts(1, false).has_single_link());
        assert!(!facts(2, false).has_single_link());
        assert!(!facts(0, false).has_single_link());
        assert!(facts(1, true).is_delete_pending());
        assert!(!facts(1, false).is_delete_pending());
    }

    // ---- 12. redaction --------------------------------------------------------

    #[test]
    fn nothing_here_prints_identifiers_or_paths() {
        let facts = HandleFacts::for_test(
            0xDEAD_BEEF_1234_5678,
            [0xAB; 16],
            1,
            false,
            FileSystemKind::Ntfs,
            true,
        );

        let shown = [
            format!("{facts:?}"),
            format!("{:?}", facts.identity()),
            format!("{:#?}", facts),
            format!("{:?}", IdentityError::Lookup),
            IdentityError::Lookup.to_string(),
            format!("{:?}", IdentityError::Unsupported),
            IdentityError::Unsupported.to_string(),
            format!("{:?}", PhysicalVerdict::Same),
        ];

        for output in &shown {
            for needle in [
                "DEADBEEF",
                "deadbeef",
                "3735928559",
                "1234",
                "5678",
                "abab",
                "ABAB",
                "171",
                LEAK_MARK,
                ".qa-local",
            ] {
                assert!(!output.contains(needle), "leaks {needle:?}: {output}");
            }
        }
    }

    // ---- 6c. real files on the developer machine's NTFS ----------------------

    #[cfg(windows)]
    mod real_files {
        use super::*;

        fn open(path: &Path) -> File {
            File::open(path).unwrap()
        }

        fn put(path: &Path, bytes: &[u8]) {
            let mut file = fs::File::create(path).unwrap();

            file.write_all(bytes).unwrap();
        }

        #[test]
        fn a_plain_file_has_trustworthy_facts() {
            let dir = scratch("plain");
            let path = dir.path().join(format!("{LEAK_MARK}.bin"));

            put(&path, b"content");

            let facts = facts_of(&open(&path)).expect("facts");

            assert_eq!(facts.filesystem, FileSystemKind::Ntfs);
            assert!(facts.local_device);
            assert_eq!(facts.links, 1);
            assert!(!facts.delete_pending);
            assert!(facts.identity_is_meaningful());
            assert!(facts.is_trustworthy());
        }

        #[test]
        fn facts_from_two_handles_to_one_file_agree() {
            let dir = scratch("same-file");
            let path = dir.path().join("a.bin");

            put(&path, b"content");

            let first = facts_of(&open(&path)).unwrap();
            let second = facts_of(&open(&path)).unwrap();

            assert_eq!(first, second);
            assert_eq!(compare(&first, &second), PhysicalVerdict::Same);
        }

        #[test]
        fn a_hard_link_has_the_same_identity_and_two_links() {
            let dir = scratch("hard-link");
            let original = dir.path().join("original.bin");
            let link = dir.path().join("link.bin");

            put(&original, b"content");
            fs::hard_link(&original, &link).unwrap();

            let a = facts_of(&open(&original)).unwrap();
            let b = facts_of(&open(&link)).unwrap();

            assert_eq!(a.identity(), b.identity());
            assert_eq!(a.links, 2);
            assert_eq!(b.links, 2);
            assert_eq!(compare(&a, &b), PhysicalVerdict::Same);
        }

        #[test]
        fn a_copy_is_a_distinct_file_with_one_link() {
            let dir = scratch("copy");
            let original = dir.path().join("original.bin");
            let copy = dir.path().join("copy.bin");

            put(&original, b"content");
            fs::copy(&original, &copy).unwrap();

            let a = facts_of(&open(&original)).unwrap();
            let b = facts_of(&open(&copy)).unwrap();

            assert_ne!(a.identity(), b.identity());
            assert_eq!(b.links, 1);
            assert_eq!(compare(&a, &b), PhysicalVerdict::Distinct);

            // A hard link to the *target* makes it ineligible (two names).
            let alias = dir.path().join("alias.bin");

            fs::hard_link(&copy, &alias).unwrap();

            let b_again = facts_of(&open(&copy)).unwrap();

            assert_eq!(b_again.links, 2);
            assert_eq!(compare(&a, &b_again), PhysicalVerdict::Uncertain);
        }

        #[test]
        fn volume_facts_read_from_a_directory_handle_and_from_a_file() {
            use std::os::windows::fs::OpenOptionsExt;

            let dir = scratch("volume-facts");
            let path = dir.path().join("a.bin");

            put(&path, b"content");

            let directory = fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x0200_0000)
                .open(dir.path())
                .unwrap();

            // A directory handle has volume facts although it has no file identity.
            let volume = volume_facts_of(&directory).expect("volume facts of a directory");

            assert!(volume.is_local_ntfs());
            assert_eq!(facts_of(&directory), Err(IdentityError::Lookup));

            // A file on the same volume reports the same volume facts.
            let from_file = volume_facts_of(&open(&path)).unwrap();

            assert_eq!(from_file, volume);
            assert!(facts_of(&open(&path)).unwrap().is_local_ntfs());
        }

        #[test]
        fn a_directory_handle_is_not_a_file_identity() {
            let dir = scratch("directory");

            // `File::open` on a directory is refused by `std`; open it with the
            // backup-semantics flag the way a directory handle is obtained.
            use std::os::windows::fs::OpenOptionsExt;

            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

            let handle = fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(dir.path())
                .unwrap();

            assert_eq!(facts_of(&handle), Err(IdentityError::Lookup));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_are_unsupported() {
        let dir = scratch("unsupported");
        let path = dir.path().join("a.bin");

        fs::write(&path, b"content").unwrap();

        assert_eq!(
            facts_of(&File::open(&path).unwrap()),
            Err(IdentityError::Unsupported)
        );
    }
}

/// Directory identity (B3b-2p), tested on the developer machine's real local NTFS
/// where stated; the pure decision is tested with injected observations, which
/// prove decision logic only. Scratch lives under
/// `.qa-local/sync-update-b3-tests/`, never `%TEMP%`.
#[cfg(all(test, windows))]
mod directory_identity {
    use std::{
        fs::{self, File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
        path::Path,
    };

    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    use super::*;
    use crate::vault::handle_ops::{
        delete_by_handle,
        test_support::{assert_local_ntfs, make_junction},
    };

    const LEAK_MARK: &str = "LEAKMARK-DIRIDENT";

    fn scratch(name: &str) -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("sync-update-b3-tests");

        fs::create_dir_all(&base).unwrap();

        let dir = tempfile::Builder::new()
            .prefix(&format!("{name}-"))
            .tempdir_in(&base)
            .unwrap();

        // Fails loudly (never skips) off a local NTFS volume.
        assert_local_ntfs(dir.path());
        assert!(!dir.path().starts_with(std::env::temp_dir()));

        dir
    }

    /// The way the caller must open a directory: read-only, default (full)
    /// sharing, never following a reparse point. No access or share mode is set.
    fn open_directory(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap()
    }

    fn identity(path: &Path) -> FileIdentity {
        directory_identity_of(&open_directory(path)).expect("a plain local NTFS directory")
    }

    // ---- A-B. equality and difference ------------------------------------------

    #[test]
    fn two_independent_handles_to_one_directory_agree() {
        let dir = scratch("dirid-same");
        let first = open_directory(dir.path());
        let second = open_directory(dir.path());

        let a = directory_identity_of(&first).unwrap();
        let b = directory_identity_of(&second).unwrap();

        assert_eq!(a, b);
        // Stable over time on the same handle.
        assert_eq!(directory_identity_of(&first).unwrap(), a);
    }

    #[test]
    fn different_directories_on_one_volume_have_different_identities() {
        let dir = scratch("dirid-different");
        let one = dir.path().join("one");
        let two = dir.path().join("two");
        let child = one.join("child");

        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        fs::create_dir(&child).unwrap();

        let identities = [
            identity(dir.path()),
            identity(&one),
            identity(&two),
            identity(&child),
        ];

        for (index, first) in identities.iter().enumerate() {
            for second in &identities[index + 1..] {
                assert_ne!(first, second);
            }
        }
    }

    // ---- C-D. the file API is unchanged, the directory API refuses files ---------

    #[test]
    fn facts_of_still_refuses_a_directory_and_the_directory_api_accepts_it() {
        let dir = scratch("dirid-facts-of");
        let handle = open_directory(dir.path());

        // The existing contract, unchanged.
        assert_eq!(facts_of(&handle), Err(IdentityError::Lookup));

        // The separate directory API on the very same handle.
        assert!(directory_identity_of(&handle).is_ok());
        assert!(volume_facts_of(&handle).unwrap().is_local_ntfs());
    }

    #[test]
    fn a_regular_file_is_refused_and_still_has_file_facts() {
        let dir = scratch("dirid-file");
        let path = dir.path().join("a.bin");

        fs::write(&path, b"content").unwrap();

        let plain = File::open(&path).unwrap();
        let flagged = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .unwrap();

        assert_eq!(directory_identity_of(&plain), Err(IdentityError::Lookup));
        assert_eq!(directory_identity_of(&flagged), Err(IdentityError::Lookup));

        // The candidate-file API still accepts the same handle.
        assert!(facts_of(&plain).unwrap().is_trustworthy());
    }

    #[test]
    fn a_device_handle_is_refused() {
        // REAL handle that is not a plain directory on a local NTFS volume.
        let Ok(device) = File::open(r"\\.\NUL") else {
            eprintln!("SKIPPED device handle case: \\\\.\\NUL could not be opened");

            return;
        };

        assert_eq!(directory_identity_of(&device), Err(IdentityError::Lookup));
    }

    // ---- E-F. a held handle follows the object, not the name ---------------------

    #[test]
    fn a_renamed_directory_keeps_its_identity_and_a_new_one_at_the_old_name_differs() {
        let dir = scratch("dirid-rename");
        let old = dir.path().join("watched");
        let moved = dir.path().join("moved-away");

        fs::create_dir(&old).unwrap();

        let held = open_directory(&old);
        let before = directory_identity_of(&held).unwrap();

        // The held handle was opened read-only with full sharing, so it does not
        // prevent the rename.
        fs::rename(&old, &moved).expect("a read-only, fully shared directory handle");

        assert_eq!(directory_identity_of(&held).unwrap(), before);
        assert_eq!(identity(&moved), before);
        assert!(fs::symlink_metadata(&old).is_err());

        // A new directory at the old pathname is another object.
        fs::create_dir(&old).unwrap();

        let replacement = identity(&old);

        assert_ne!(replacement, before);
        assert_eq!(directory_identity_of(&held).unwrap(), before);
    }

    // ---- G. reparse directories ---------------------------------------------------

    #[test]
    fn a_junction_directory_is_refused_when_opened_without_following() {
        let dir = scratch("dirid-junction");
        let target = dir.path().join("target");
        let link = dir.path().join("link");

        fs::create_dir(&target).unwrap();
        make_junction(&link, &target);

        assert_eq!(
            directory_identity_of(&open_directory(&link)),
            Err(IdentityError::Lookup)
        );

        // Documented limit, observed: a handle that already followed the junction
        // *is* the target directory and cannot be told apart. The caller must open
        // with FILE_FLAG_OPEN_REPARSE_POINT.
        let followed = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&link)
            .unwrap();

        assert_eq!(directory_identity_of(&followed).unwrap(), identity(&target));
    }

    #[test]
    fn a_symlink_directory_is_refused_where_one_can_be_created() {
        let dir = scratch("dirid-symlink");
        let target = dir.path().join("target");
        let link = dir.path().join("link");

        fs::create_dir(&target).unwrap();

        if std::os::windows::fs::symlink_dir(&target, &link).is_err() {
            // Needs a privilege this account may lack. Not run; not counted.
            eprintln!("SKIPPED symlink directory case: the link could not be created");

            return;
        }

        assert_eq!(
            directory_identity_of(&open_directory(&link)),
            Err(IdentityError::Lookup)
        );
    }

    // ---- H. unavailable, degenerate or uncertain observations never yield a value --

    fn good_observation() -> DirectoryObservation {
        DirectoryObservation {
            is_directory: true,
            is_reparse_point: false,
            delete_pending: false,
            volume: VolumeFacts::for_test(FileSystemKind::Ntfs, true),
            identity: FileIdentity {
                volume: 7,
                id: [1; 16],
            },
        }
    }

    #[test]
    fn injected_observations_that_are_not_a_plain_live_local_ntfs_directory_are_refused() {
        // INJECTED: decision logic only.
        assert_eq!(
            judge_directory(good_observation()),
            Ok(good_observation().identity)
        );

        type Change = fn(&mut DirectoryObservation);

        let bad: [(&str, Change); 9] = [
            ("not a directory", |o| o.is_directory = false),
            ("reparse point", |o| o.is_reparse_point = true),
            ("delete pending", |o| o.delete_pending = true),
            ("ReFS", |o| {
                o.volume = VolumeFacts::for_test(FileSystemKind::Refs, true)
            }),
            ("other filesystem", |o| {
                o.volume = VolumeFacts::for_test(FileSystemKind::Other, true)
            }),
            ("not a local device", |o| {
                o.volume = VolumeFacts::for_test(FileSystemKind::Ntfs, false)
            }),
            ("zero volume serial", |o| o.identity.volume = 0),
            ("zero file id", |o| o.identity.id = [0; 16]),
            ("nothing at all", |o| {
                o.is_directory = false;
                o.volume = VolumeFacts::for_test(FileSystemKind::Other, false);
                o.identity = FileIdentity {
                    volume: 0,
                    id: [0; 16],
                };
            }),
        ];

        for (name, change) in bad {
            let mut observed = good_observation();

            change(&mut observed);

            assert_eq!(
                judge_directory(observed),
                Err(IdentityError::Lookup),
                "{name}"
            );
        }
    }

    #[test]
    fn a_delete_pending_directory_is_observed_and_refused() {
        // REAL NTFS. A second handle with DELETE access marks the directory for
        // deletion by handle; the first, read-only handle stays open.
        let dir = scratch("dirid-delete-pending");
        let doomed = dir.path().join("doomed");

        fs::create_dir(&doomed).unwrap();

        let observer = open_directory(&doomed);
        let deleter = OpenOptions::new()
            .read(true)
            .access_mode(DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&doomed)
            .unwrap();

        assert!(directory_identity_of(&observer).is_ok());

        delete_by_handle(&deleter).expect("the directory can be marked for deletion");

        let observed = windows::directory_observation_of(&observer).unwrap();

        eprintln!(
            "OBSERVED delete-pending directory: delete_pending={}",
            observed.delete_pending
        );

        assert!(observed.delete_pending);
        assert_eq!(directory_identity_of(&observer), Err(IdentityError::Lookup));
    }

    // ---- I. read-only access, full sharing -------------------------------------------

    #[test]
    fn the_handle_is_read_only_fully_shared_and_never_blocks_others() {
        let dir = scratch("dirid-sharing");
        let watched = dir.path().join("watched");

        fs::create_dir(&watched).unwrap();

        let held = open_directory(&watched);
        let before = directory_identity_of(&held).unwrap();

        // With the handle held, others can open the directory again, create files
        // and directories inside it, and remove them: nothing is pinned.
        let second = open_directory(&watched);

        fs::write(watched.join("inside.bin"), b"x").unwrap();
        fs::create_dir(watched.join("inside-dir")).unwrap();
        fs::remove_file(watched.join("inside.bin")).unwrap();
        fs::remove_dir(watched.join("inside-dir")).unwrap();

        assert_eq!(directory_identity_of(&held).unwrap(), before);
        assert_eq!(directory_identity_of(&second).unwrap(), before);
    }

    /// The production half of this file: everything before the unit tests, without
    /// comment lines.
    fn production_code() -> String {
        include_str!("file_identity.rs")
            .split("mod tests {")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_production_code_opens_nothing_and_adds_no_unsafe() {
        let code = production_code();

        assert!(code.contains("pub(crate) fn directory_identity_of("));

        // Still exactly the three original foreign calls.
        assert_eq!(code.matches("unsafe {").count(), 3);

        // The identity code never opens, writes, renames or deletes, and never
        // asks for write or DELETE access or a restrictive share mode.
        for forbidden in [
            "OpenOptions",
            "share_mode",
            "access_mode",
            "GENERIC_WRITE",
            "DELETE",
            "fs::rename",
            "fs::write",
            "remove_file",
            "remove_dir",
            "create_dir",
            "hard_link",
            "set_len",
            "temp_dir",
        ] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
    }

    // ---- J. redaction -------------------------------------------------------------------

    #[test]
    fn nothing_printed_reveals_a_directory_identity_or_path() {
        let dir = scratch("dirid-redaction");
        let named = dir.path().join(LEAK_MARK);

        fs::create_dir(&named).unwrap();

        let real = identity(&named);
        let injected = judge_directory(DirectoryObservation {
            identity: FileIdentity {
                volume: 0xDEAD_BEEF_1234_5678,
                id: [0xAB; 16],
            },
            ..good_observation()
        })
        .unwrap();

        let shown = [
            format!("{real:?}"),
            format!("{real:#?}"),
            format!("{injected:?}"),
            format!("{:#?}", Ok::<_, IdentityError>(injected)),
            format!("{:?}", Err::<FileIdentity, _>(IdentityError::Lookup)),
        ];

        for output in &shown {
            for needle in [
                "DEADBEEF",
                "deadbeef",
                "3735928559",
                "1234",
                "5678",
                "abab",
                "ABAB",
                "171",
                LEAK_MARK,
                ".qa-local",
            ] {
                assert!(!output.contains(needle), "leaks {needle:?}: {output}");
            }
        }

        assert_eq!(shown[0], "FileIdentity(<redacted>)");
        assert_eq!(shown[2], "FileIdentity(<redacted>)");
    }
}
