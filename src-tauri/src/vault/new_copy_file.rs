//! Safe-code publication of a new encrypted copy (Stage 1U-4, slice B2a).
//!
//! Creates ONE new file, at a target that does not exist, holding exactly the
//! caller's bytes, and publishes it under its final name **without ever replacing
//! anything**. All `unsafe` lives in `handle_ops`; this module is safe code only.
//! Nothing here touches the sync state, the vault, its backup or its lock, and
//! nothing is retried.
//!
//! # Sequence
//!
//! 1. **Pin the destination directory.** The target's parent is opened without
//!    following a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`), with read and
//!    traverse access and a share mode that denies delete, and the *handle* is
//!    judged: a plain, non-reparse directory on a local, non-remote, non-virtual
//!    `NTFS` volume. Every ancestor is then confirmed to be a plain directory
//!    *after* the pin, so a redirection installed before it is caught. No
//!    directory is ever created.
//! 2. **Create the staging file exclusively** (`create_new`, a fresh random name
//!    in that directory) with read, write and delete access and a share mode that
//!    allows readers only. While the handle is open no other process can write,
//!    delete or rename the staging file or replace its directory entry.
//! 3. **Write** exactly the caller's bytes through that handle; flush; `sync_all`.
//! 4. **Check identity on the handle**: local NTFS, one link, not delete-pending,
//!    a physical file distinct from the vault's own primary.
//! 5. **Narrow**: the caller's evidence check, then the target must still be
//!    absent.
//! 6. **Rename the open staging handle into the pinned directory**, no replace
//!    (`handle_ops`). The destination is the directory *object* behind the pin.
//! 7. **Verify while still holding both handles**: an independent read of the
//!    target path returns the same physical file (same identity, one link, local
//!    NTFS, distinct from the primary) with exactly the source bytes, and the
//!    caller's own check (the session's cryptographic authentication) passes.
//!
//! # Cleanup and ambiguity
//!
//! Cleanup is **only** a handle-bound delete of the staging file this call
//! created, and **only** while the object certainly still carries its staging
//! name: a failure before the rename call, or a rename NTFS definitely refused.
//! After a successful or unknown rename nothing is ever deleted, because that
//! object may be the published target. If the delete cannot be confirmed the file
//! is left in place and reported (`staging_remains`). There is no path-based
//! delete, rename, copy or link anywhere.
//!
//! # Limits (not claimed away)
//!
//! * The staging file is created by path in the pinned directory's path. A
//!   redirection installed in the instant between the post-pin ancestor check and
//!   that creation could place it elsewhere on the same volume; the handle-bound
//!   rename still moves it into the pinned directory, and another volume is
//!   refused (`STATUS_NOT_SAME_DEVICE`). Closing this fully needs a create
//!   relative to the pin, which needs further `windows-sys` features and is
//!   deliberately not done here.
//! * Whether an ancestor of the pinned directory can be renamed while the pin is
//!   held is measured by the tests, not assumed. If it happens the file lands in
//!   the right directory object at a different path; the path read then finds no
//!   file and the result is [`PublishOutcome::CreatedUnverified`], never success.
//! * Sharing modes bind ordinary processes only: administrators, backup-privileged
//!   processes, kernel components and filesystem filters can bypass them, and the
//!   driver-reported filesystem and device facts are trusted.
//! * After the handles close, the published file is ordinary user data.
//! * The directory entry is **not** flushed: the published name is not claimed to
//!   survive a power loss. A crash can leave a hidden, encrypted staging file.
//!
//! Outcomes carry fixed categories only: no path, identifier, fingerprint or
//! content, in `Debug` or otherwise.
#![cfg_attr(not(windows), allow(dead_code))]

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE,
    },
};

use super::{
    file_identity::{compare, facts_of, volume_facts_of, HandleFacts, PhysicalVerdict},
    handle_ops::{self, DefiniteRefusal, RenameStatus},
    sync_file_adapter::{SyncFileRead, SyncFileTarget, UnavailableReason},
};

/// How many staging names are tried before giving up.
const STAGING_ATTEMPTS: usize = 16;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Why nothing was published. Fixed categories only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotPublishedReason {
    /// The staging file could not be created.
    StagingFailed,
    /// The bytes could not be written or flushed completely.
    WriteFailed,
    /// The destination or the staging file is not on a local `NTFS` volume.
    VolumeNotLocalNtfs,
    /// The physical identity of the staging file could not be established, or it
    /// is not a single, distinct, live file.
    IdentityUncertain,
    /// The location, or the evidence the caller checked, is no longer what was
    /// prepared.
    EvidenceChanged,
    /// Something already exists at the target name.
    TargetAppeared,
    /// NTFS refused the rename for a reason other than a name collision (for
    /// example a different volume or a rejected parameter).
    RenameRefused,
}

/// What [`publish_new_copy`] established. See the module documentation for what
/// each variant permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum PublishOutcome {
    /// Created at the target name and independently verified, including the
    /// caller's own check.
    Published,
    /// Definitely not published. `staging_remains` is true if our own hidden
    /// staging file could not be confirmed removed.
    NotPublished {
        reason: NotPublishedReason,
        staging_remains: bool,
    },
    /// The rename may or may not have happened. Nothing was deleted.
    PublicationUnknown,
    /// The rename happened (or contradictory evidence says so) but an independent
    /// check failed or could not run. The target is kept.
    CreatedUnverified,
}

/// What to create. Borrowed for the call only.
pub(crate) struct PublishRequest<'a> {
    /// The absent target to create. Its parent must exist.
    pub(crate) target: &'a SyncFileTarget,
    /// The exact bytes to write.
    pub(crate) source: &'a [u8],
    /// Physical facts of the vault's own primary file: the copy must be distinct.
    pub(crate) primary: &'a HandleFacts,
}

/// Fixed points of the sequence, for the test hooks. Always defined; only tests
/// can observe them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    BeforePin,
    AfterStagingOpen,
    BeforeWrite,
    BeforeIdentity,
    BeforeRename,
    BeforeCleanup,
    BeforeVerify,
}

#[cfg(test)]
type StageHook = Box<dyn FnMut(Stage, Option<&Path>)>;

/// Test seams. In production this is an empty value whose methods change nothing.
/// Injected facts and hooks prove **decision logic only**; they say nothing about
/// what a real filesystem does.
#[derive(Default)]
pub(crate) struct Seams {
    #[cfg(test)]
    pub(crate) hook: Option<StageHook>,
    #[cfg(test)]
    pub(crate) directory_facts: Option<super::file_identity::VolumeFacts>,
    #[cfg(test)]
    pub(crate) staging_facts: Option<Result<HandleFacts, super::file_identity::IdentityError>>,
    #[cfg(test)]
    pub(crate) verify_read: Option<Box<dyn FnMut(SyncFileRead) -> SyncFileRead>>,
}

impl Seams {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn hit(&mut self, stage: Stage, staging: Option<&Path>) {
        #[cfg(test)]
        if let Some(hook) = self.hook.as_mut() {
            hook(stage, staging);
        }
    }

    fn directory_facts(
        &self,
        real: Result<super::file_identity::VolumeFacts, super::file_identity::IdentityError>,
    ) -> Result<super::file_identity::VolumeFacts, super::file_identity::IdentityError> {
        #[cfg(test)]
        if let Some(injected) = self.directory_facts {
            return Ok(injected);
        }

        real
    }

    fn staging_facts(
        &self,
        real: Result<HandleFacts, super::file_identity::IdentityError>,
    ) -> Result<HandleFacts, super::file_identity::IdentityError> {
        #[cfg(test)]
        if let Some(injected) = self.staging_facts {
            return injected;
        }

        real
    }

    fn verify_read(&mut self, real: SyncFileRead) -> SyncFileRead {
        #[cfg(test)]
        if let Some(map) = self.verify_read.as_mut() {
            return map(real);
        }

        real
    }
}

/// Open `dir` as a pin: not following a reparse point, read and traverse access,
/// sharing read and write but **not delete**, so that while it is held no other
/// process can rename or delete the directory. Write sharing stays on because the
/// kernel's own add-file open of the rename target must be share-compatible with
/// the pin.
#[cfg(windows)]
pub(crate) fn open_directory_pin(dir: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
}

#[cfg(not(windows))]
pub(crate) fn open_directory_pin(_dir: &Path) -> io::Result<File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Create a staging file for `leaf` in `dir` with `create_new`, holding it open
/// with read, write and delete access and read-only sharing. Returns the handle
/// and the staging path.
#[cfg(windows)]
pub(crate) fn create_staging(dir: &Path, leaf: &OsStr) -> io::Result<(File, PathBuf)> {
    let mut last = io::Error::from(io::ErrorKind::AlreadyExists);

    for _ in 0..STAGING_ATTEMPTS {
        let mut id = [0u8; 16];

        getrandom::fill(&mut id).map_err(|_| io::Error::other("secure randomness unavailable"))?;

        let id = uuid::Builder::from_random_bytes(id).into_uuid();
        let mut name = std::ffi::OsString::from(".");

        name.push(leaf);
        name.push(format!(".localvault-copy-{id}.tmp"));

        let path = dir.join(name);

        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = error,
            Err(error) => return Err(error),
        }
    }

    Err(last)
}

#[cfg(not(windows))]
pub(crate) fn create_staging(_dir: &Path, _leaf: &OsStr) -> io::Result<(File, PathBuf)> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Whether `metadata` describes a plain directory: not a symlink, not any reparse
/// point (junction, mount point, placeholder).
fn is_plain_directory(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let reparse = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    #[cfg(not(windows))]
    let reparse = false;

    metadata.is_dir() && !metadata.file_type().is_symlink() && !reparse
}

/// Every ancestor of `path` (its parent up to the root) exists and is a plain
/// directory. Local on purpose: the adapter's own check is private.
fn ancestors_are_plain(path: &Path) -> bool {
    let mut confirmed = 0usize;

    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_plain_directory(&metadata) => confirmed += 1,
            _ => return false,
        }
    }

    confirmed > 0
}

/// Whether the parent of `target_path` is, right now, an eligible destination:
/// it exists, can be opened as a pin, is a plain directory on a local `NTFS`
/// volume, and every ancestor is a plain directory. Strictly read-only: the pin is
/// closed again before returning, nothing is created, and the answer is only
/// ever a preview (publication repeats every check on its own pin).
pub(crate) fn destination_is_eligible(target_path: &Path) -> bool {
    #[cfg(not(windows))]
    {
        let _ = target_path;

        false
    }

    #[cfg(windows)]
    {
        let Some(parent) = target_path.parent() else {
            return false;
        };

        let Ok(pin) = open_directory_pin(parent) else {
            return false;
        };

        pin.metadata()
            .is_ok_and(|metadata| is_plain_directory(&metadata))
            && volume_facts_of(&pin).is_ok_and(|facts| facts.is_local_ntfs())
            && ancestors_are_plain(target_path)
    }
}

fn not_published(reason: NotPublishedReason) -> PublishOutcome {
    PublishOutcome::NotPublished {
        reason,
        staging_remains: false,
    }
}

/// Handle-bound cleanup of the staging file, for the failure paths where the
/// object certainly still carries its staging name. The delete is by handle;
/// because its effect is observed only when the handle closes, the handle is
/// dropped and the result is then checked (a read-only metadata query by path).
/// Anything that cannot be confirmed gone is reported as remaining.
fn abandon(
    staging: File,
    staging_path: &Path,
    reason: NotPublishedReason,
    seams: &mut Seams,
) -> PublishOutcome {
    seams.hit(Stage::BeforeCleanup, Some(staging_path));

    let deleted = handle_ops::delete_by_handle(&staging).is_ok();

    drop(staging);

    let gone = deleted
        && matches!(
            fs::symlink_metadata(staging_path),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );

    PublishOutcome::NotPublished {
        reason,
        staging_remains: !gone,
    }
}

fn refusal_reason(refusal: DefiniteRefusal) -> NotPublishedReason {
    match refusal {
        DefiniteRefusal::NameCollision => NotPublishedReason::TargetAppeared,
        DefiniteRefusal::NotSameDevice => NotPublishedReason::VolumeNotLocalNtfs,
        DefiniteRefusal::NameInvalid
        | DefiniteRefusal::InvalidParameter
        | DefiniteRefusal::AccessDenied
        | DefiniteRefusal::SharingViolation => NotPublishedReason::RenameRefused,
    }
}

/// Whether `read` is a file with the staged physical identity.
fn is_ours(read: &SyncFileRead, staged: &HandleFacts) -> bool {
    matches!(
        read,
        SyncFileRead::Present(present)
            if present
                .physical()
                .is_ok_and(|facts| facts.identity() == staged.identity())
    )
}

/// Create the file described by `request`. See the module documentation.
///
/// `recheck` is called once, immediately before the rename, and must return
/// `true` only if the caller's own evidence (the source bytes, the sync state)
/// is unchanged. `verify_bytes` is called with the bytes independently read back
/// from the target, while every handle is still held, and must return `true` only
/// if they authenticate.
pub(crate) fn publish_new_copy(
    request: &PublishRequest<'_>,
    recheck: &mut dyn FnMut() -> bool,
    verify_bytes: &mut dyn FnMut(&[u8]) -> bool,
    seams: &mut Seams,
) -> PublishOutcome {
    #[cfg(not(windows))]
    {
        let _ = (request, recheck, verify_bytes, seams);

        not_published(NotPublishedReason::VolumeNotLocalNtfs)
    }

    #[cfg(windows)]
    {
        publish_on_windows(request, recheck, verify_bytes, seams)
    }
}

#[cfg(windows)]
fn publish_on_windows(
    request: &PublishRequest<'_>,
    recheck: &mut dyn FnMut() -> bool,
    verify_bytes: &mut dyn FnMut(&[u8]) -> bool,
    seams: &mut Seams,
) -> PublishOutcome {
    use NotPublishedReason as Reason;

    let target_path = Path::new(request.target.locator().as_str());

    let (Some(parent), Some(leaf)) = (target_path.parent(), target_path.file_name()) else {
        return not_published(Reason::EvidenceChanged);
    };

    // 1. Pin the destination directory and judge the handle.
    seams.hit(Stage::BeforePin, None);

    let Ok(pin) = open_directory_pin(parent) else {
        return not_published(Reason::EvidenceChanged);
    };

    match pin.metadata() {
        Ok(metadata) if is_plain_directory(&metadata) => {}
        _ => return not_published(Reason::EvidenceChanged),
    }

    match seams.directory_facts(volume_facts_of(&pin)) {
        Ok(facts) if facts.is_local_ntfs() => {}
        _ => return not_published(Reason::VolumeNotLocalNtfs),
    }

    // After the pin, so a redirection installed before it is caught here.
    if !ancestors_are_plain(target_path) {
        return not_published(Reason::EvidenceChanged);
    }

    // 2. The staging file, exclusively, held open from here on.
    let (mut staging, staging_path) = match create_staging(parent, leaf) {
        Ok(created) => created,
        Err(_) => return not_published(Reason::StagingFailed),
    };

    seams.hit(Stage::AfterStagingOpen, Some(&staging_path));

    // 3. Exactly the caller's bytes.
    seams.hit(Stage::BeforeWrite, Some(&staging_path));

    let written = staging
        .write_all(request.source)
        .and_then(|()| staging.flush())
        .and_then(|()| staging.sync_all())
        .is_ok()
        && staging
            .metadata()
            .is_ok_and(|metadata| metadata.len() == request.source.len() as u64);

    if !written {
        return abandon(staging, &staging_path, Reason::WriteFailed, seams);
    }

    // 4. Identity, from the very handle that was written.
    seams.hit(Stage::BeforeIdentity, Some(&staging_path));

    let staged = match seams.staging_facts(facts_of(&staging)) {
        Ok(facts) => facts,
        Err(_) => return abandon(staging, &staging_path, Reason::IdentityUncertain, seams),
    };

    if !staged.is_local_ntfs() {
        return abandon(staging, &staging_path, Reason::VolumeNotLocalNtfs, seams);
    }

    if compare(request.primary, &staged) != PhysicalVerdict::Distinct
        || !staged.has_single_link()
        || staged.is_delete_pending()
    {
        return abandon(staging, &staging_path, Reason::IdentityUncertain, seams);
    }

    // 5. Narrowing checks immediately before publication.
    if !recheck() {
        return abandon(staging, &staging_path, Reason::EvidenceChanged, seams);
    }

    match request.target.read() {
        SyncFileRead::AbsentOnDisk => {}
        SyncFileRead::Present(_)
        | SyncFileRead::Unavailable(UnavailableReason::UnexpectedObject) => {
            return abandon(staging, &staging_path, Reason::TargetAppeared, seams)
        }
        SyncFileRead::Unavailable(_) => {
            return abandon(staging, &staging_path, Reason::EvidenceChanged, seams)
        }
    }

    // 6. Publish: rename the open handle into the pinned directory, no replace.
    seams.hit(Stage::BeforeRename, Some(&staging_path));

    match handle_ops::rename_into_directory_no_replace(&staging, &pin, leaf) {
        RenameStatus::Renamed => {}

        // The leaf was not one plain name: no native call was made.
        RenameStatus::Rejected => {
            return abandon(staging, &staging_path, Reason::EvidenceChanged, seams)
        }

        RenameStatus::Refused(refusal) => {
            let post = request.target.read();

            // A refusal contradicted by our own file at the target name.
            if is_ours(&post, &staged) {
                return PublishOutcome::CreatedUnverified;
            }

            return match refusal {
                // NTFS itself says the name exists: whatever is there, it is not
                // ours (checked above), and the rename was not performed.
                DefiniteRefusal::NameCollision => {
                    abandon(staging, &staging_path, Reason::TargetAppeared, seams)
                }
                // Any other refusal also needs the target to be provably absent.
                other if matches!(post, SyncFileRead::AbsentOnDisk) => {
                    abandon(staging, &staging_path, refusal_reason(other), seams)
                }
                _ => PublishOutcome::PublicationUnknown,
            };
        }

        RenameStatus::Unknown => {
            return if is_ours(&request.target.read(), &staged) {
                PublishOutcome::CreatedUnverified
            } else {
                PublishOutcome::PublicationUnknown
            };
        }
    }

    // 7. Verify while every handle is still held. Nothing is ever deleted below.
    seams.hit(Stage::BeforeVerify, Some(&staging_path));

    match seams.staging_facts(facts_of(&staging)) {
        Ok(after) if after == staged => {}
        _ => return PublishOutcome::CreatedUnverified,
    }

    let SyncFileRead::Present(present) = seams.verify_read(request.target.read()) else {
        return PublishOutcome::CreatedUnverified;
    };

    let Ok(read_facts) = present.physical() else {
        return PublishOutcome::CreatedUnverified;
    };

    let independent = present.target() == request.target.locator()
        && read_facts.identity() == staged.identity()
        && read_facts.has_single_link()
        && !read_facts.is_delete_pending()
        && read_facts.is_local_ntfs()
        && compare(request.primary, read_facts) == PhysicalVerdict::Distinct
        && present.candidate_raw() == request.source;

    if independent && verify_bytes(present.candidate_raw()) {
        PublishOutcome::Published
    } else {
        PublishOutcome::CreatedUnverified
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        os::windows::fs::OpenOptionsExt,
        rc::Rc,
    };

    use super::*;
    use crate::vault::{
        file_identity::{FileSystemKind, IdentityError, VolumeFacts},
        handle_ops::{
            inject_delete_status, inject_rename_status, take_last_delete_status,
            take_last_rename_status, test_support::*,
        },
    };

    type Attempts = Vec<(&'static str, bool)>;
    type ErrorCodes = Vec<(&'static str, Option<i32>)>;
    type VerifyMap = Box<dyn FnMut(SyncFileRead) -> SyncFileRead>;

    const SOURCE: &[u8] = b"b2a-new-copy-test-bytes: exact, opaque, never parsed here";
    const STAGING_MARK: &str = ".localvault-copy-";
    const LEAK_MARK: &str = "LEAKMARK-NEWCOPY";

    fn hex(status: i32) -> String {
        format!("0x{:08X}", status as u32)
    }

    /// `vault\primary.lvault` (the stand-in primary), `dest\` (the pinned
    /// destination), `other\` with a same-leaf decoy, and a held primary handle.
    struct Rig {
        // The held primary handle is declared before the scratch directory guard
        // (declared last) so it closes first.
        primary: File,
        dest: PathBuf,
        target_path: PathBuf,
        target: SyncFileTarget,
        primary_path: PathBuf,
        primary_facts: HandleFacts,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn new(name: &str) -> Self {
            let dir = scratch(name);
            let dest = dir.path().join("dest");
            let vault = dir.path().join("vault");
            let other = dir.path().join("other");

            fs::create_dir(&dest).unwrap();
            fs::create_dir(&vault).unwrap();
            fs::create_dir(&other).unwrap();

            let primary_path = vault.join("primary.lvault");

            fs::write(&primary_path, SOURCE).unwrap();
            fs::write(vault.join("primary.lvault.backup"), b"backup bytes").unwrap();
            fs::write(other.join("copy.lvault"), b"decoy with the same leaf").unwrap();

            let primary = File::open(&primary_path).unwrap();
            let primary_facts = facts_of(&primary).unwrap();
            let target_path = dest.join("copy.lvault");
            let target = SyncFileTarget::from_path(&target_path).unwrap();

            Self {
                dir,
                dest,
                target_path,
                target,
                primary_path,
                primary,
                primary_facts,
            }
        }

        fn run_with(
            &self,
            recheck: &mut dyn FnMut() -> bool,
            verify: &mut dyn FnMut(&[u8]) -> bool,
            seams: &mut Seams,
        ) -> PublishOutcome {
            let _ = &self.primary;

            publish_new_copy(
                &PublishRequest {
                    target: &self.target,
                    source: SOURCE,
                    primary: &self.primary_facts,
                },
                recheck,
                verify,
                seams,
            )
        }

        fn publish(&self) -> PublishOutcome {
            self.run_with(&mut || true, &mut |_| true, &mut Seams::none())
        }

        fn publish_with(&self, seams: &mut Seams) -> PublishOutcome {
            self.run_with(&mut || true, &mut |_| true, seams)
        }

        fn staging_names(&self) -> bool {
            any_name_contains(self.dir.path(), STAGING_MARK)
        }
    }

    fn hook(f: impl FnMut(Stage, Option<&Path>) + 'static) -> Seams {
        Seams {
            hook: Some(Box::new(f)),
            ..Seams::none()
        }
    }

    fn at(stage: Stage, mut f: impl FnMut(&Path) + 'static) -> Seams {
        hook(move |hit, staging| {
            if hit == stage {
                f(staging.unwrap_or(Path::new("")));
            }
        })
    }

    // ---- success ---------------------------------------------------------------

    #[test]
    fn a_new_copy_is_created_with_the_exact_bytes_and_nothing_else_changes() {
        let rig = Rig::new("copy-success");
        let cwd = std::env::current_dir().unwrap();

        assert!(!rig.dir.path().starts_with(&cwd) && !cwd.starts_with(rig.dir.path()));

        let cwd_before = cwd_names();
        let outside_before = snapshot(&rig.dir.path().join("vault"));
        let decoy_before = snapshot(&rig.dir.path().join("other"));

        let _ = take_last_rename_status();

        assert_eq!(rig.publish(), PublishOutcome::Published);
        assert_eq!(take_last_rename_status(), Some(0));

        // Exactly the source bytes, one name, one link, no staging name anywhere.
        assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
        assert_eq!(names(&rig.dest), vec!["copy.lvault".to_owned()]);
        assert!(!rig.staging_names());

        let facts = facts_of(&File::open(&rig.target_path).unwrap()).unwrap();

        assert!(facts.has_single_link() && facts.is_local_ntfs());
        assert_eq!(
            compare(&rig.primary_facts, &facts),
            PhysicalVerdict::Distinct
        );

        // The primary, its backup and the same-leaf decoy are untouched, and the
        // working directory gained nothing.
        assert_eq!(snapshot(&rig.dir.path().join("vault")), outside_before);
        assert_eq!(snapshot(&rig.dir.path().join("other")), decoy_before);
        assert_eq!(cwd_names(), cwd_before);
        assert!(!cwd.join("copy.lvault").exists());
        assert!(!any_name_contains(&cwd.join("src"), STAGING_MARK));
    }

    #[test]
    fn the_staging_identity_before_and_after_the_rename_equals_the_independent_read() {
        let rig = Rig::new("copy-identity");
        let before: Rc<RefCell<Option<HandleFacts>>> = Rc::default();
        let sink = Rc::clone(&before);

        let mut seams = at(Stage::BeforeRename, move |staging| {
            // A second, reading handle to the staging file (readers are allowed).
            *sink.borrow_mut() = Some(facts_of(&File::open(staging).unwrap()).unwrap());
        });

        assert_eq!(rig.publish_with(&mut seams), PublishOutcome::Published);

        let before = before.borrow().expect("facts before the rename");
        let after = facts_of(&File::open(&rig.target_path).unwrap()).unwrap();

        assert_eq!(before, after);
        assert!(before.has_single_link() && after.has_single_link());
    }

    #[test]
    fn the_stages_are_visited_in_the_documented_order() {
        let rig = Rig::new("copy-stages");
        let seen: Rc<RefCell<Vec<Stage>>> = Rc::default();
        let sink = Rc::clone(&seen);
        let mut seams = hook(move |stage, _| sink.borrow_mut().push(stage));

        assert_eq!(rig.publish_with(&mut seams), PublishOutcome::Published);
        assert_eq!(
            *seen.borrow(),
            vec![
                Stage::BeforePin,
                Stage::AfterStagingOpen,
                Stage::BeforeWrite,
                Stage::BeforeIdentity,
                Stage::BeforeRename,
                Stage::BeforeVerify,
            ]
        );

        // A failure path ends in cleanup instead of the rename and the verify.
        let rig = Rig::new("copy-stages-failure");
        let seen: Rc<RefCell<Vec<Stage>>> = Rc::default();
        let sink = Rc::clone(&seen);
        let mut seams = hook(move |stage, _| sink.borrow_mut().push(stage));

        assert_eq!(
            rig.run_with(&mut || false, &mut |_| true, &mut seams),
            not_published(NotPublishedReason::EvidenceChanged)
        );
        assert_eq!(
            *seen.borrow(),
            vec![
                Stage::BeforePin,
                Stage::AfterStagingOpen,
                Stage::BeforeWrite,
                Stage::BeforeIdentity,
                Stage::BeforeCleanup,
            ]
        );
    }

    #[test]
    fn the_verification_sees_exactly_the_independently_read_bytes() {
        let rig = Rig::new("copy-verify-bytes");
        let seen: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
        let sink = Rc::clone(&seen);

        let outcome = rig.run_with(
            &mut || true,
            &mut |bytes| {
                sink.borrow_mut().push(bytes.to_vec());

                true
            },
            &mut Seams::none(),
        );

        assert_eq!(outcome, PublishOutcome::Published);
        assert_eq!(*seen.borrow(), vec![SOURCE.to_vec()]);
    }

    // ---- refusals before any write --------------------------------------------

    #[test]
    fn a_missing_parent_refuses_and_creates_no_directory() {
        let rig = Rig::new("copy-missing-parent");
        let target =
            SyncFileTarget::from_path(&rig.dir.path().join("absent").join("copy.lvault")).unwrap();
        let before = snapshot(rig.dir.path());

        let outcome = publish_new_copy(
            &PublishRequest {
                target: &target,
                source: SOURCE,
                primary: &rig.primary_facts,
            },
            &mut || true,
            &mut |_| true,
            &mut Seams::none(),
        );

        assert_eq!(outcome, not_published(NotPublishedReason::EvidenceChanged));
        assert_eq!(snapshot(rig.dir.path()), before);
        assert!(!rig.dir.path().join("absent").exists());
    }

    #[test]
    fn an_existing_file_directory_or_junction_at_the_target_is_never_replaced() {
        for kind in ["file", "directory", "junction"] {
            let rig = Rig::new(&format!("copy-exists-{kind}"));
            let aside = rig.dir.path().join("aside");

            fs::create_dir(&aside).unwrap();
            fs::write(aside.join("inner.txt"), b"inside").unwrap();

            match kind {
                "file" => fs::write(&rig.target_path, b"someone else's file").unwrap(),
                "directory" => {
                    fs::create_dir(&rig.target_path).unwrap();
                    fs::write(rig.target_path.join("child"), b"child").unwrap();
                }
                _ => make_junction(&rig.target_path, &aside),
            }

            let before = snapshot(rig.dir.path());

            assert_eq!(
                rig.publish(),
                not_published(NotPublishedReason::TargetAppeared),
                "{kind}"
            );
            assert_eq!(snapshot(rig.dir.path()), before, "{kind}");
            assert!(!rig.staging_names(), "{kind}");
        }
    }

    #[test]
    fn an_unsupported_destination_or_staging_volume_is_refused_before_the_rename() {
        let volumes = [
            ("refs", VolumeFacts::for_test(FileSystemKind::Refs, true)),
            ("other", VolumeFacts::for_test(FileSystemKind::Other, true)),
            ("remote", VolumeFacts::for_test(FileSystemKind::Ntfs, false)),
        ];

        for (name, volume) in volumes {
            // At the directory: nothing at all is created.
            let rig = Rig::new(&format!("copy-dir-{name}"));
            let before = snapshot(rig.dir.path());
            let mut seams = Seams {
                directory_facts: Some(volume),
                ..Seams::none()
            };

            assert_eq!(
                rig.publish_with(&mut seams),
                not_published(NotPublishedReason::VolumeNotLocalNtfs),
                "directory {name}"
            );
            assert_eq!(snapshot(rig.dir.path()), before, "directory {name}");

            // At the staging handle: created, then removed by handle.
            let rig = Rig::new(&format!("copy-staging-{name}"));
            let mut seams = Seams {
                staging_facts: Some(Ok(HandleFacts::for_test(
                    77,
                    [9; 16],
                    1,
                    false,
                    volume_kind(name),
                    name != "remote",
                ))),
                ..Seams::none()
            };

            let _ = take_last_rename_status();

            assert_eq!(
                rig.publish_with(&mut seams),
                not_published(NotPublishedReason::VolumeNotLocalNtfs),
                "staging {name}"
            );
            // The rename was never attempted.
            assert_eq!(take_last_rename_status(), None, "staging {name}");
            assert!(!rig.target_path.exists(), "staging {name}");
            assert!(names(&rig.dest).is_empty(), "staging {name}");
        }
    }

    fn volume_kind(name: &str) -> FileSystemKind {
        match name {
            "refs" => FileSystemKind::Refs,
            "other" => FileSystemKind::Other,
            _ => FileSystemKind::Ntfs,
        }
    }

    #[test]
    fn staging_facts_that_are_not_a_single_distinct_live_file_are_refused() {
        let rig = Rig::new("copy-facts");
        let primary = rig.primary_facts;
        let bad = [
            ("same file as the primary", Ok(primary)),
            (
                "two links",
                Ok(HandleFacts::for_test(
                    7,
                    [2; 16],
                    2,
                    false,
                    FileSystemKind::Ntfs,
                    true,
                )),
            ),
            (
                "delete pending",
                Ok(HandleFacts::for_test(
                    7,
                    [2; 16],
                    1,
                    true,
                    FileSystemKind::Ntfs,
                    true,
                )),
            ),
            (
                "degenerate id",
                Ok(HandleFacts::for_test(
                    0,
                    [0; 16],
                    1,
                    false,
                    FileSystemKind::Ntfs,
                    true,
                )),
            ),
            ("lookup failure", Err(IdentityError::Lookup)),
        ];

        for (label, injected) in bad {
            let mut seams = Seams {
                staging_facts: Some(injected),
                ..Seams::none()
            };

            let _ = take_last_rename_status();

            assert_eq!(
                rig.publish_with(&mut seams),
                not_published(NotPublishedReason::IdentityUncertain),
                "{label}"
            );
            assert_eq!(take_last_rename_status(), None, "{label}");
            assert!(names(&rig.dest).is_empty(), "{label}");
        }
    }

    #[test]
    fn a_failed_caller_recheck_removes_the_staging_file_and_publishes_nothing() {
        let rig = Rig::new("copy-recheck");
        let before = snapshot(&rig.dir.path().join("vault"));

        let outcome = rig.run_with(&mut || false, &mut |_| true, &mut Seams::none());

        assert_eq!(outcome, not_published(NotPublishedReason::EvidenceChanged));
        assert!(names(&rig.dest).is_empty());
        assert_eq!(snapshot(&rig.dir.path().join("vault")), before);
    }

    // ---- sharing / substitution attempts --------------------------------------

    fn attempts_on_staging(staging: &Path, primary: &Path) -> Vec<(&'static str, bool)> {
        let elsewhere = staging.with_extension("moved");

        vec![
            ("remove", fs::remove_file(staging).is_err()),
            ("rename away", fs::rename(staging, &elsewhere).is_err()),
            ("rename over", fs::rename(primary, staging).is_err()),
            ("replace bytes", fs::write(staging, SOURCE).is_err()),
            (
                "write open",
                OpenOptions::new().write(true).open(staging).is_err(),
            ),
            ("hard link", fs::hard_link(primary, staging).is_err()),
            (
                "delete access",
                OpenOptions::new()
                    .read(true)
                    .access_mode(DELETE)
                    .open(staging)
                    .is_err(),
            ),
        ]
    }

    #[test]
    fn substitution_attempts_on_the_staging_path_before_the_rename_all_fail() {
        let rig = Rig::new("copy-substitute");
        let primary = rig.primary_path.clone();
        let results: Rc<RefCell<Attempts>> = Rc::default();
        let sink = Rc::clone(&results);

        let mut seams = at(Stage::BeforeRename, move |staging| {
            *sink.borrow_mut() = attempts_on_staging(staging, &primary);
        });

        assert_eq!(rig.publish_with(&mut seams), PublishOutcome::Published);

        let results = results.borrow();

        assert_eq!(results.len(), 7);

        for (label, refused) in results.iter() {
            assert!(refused, "{label} was not refused");
        }

        // The published bytes and identity are ours, and the primary is intact.
        assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
        assert_eq!(fs::read(&rig.primary_path).unwrap(), SOURCE);
        assert_eq!(names(&rig.dest), vec!["copy.lvault".to_owned()]);
    }

    #[test]
    fn substitution_attempts_during_cleanup_fail_and_only_our_object_is_removed() {
        let rig = Rig::new("copy-cleanup-substitute");
        let decoy = rig.dest.join("decoy.txt");

        fs::write(&decoy, b"unrelated decoy").unwrap();

        let decoy_before = snapshot(&rig.dest)
            .into_iter()
            .filter(|line| line.contains("decoy"))
            .collect::<Vec<_>>();
        let primary = rig.primary_path.clone();
        let results: Rc<RefCell<Attempts>> = Rc::default();
        let sink = Rc::clone(&results);

        let mut seams = at(Stage::BeforeCleanup, move |staging| {
            *sink.borrow_mut() = attempts_on_staging(staging, &primary);
        });

        // A failure path that cleans up: the caller's recheck fails.
        let outcome = rig.run_with(&mut || false, &mut |_| true, &mut seams);

        assert_eq!(outcome, not_published(NotPublishedReason::EvidenceChanged));

        for (label, refused) in results.borrow().iter() {
            assert!(refused, "{label} was not refused");
        }

        // Only the staging object is gone; the decoy and the primary are intact.
        assert_eq!(names(&rig.dest), vec!["decoy.txt".to_owned()]);
        assert_eq!(
            snapshot(&rig.dest)
                .into_iter()
                .filter(|line| line.contains("decoy"))
                .collect::<Vec<_>>(),
            decoy_before
        );
        assert_eq!(fs::read(&rig.primary_path).unwrap(), SOURCE);
    }

    // ---- competing targets ------------------------------------------------------

    #[test]
    fn a_competing_target_created_just_before_the_rename_is_never_replaced() {
        for kind in ["file", "directory", "junction"] {
            let rig = Rig::new(&format!("copy-race-{kind}"));
            let aside = rig.dir.path().join("aside");
            let target = rig.target_path.clone();

            fs::create_dir(&aside).unwrap();
            fs::write(aside.join("inner.txt"), b"inside").unwrap();

            let snapshot_after: Rc<RefCell<Vec<String>>> = Rc::default();
            let sink = Rc::clone(&snapshot_after);
            let root = rig.dir.path().to_path_buf();

            let mut seams = at(Stage::BeforeRename, move |_staging| {
                match kind {
                    "file" => fs::write(&target, b"the competing bytes").unwrap(),
                    "directory" => {
                        fs::create_dir(&target).unwrap();
                        fs::write(target.join("child"), b"child").unwrap();
                    }
                    _ => make_junction(&target, &aside),
                }

                // Everything except the staging file, as it stands now.
                *sink.borrow_mut() = snapshot(&root)
                    .into_iter()
                    .filter(|line| !line.contains(STAGING_MARK))
                    .collect();
            });

            let _ = take_last_rename_status();

            assert_eq!(
                rig.publish_with(&mut seams),
                not_published(NotPublishedReason::TargetAppeared),
                "{kind}"
            );

            eprintln!(
                "OBSERVED competing {kind} at BeforeRename: rename status {}",
                hex(take_last_rename_status().expect("a real rename status"))
            );

            // The competitor is byte- and mtime-identical, the staging file is gone.
            assert_eq!(snapshot(rig.dir.path()), *snapshot_after.borrow(), "{kind}");
            assert!(!rig.staging_names(), "{kind}");
        }
    }

    // ---- unexpected native results (injected: decision logic only) --------------

    #[test]
    fn a_definite_refusal_with_an_absent_target_removes_the_staging_file() {
        let rig = Rig::new("copy-refused");

        inject_rename_status(0xC000_000D_u32 as i32); // STATUS_INVALID_PARAMETER

        assert_eq!(
            rig.publish(),
            not_published(NotPublishedReason::RenameRefused)
        );
        assert!(names(&rig.dest).is_empty());
        assert!(!rig.target_path.exists());
    }

    #[test]
    fn an_unrecognised_status_is_unknown_and_nothing_is_deleted() {
        for status in [0xC000_0001_u32 as i32, 0x4000_0000, 0x0000_0103] {
            let rig = Rig::new("copy-unknown");

            inject_rename_status(status);

            assert_eq!(rig.publish(), PublishOutcome::PublicationUnknown);

            // The staging file is preserved; the target does not exist.
            let left = names(&rig.dest);

            assert_eq!(left.len(), 1);
            assert!(left[0].contains(STAGING_MARK));
            assert!(!rig.target_path.exists());
        }
    }

    #[test]
    fn a_refusal_that_is_not_provably_absent_is_unknown() {
        // A non-collision refusal while something else stands at the target name.
        let rig = Rig::new("copy-refused-present");
        let target = rig.target_path.clone();

        let mut seams = at(Stage::BeforeRename, move |_| {
            fs::write(&target, b"appeared meanwhile").unwrap();
        });

        inject_rename_status(0xC000_0022_u32 as i32); // STATUS_ACCESS_DENIED

        assert_eq!(
            rig.publish_with(&mut seams),
            PublishOutcome::PublicationUnknown
        );
        assert_eq!(fs::read(&rig.target_path).unwrap(), b"appeared meanwhile");
        assert_eq!(
            names(&rig.dest)
                .iter()
                .filter(|n| n.contains(STAGING_MARK))
                .count(),
            1
        );
    }

    #[test]
    fn an_injected_success_with_no_target_is_created_unverified_and_deletes_nothing() {
        let rig = Rig::new("copy-injected-success");

        inject_rename_status(0);

        assert_eq!(rig.publish(), PublishOutcome::CreatedUnverified);
        assert!(!rig.target_path.exists());
        // The staging file (which is all there is) was not deleted.
        assert_eq!(names(&rig.dest).len(), 1);
    }

    #[test]
    fn a_failed_handle_delete_after_a_refusal_keeps_the_file_and_says_so() {
        let rig = Rig::new("copy-delete-fails");

        inject_rename_status(0xC000_000D_u32 as i32);
        inject_delete_status(0xC000_0001_u32 as i32);

        assert_eq!(
            rig.publish(),
            PublishOutcome::NotPublished {
                reason: NotPublishedReason::RenameRefused,
                staging_remains: true,
            }
        );
        assert!(!rig.target_path.exists());
        assert_eq!(names(&rig.dest).len(), 1);
    }

    #[test]
    fn a_collision_refusal_with_a_failed_delete_reports_the_leftover() {
        let rig = Rig::new("copy-collision-delete-fails");
        let target = rig.target_path.clone();

        let mut seams = at(Stage::BeforeRename, move |_| {
            fs::write(&target, b"competitor").unwrap();
        });

        inject_delete_status(0xC000_0001_u32 as i32);

        assert_eq!(
            rig.publish_with(&mut seams),
            PublishOutcome::NotPublished {
                reason: NotPublishedReason::TargetAppeared,
                staging_remains: true,
            }
        );
        assert_eq!(fs::read(&rig.target_path).unwrap(), b"competitor");

        let _ = take_last_delete_status();
    }

    // ---- verification failures --------------------------------------------------

    fn with_physical(
        facts: Result<HandleFacts, IdentityError>,
    ) -> Box<dyn FnMut(SyncFileRead) -> SyncFileRead> {
        Box::new(move |read| match read {
            SyncFileRead::Present(present) => {
                SyncFileRead::Present(present.with_physical_for_test(facts))
            }
            other => other,
        })
    }

    #[test]
    fn every_verification_failure_is_created_unverified_and_keeps_the_target() {
        // Each case replaces what the independent read-back reports. (A real file
        // whose bytes differ cannot be produced here: the sharing mode keeps every
        // writer out while the staging handle is held, which is itself the
        // property under test elsewhere.)
        let ntfs = |id: u8, links: u32, pending: bool| {
            HandleFacts::for_test(99, [id; 16], links, pending, FileSystemKind::Ntfs, true)
        };

        let cases: Vec<(&str, VerifyMap)> = vec![
            ("another identity", with_physical(Ok(ntfs(5, 1, false)))),
            ("two links", with_physical(Ok(ntfs(3, 2, false)))),
            ("delete pending", with_physical(Ok(ntfs(4, 1, true)))),
            (
                "facts lookup failed",
                with_physical(Err(IdentityError::Lookup)),
            ),
            (
                "unreadable",
                Box::new(|_| SyncFileRead::Unavailable(UnavailableReason::Changed)),
            ),
            ("absent", Box::new(|_| SyncFileRead::AbsentOnDisk)),
        ];

        for (label, map) in cases {
            let rig = Rig::new("copy-verify-fails");
            let mut seams = Seams {
                verify_read: Some(map),
                ..Seams::none()
            };

            assert_eq!(
                rig.publish_with(&mut seams),
                PublishOutcome::CreatedUnverified,
                "{label}"
            );
            // The target is kept, with the exact bytes, and nothing was deleted.
            assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE, "{label}");
            assert_eq!(names(&rig.dest), vec!["copy.lvault".to_owned()], "{label}");
        }
    }

    #[test]
    fn a_read_back_of_a_different_file_is_created_unverified() {
        // Different locator, bytes and identity: another real file read instead.
        let rig = Rig::new("copy-verify-other-file");
        let impostor_path = rig.dir.path().join("other").join("copy.lvault");
        let impostor = SyncFileTarget::from_path(&impostor_path).unwrap();
        let mut seams = Seams {
            verify_read: Some(Box::new(move |_| impostor.read())),
            ..Seams::none()
        };

        assert_eq!(
            rig.publish_with(&mut seams),
            PublishOutcome::CreatedUnverified
        );
        assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
        assert_eq!(
            fs::read(&impostor_path).unwrap(),
            b"decoy with the same leaf"
        );
    }

    #[test]
    fn a_delete_pending_or_foreign_identity_read_back_is_created_unverified() {
        for (label, facts) in [
            (
                "delete pending",
                Ok(HandleFacts::for_test(
                    7,
                    [4; 16],
                    1,
                    true,
                    FileSystemKind::Ntfs,
                    true,
                )),
            ),
            (
                "refs",
                Ok(HandleFacts::for_test(
                    7,
                    [4; 16],
                    1,
                    false,
                    FileSystemKind::Refs,
                    true,
                )),
            ),
        ] {
            let rig = Rig::new("copy-verify-facts");
            let mut seams = Seams {
                verify_read: Some(Box::new(move |read| match read {
                    SyncFileRead::Present(present) => {
                        SyncFileRead::Present(present.with_physical_for_test(facts))
                    }
                    other => other,
                })),
                ..Seams::none()
            };

            assert_eq!(
                rig.publish_with(&mut seams),
                PublishOutcome::CreatedUnverified,
                "{label}"
            );
            assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
        }
    }

    #[test]
    fn a_failed_caller_check_on_the_read_back_bytes_is_created_unverified() {
        let rig = Rig::new("copy-crypto-fails");

        let outcome = rig.run_with(&mut || true, &mut |_| false, &mut Seams::none());

        assert_eq!(outcome, PublishOutcome::CreatedUnverified);
        assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
        assert!(!rig.staging_names());
    }

    // ---- the parent and its ancestors ------------------------------------------

    #[test]
    fn a_parent_replaced_by_a_junction_before_the_pin_is_refused_and_nothing_is_written() {
        let rig = Rig::new("copy-parent-junction");
        let dest = rig.dest.clone();
        let real = rig.dir.path().join("dest-real");
        let real_for_hook = real.clone();

        let mut seams = at(Stage::BeforePin, move |_| {
            fs::rename(&dest, &real_for_hook).unwrap();
            make_junction(&dest, &real_for_hook);
        });

        assert_eq!(
            rig.publish_with(&mut seams),
            not_published(NotPublishedReason::EvidenceChanged)
        );
        // Nothing was written through the junction.
        assert!(names(&real).is_empty());
        assert!(!rig.staging_names());
    }

    #[test]
    fn a_pinned_parent_cannot_be_renamed_or_deleted_while_publishing() {
        let rig = Rig::new("copy-parent-pinned");
        let dest = rig.dest.clone();
        let moved = rig.dir.path().join("dest-moved");
        let results: Rc<RefCell<ErrorCodes>> = Rc::default();
        let sink = Rc::clone(&results);

        let mut seams = at(Stage::BeforeRename, move |_| {
            let rename = fs::rename(&dest, &moved)
                .err()
                .and_then(|e| e.raw_os_error());
            let remove = fs::remove_dir(&dest).err().and_then(|e| e.raw_os_error());
            let remove_all = fs::remove_dir_all(&dest)
                .err()
                .and_then(|e| e.raw_os_error());

            *sink.borrow_mut() = vec![
                ("rename", rename),
                ("remove", remove),
                ("remove_all", remove_all),
            ];
        });

        assert_eq!(rig.publish_with(&mut seams), PublishOutcome::Published);

        for (label, error) in results.borrow().iter() {
            eprintln!("OBSERVED pinned parent {label} during publish: os error {error:?}");

            assert!(error.is_some(), "{label} unexpectedly succeeded");
        }

        assert_eq!(fs::read(&rig.target_path).unwrap(), SOURCE);
    }

    #[test]
    fn a_grandparent_rename_during_publication_never_reports_success() {
        let dir = scratch("copy-grandparent");
        let outer = dir.path().join("outer");
        let dest = outer.join("dest");
        let vault = dir.path().join("vault");

        fs::create_dir_all(&dest).unwrap();
        fs::create_dir(&vault).unwrap();

        let primary_path = vault.join("primary.lvault");

        fs::write(&primary_path, SOURCE).unwrap();

        let primary = File::open(&primary_path).unwrap();
        let primary_facts = facts_of(&primary).unwrap();
        let target_path = dest.join("copy.lvault");
        let target = SyncFileTarget::from_path(&target_path).unwrap();
        let moved = dir.path().join("outer-moved");
        let succeeded = Rc::new(Cell::new(None));
        let flag = Rc::clone(&succeeded);
        let (from, to) = (outer.clone(), moved.clone());

        let mut seams = at(Stage::BeforeRename, move |_| {
            let result = fs::rename(&from, &to);

            if let Err(error) = &result {
                eprintln!(
                    "OBSERVED grandparent rename at BeforeRename: FAILED kind={:?} os={:?}",
                    error.kind(),
                    error.raw_os_error()
                );
            } else {
                eprintln!("OBSERVED grandparent rename at BeforeRename: SUCCEEDED");
            }

            flag.set(Some(result.is_ok()));
        });

        let outcome = publish_new_copy(
            &PublishRequest {
                target: &target,
                source: SOURCE,
                primary: &primary_facts,
            },
            &mut || true,
            &mut |_| true,
            &mut seams,
        );

        match succeeded.get().expect("the hook ran") {
            // Normal publication: the ancestor could not move.
            false => {
                assert_eq!(outcome, PublishOutcome::Published);
                assert_eq!(fs::read(&target_path).unwrap(), SOURCE);
            }
            // The file landed inside the moved, pinned directory object; nothing at
            // the old path; and the path read means this can never be success.
            true => {
                assert_eq!(outcome, PublishOutcome::CreatedUnverified);
                assert!(!outer.exists());
                assert_eq!(
                    fs::read(moved.join("dest").join("copy.lvault")).unwrap(),
                    SOURCE
                );
            }
        }
    }

    // ---- redaction --------------------------------------------------------------

    #[test]
    fn outcomes_reveal_no_path_identifier_or_content() {
        let dir = scratch(&format!("copy-redact-{}", &LEAK_MARK[8..12]));
        let leaky = dir.path().join(format!("{LEAK_MARK}.lvault"));
        let target = SyncFileTarget::from_path(&leaky).unwrap();
        let facts = HandleFacts::for_test(
            0xDEAD_BEEF,
            [0xAB; 16],
            1,
            false,
            FileSystemKind::Ntfs,
            true,
        );
        let outcome = publish_new_copy(
            &PublishRequest {
                target: &target,
                source: LEAK_MARK.as_bytes(),
                primary: &facts,
            },
            &mut || true,
            &mut |_| true,
            &mut Seams::none(),
        );

        let shown = [
            format!("{outcome:?}"),
            format!("{:?}", PublishOutcome::Published),
            format!("{:?}", PublishOutcome::PublicationUnknown),
            format!("{:?}", PublishOutcome::CreatedUnverified),
            format!("{:?}", not_published(NotPublishedReason::RenameRefused)),
            format!("{:?}", NotPublishedReason::TargetAppeared),
            format!("{:?}", Stage::BeforeRename),
        ];

        for output in &shown {
            for needle in [
                LEAK_MARK,
                ".qa-local",
                "DEADBEEF",
                "deadbeef",
                "abab",
                "ABAB",
                ".lvault",
            ] {
                assert!(!output.contains(needle), "leaks {needle:?}: {output}");
            }
        }
    }
}
