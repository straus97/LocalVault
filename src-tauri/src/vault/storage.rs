use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use thiserror::Error;
use uuid::Uuid;

use localvault_core::vault::format::{VaultEnvelope, VaultError};

pub const MAX_VAULT_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("vault path is invalid")]
    InvalidPath,

    #[error("vault file does not exist")]
    NotFound,

    #[error("vault path points to a symbolic link")]
    SymlinkPath,

    #[error("vault path is not a regular file")]
    NotRegularFile,

    #[error("destination already exists")]
    DestinationExists,

    #[error("backup path must differ from the vault path")]
    BackupPathMatchesVault,

    #[error("vault file is empty")]
    EmptyFile,

    #[error("vault file exceeds the maximum supported size")]
    TooLarge,

    #[error("vault serialization failed")]
    Serialization(#[source] serde_json::Error),

    #[error("vault deserialization failed")]
    Deserialization(#[source] serde_json::Error),

    #[error("vault envelope validation failed")]
    InvalidEnvelope(#[source] VaultError),

    #[error("vault filesystem operation failed")]
    Io(#[source] io::Error),
}

fn parent_directory(path: &Path) -> Result<&Path, StorageError> {
    let parent = path.parent().ok_or(StorageError::InvalidPath)?;

    if parent.as_os_str().is_empty() {
        return Err(StorageError::InvalidPath);
    }

    Ok(parent)
}

fn reject_unsafe_existing_destination(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StorageError::SymlinkPath);
            }

            if !metadata.is_file() {
                return Err(StorageError::NotRegularFile);
            }

            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn read_file_bounded(path: &Path) -> Result<Vec<u8>, StorageError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound);
        }
        Err(error) => return Err(StorageError::Io(error)),
    };

    if metadata.file_type().is_symlink() {
        return Err(StorageError::SymlinkPath);
    }

    if !metadata.is_file() {
        return Err(StorageError::NotRegularFile);
    }

    if metadata.len() == 0 {
        return Err(StorageError::EmptyFile);
    }

    if metadata.len() > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    let file = File::open(path).map_err(StorageError::Io)?;

    let mut bytes = Vec::with_capacity(metadata.len() as usize);

    file.take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(StorageError::Io)?;

    if bytes.is_empty() {
        return Err(StorageError::EmptyFile);
    }

    if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    Ok(bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() {
        return Err(StorageError::EmptyFile);
    }

    if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    let parent = parent_directory(path)?;

    fs::create_dir_all(parent).map_err(StorageError::Io)?;

    reject_unsafe_existing_destination(path)?;

    let mut file = AtomicWriteFile::open(path).map_err(StorageError::Io)?;

    file.write_all(bytes).map_err(StorageError::Io)?;
    file.flush().map_err(StorageError::Io)?;
    file.sync_all().map_err(StorageError::Io)?;

    file.commit().map_err(StorageError::Io)?;

    Ok(())
}

pub(crate) fn ensure_distinct_paths(source: &Path, destination: &Path) -> Result<(), StorageError> {
    if source == destination {
        return Err(StorageError::BackupPathMatchesVault);
    }

    let source_canonical = fs::canonicalize(source).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            StorageError::NotFound
        } else {
            StorageError::Io(error)
        }
    })?;

    match fs::canonicalize(destination) {
        Ok(destination_canonical) => {
            if source_canonical == destination_canonical {
                return Err(StorageError::BackupPathMatchesVault);
            }

            Ok(())
        }

        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),

        Err(error) => Err(StorageError::Io(error)),
    }
}

fn reject_existing_new_destination(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StorageError::SymlinkPath);
            }

            if !metadata.is_file() {
                return Err(StorageError::NotRegularFile);
            }

            Err(StorageError::DestinationExists)
        }

        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),

        Err(error) => Err(StorageError::Io(error)),
    }
}

fn create_atomic_temp_file(destination: &Path) -> Result<(PathBuf, File), StorageError> {
    let parent = parent_directory(destination)?;

    let file_name = destination.file_name().ok_or(StorageError::InvalidPath)?;

    for _ in 0..16 {
        let mut temp_name = OsString::from(".");

        temp_name.push(file_name);

        temp_name.push(format!(".localvault-{}.tmp", Uuid::new_v4(),));

        let temp_path = parent.join(temp_name);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => {
                return Ok((temp_path, file));
            }

            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                continue;
            }

            Err(error) => {
                return Err(StorageError::Io(error));
            }
        }
    }

    Err(StorageError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate temporary backup file",
    )))
}

/// Publishes a fully written temporary file under `destination` without ever
/// replacing an existing destination.
///
/// The no-clobber guarantee comes from the publication primitive itself:
/// `fs::hard_link` (`link(2)` / `CreateHardLinkW`) fails with `AlreadyExists`
/// if `destination` exists at the moment of the call, so a file created by
/// another actor after any earlier existence check is never overwritten.
///
/// `fs::rename` must NOT be used here: on Windows it replaces an existing
/// destination (and on POSIX it always does).
///
/// There is deliberately no fallback. If the filesystem does not support hard
/// links (for example FAT/exFAT), publication fails closed with an error and
/// `destination` is left untouched.
///
/// On `Ok` the destination is published. Removing the temporary name afterwards
/// is best effort: if it fails, the vault is still correctly published and an
/// extra encrypted-bytes-only name for the same file may remain. It is never
/// reported as a failed create, and `destination` is never rolled back.
fn commit_new_temp_file(temp_path: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(temp_path, destination)?;

    let _ = fs::remove_file(temp_path);

    Ok(())
}

#[cfg(test)]
type BeforePublishHook = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
thread_local! {
    /// Test-only seam: runs once, on the calling thread, between the staged
    /// file being complete and its publication. Compiled out of release builds.
    static BEFORE_PUBLISH_HOOK: std::cell::RefCell<Option<BeforePublishHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_before_publish_hook(destination: &Path) {
    let hook = BEFORE_PUBLISH_HOOK.with(|cell| cell.borrow_mut().take());

    if let Some(hook) = hook {
        hook(destination);
    }
}

fn map_new_destination_commit_error(destination: &Path, original: io::Error) -> StorageError {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                StorageError::SymlinkPath
            } else if !metadata.is_file() {
                StorageError::NotRegularFile
            } else {
                StorageError::DestinationExists
            }
        }

        Err(error) if error.kind() == io::ErrorKind::NotFound => StorageError::Io(original),

        Err(error) => StorageError::Io(error),
    }
}

fn write_bytes_atomic_new(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() {
        return Err(StorageError::EmptyFile);
    }

    if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    let parent = parent_directory(path)?;

    fs::create_dir_all(parent).map_err(StorageError::Io)?;

    // Early, best-effort check that gives precise errors (symlink, directory,
    // already exists). It is NOT the safety guarantee: the destination may
    // appear after this point, and commit_new_temp_file refuses that case.
    reject_existing_new_destination(path)?;

    let (temp_path, mut temp_file) = create_atomic_temp_file(path)?;

    let result = (|| {
        temp_file.write_all(bytes).map_err(StorageError::Io)?;

        temp_file.flush().map_err(StorageError::Io)?;

        temp_file.sync_all().map_err(StorageError::Io)?;

        /*
         * Close the temporary file before publication so no handle
         * to it is held open while it is linked.
         */
        drop(temp_file);

        #[cfg(test)]
        run_before_publish_hook(path);

        commit_new_temp_file(&temp_path, path)
            .map_err(|error| map_new_destination_commit_error(path, error))?;

        Ok(())
    })();

    // Only the temporary file owned by this call is removed, and only when
    // publication did not happen. `destination` is never touched here, so a
    // competing file is never deleted and a published vault is never rolled back.
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

pub(crate) fn save_envelope_atomic_new(
    path: &Path,
    envelope: &VaultEnvelope,
) -> Result<(), StorageError> {
    envelope
        .validate_header()
        .map_err(StorageError::InvalidEnvelope)?;

    let bytes = serde_json::to_vec(envelope).map_err(StorageError::Serialization)?;

    write_bytes_atomic_new(path, &bytes)
}
pub fn save_envelope_atomic(path: &Path, envelope: &VaultEnvelope) -> Result<(), StorageError> {
    envelope
        .validate_header()
        .map_err(StorageError::InvalidEnvelope)?;

    let bytes = serde_json::to_vec(envelope).map_err(StorageError::Serialization)?;

    write_bytes_atomic(path, &bytes)
}

pub fn load_envelope(path: &Path) -> Result<VaultEnvelope, StorageError> {
    let bytes = read_file_bounded(path)?;

    let envelope: VaultEnvelope =
        serde_json::from_slice(&bytes).map_err(StorageError::Deserialization)?;

    envelope
        .validate_header()
        .map_err(StorageError::InvalidEnvelope)?;

    Ok(envelope)
}

pub fn save_envelope_atomic_with_backup(
    path: &Path,
    backup_path: &Path,
    envelope: &VaultEnvelope,
) -> Result<(), StorageError> {
    if path == backup_path {
        return Err(StorageError::BackupPathMatchesVault);
    }

    match fs::symlink_metadata(path) {
        Ok(_) => {
            let previous_bytes = read_file_bounded(path)?;

            write_bytes_atomic(backup_path, &previous_bytes)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(StorageError::Io(error)),
    }

    save_envelope_atomic(path, envelope)
}
#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use localvault_core::vault::format::{create_envelope, open_envelope, VAULT_MAGIC};

    const MASTER_PASSWORD: &str = "storage-layer-master-password-test-only";

    const TEST_PAYLOAD: &[u8] =
        br#"{"entries":[{"site":"storage.example.test","password":"STORAGE_TEST_ONLY_SECRET"}]}"#;

    #[test]
    fn save_load_and_decrypt_round_trip_succeeds() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let loaded = load_envelope(&path).unwrap();

        let plaintext = open_envelope(MASTER_PASSWORD, &loaded).unwrap();

        assert_eq!(plaintext.as_slice(), TEST_PAYLOAD);
    }

    #[test]
    fn stored_file_contains_no_plaintext_secrets() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let raw = fs::read_to_string(&path).unwrap();

        assert!(raw.contains(VAULT_MAGIC));
        assert!(!raw.contains(MASTER_PASSWORD));
        assert!(!raw.contains("STORAGE_TEST_ONLY_SECRET"));
        assert!(!raw.contains("storage.example.test"));
    }

    #[test]
    fn atomic_save_replaces_existing_vault() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");

        let first = create_envelope(MASTER_PASSWORD, b"first").unwrap();

        let second = create_envelope(MASTER_PASSWORD, b"second").unwrap();

        save_envelope_atomic(&path, &first).unwrap();
        save_envelope_atomic(&path, &second).unwrap();

        let loaded = load_envelope(&path).unwrap();

        assert_eq!(loaded, second);
        assert_ne!(loaded, first);
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let temp = tempdir().unwrap();

        let path = temp
            .path()
            .join("nested")
            .join("vault")
            .join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        assert!(path.is_file());
        assert!(load_envelope(&path).is_ok());
    }

    #[test]
    fn missing_file_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("missing.lvault");

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn empty_file_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("empty.lvault");

        fs::write(&path, []).unwrap();

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::EmptyFile)));
    }

    #[test]
    fn oversized_file_is_rejected_before_reading_contents() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("oversized.lvault");

        let file = File::create(&path).unwrap();
        file.set_len(MAX_VAULT_FILE_BYTES + 1).unwrap();

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::TooLarge)));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("malformed.lvault");

        fs::write(&path, b"{ definitely not valid json").unwrap();

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::Deserialization(_))));
    }

    #[test]
    fn truncated_vault_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("truncated.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() / 2);
        fs::write(&path, bytes).unwrap();

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::Deserialization(_))));
    }

    #[test]
    fn invalid_vault_header_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("invalid-header.lvault");

        let mut envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        envelope.magic = "NOT-LOCALVAULT".to_owned();

        let bytes = serde_json::to_vec(&envelope).unwrap();
        fs::write(&path, bytes).unwrap();

        let result = load_envelope(&path);

        assert!(matches!(result, Err(StorageError::InvalidEnvelope(_))));
    }

    #[test]
    fn directory_path_is_rejected() {
        let temp = tempdir().unwrap();

        let result = load_envelope(temp.path());

        assert!(matches!(result, Err(StorageError::NotRegularFile)));
    }

    #[test]
    fn save_with_backup_preserves_previous_encrypted_vault() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("vault.lvault");
        let backup_path = temp.path().join("vault.lvault.backup");

        let first = create_envelope(MASTER_PASSWORD, b"first-version").unwrap();

        let second = create_envelope(MASTER_PASSWORD, b"second-version").unwrap();

        save_envelope_atomic(&path, &first).unwrap();

        save_envelope_atomic_with_backup(&path, &backup_path, &second).unwrap();

        let current = load_envelope(&path).unwrap();
        let backup = load_envelope(&backup_path).unwrap();

        let current_plaintext = open_envelope(MASTER_PASSWORD, &current).unwrap();

        let backup_plaintext = open_envelope(MASTER_PASSWORD, &backup).unwrap();

        assert_eq!(current_plaintext.as_slice(), b"second-version");

        assert_eq!(backup_plaintext.as_slice(), b"first-version");
    }

    #[test]
    fn failed_backup_does_not_modify_existing_vault() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let invalid_backup_path = temp.path().join("backup-directory");

        fs::create_dir(&invalid_backup_path).unwrap();

        let first = create_envelope(MASTER_PASSWORD, b"original").unwrap();

        let second = create_envelope(MASTER_PASSWORD, b"replacement").unwrap();

        save_envelope_atomic(&path, &first).unwrap();

        let result = save_envelope_atomic_with_backup(&path, &invalid_backup_path, &second);

        assert!(matches!(result, Err(StorageError::NotRegularFile)));

        let still_current = load_envelope(&path).unwrap();

        let plaintext = open_envelope(MASTER_PASSWORD, &still_current).unwrap();

        assert_eq!(plaintext.as_slice(), b"original");
    }

    #[test]
    fn first_save_does_not_create_unnecessary_backup() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");
        let backup_path = temp.path().join("vault.lvault.backup");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic_with_backup(&path, &backup_path, &envelope).unwrap();

        assert!(path.is_file());
        assert!(!backup_path.exists());
    }

    #[test]
    fn vault_and_backup_paths_must_differ() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic(&path, &envelope).unwrap();

        let result = save_envelope_atomic_with_backup(&path, &path, &envelope);

        assert!(matches!(result, Err(StorageError::BackupPathMatchesVault)));

        assert!(load_envelope(&path).is_ok());
    }

    // -- No-clobber publication of NEW vault files --------------------------

    const COMPETING_BYTES: &[u8] = b"competing-actor-synthetic-bytes-not-a-vault";

    /// Unique, test-owned scratch directory under the repository's
    /// `.qa-local\vault-create-noclobber-tests\`. Dropping the returned guard
    /// removes only that directory.
    fn scratch_dir() -> tempfile::TempDir {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".qa-local")
            .join("vault-create-noclobber-tests");

        fs::create_dir_all(&base).unwrap();

        tempfile::Builder::new()
            .prefix("case-")
            .tempdir_in(&base)
            .unwrap()
    }

    fn set_before_publish_hook(hook: impl FnOnce(&Path) + 'static) {
        BEFORE_PUBLISH_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    fn leftover_temp_files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".tmp"))
            })
            .collect()
    }

    #[test]
    fn plain_rename_replaces_existing_destination_which_is_why_it_is_not_used() {
        let dir = scratch_dir();
        let staged = dir.path().join("staged.tmp");
        let destination = dir.path().join("vault.lvault");

        fs::write(&staged, b"new-bytes").unwrap();
        fs::write(&destination, COMPETING_BYTES).unwrap();

        // The root cause: rename silently clobbers an existing destination.
        fs::rename(&staged, &destination).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new-bytes");
    }

    #[test]
    fn hard_link_refuses_existing_destination_and_leaves_it_untouched() {
        let dir = scratch_dir();
        let staged = dir.path().join("staged.tmp");
        let destination = dir.path().join("vault.lvault");

        fs::write(&staged, b"new-bytes").unwrap();
        fs::write(&destination, COMPETING_BYTES).unwrap();

        let error = fs::hard_link(&staged, &destination).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), COMPETING_BYTES);
    }

    #[test]
    fn commit_new_temp_file_publishes_and_removes_only_the_temp_name() {
        let dir = scratch_dir();
        let staged = dir.path().join(".staged.tmp");
        let destination = dir.path().join("vault.lvault");

        fs::write(&staged, b"new-bytes").unwrap();

        commit_new_temp_file(&staged, &destination).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"new-bytes");
        assert!(!staged.exists());
    }

    #[test]
    fn commit_new_temp_file_refuses_existing_destination() {
        let dir = scratch_dir();
        let staged = dir.path().join(".staged.tmp");
        let destination = dir.path().join("vault.lvault");

        fs::write(&staged, b"new-bytes").unwrap();
        fs::write(&destination, COMPETING_BYTES).unwrap();

        let error = commit_new_temp_file(&staged, &destination).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), COMPETING_BYTES);

        // Cleanup of the staged file is the caller's job on failure.
        assert_eq!(fs::read(&staged).unwrap(), b"new-bytes");
    }

    #[test]
    fn new_vault_creation_publishes_valid_encrypted_bytes() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic_new(&path, &envelope).unwrap();

        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec(&envelope).unwrap()
        );

        let loaded = load_envelope(&path).unwrap();
        let plaintext = open_envelope(MASTER_PASSWORD, &loaded).unwrap();

        assert_eq!(plaintext.as_slice(), TEST_PAYLOAD);
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn new_vault_creation_creates_missing_parent_directories() {
        let dir = scratch_dir();
        let path = dir.path().join("nested").join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        save_envelope_atomic_new(&path, &envelope).unwrap();

        assert!(load_envelope(&path).is_ok());
    }

    #[test]
    fn destination_existing_before_staging_is_refused_and_unchanged() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        fs::write(&path, COMPETING_BYTES).unwrap();

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let result = save_envelope_atomic_new(&path, &envelope);

        assert!(matches!(result, Err(StorageError::DestinationExists)));
        assert_eq!(fs::read(&path).unwrap(), COMPETING_BYTES);
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn destination_created_between_check_and_publish_is_not_clobbered() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        // Another actor creates the destination after the existence check and
        // after the new vault has been fully staged, immediately before publish.
        set_before_publish_hook(|destination| {
            assert!(!destination.exists());
            fs::write(destination, COMPETING_BYTES).unwrap();
        });

        let result = save_envelope_atomic_new(&path, &envelope);

        assert!(matches!(result, Err(StorageError::DestinationExists)));

        // Byte-for-byte unchanged, not deleted, and our temp file is cleaned up.
        assert_eq!(fs::read(&path).unwrap(), COMPETING_BYTES);
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn competing_file_survives_refused_publish_with_backup_untouched() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");
        let backup_path = dir.path().join("vault.lvault.backup");

        fs::write(&backup_path, b"unrelated-backup-bytes").unwrap();

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        set_before_publish_hook(|destination| {
            fs::write(destination, COMPETING_BYTES).unwrap();
        });

        let result = save_envelope_atomic_new(&path, &envelope);

        assert!(matches!(result, Err(StorageError::DestinationExists)));
        assert_eq!(fs::read(&path).unwrap(), COMPETING_BYTES);
        assert_eq!(fs::read(&backup_path).unwrap(), b"unrelated-backup-bytes");
    }

    #[test]
    fn competing_non_file_destination_is_refused_and_preserved() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        set_before_publish_hook(|destination| {
            fs::create_dir(destination).unwrap();
        });

        let result = save_envelope_atomic_new(&path, &envelope);

        assert!(matches!(result, Err(StorageError::NotRegularFile)));
        assert!(path.is_dir());
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn failed_publish_reports_error_leaves_no_destination_and_cleans_up() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        // Make publication fail for a reason other than an existing destination:
        // the staged file disappears before it can be linked.
        set_before_publish_hook(|destination| {
            for staged in leftover_temp_files(destination.parent().unwrap()) {
                fs::remove_file(staged).unwrap();
            }
        });

        let result = save_envelope_atomic_new(&path, &envelope);

        assert!(matches!(result, Err(StorageError::Io(_))));

        // A failed create must never leave a destination behind that could be
        // mistaken for a successful create.
        assert!(!path.exists());
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn independent_creations_in_one_directory_all_succeed_without_leftovers() {
        let dir = scratch_dir();

        let mut expected = Vec::new();

        for index in 0..3 {
            let path = dir.path().join(format!("vault-{index}.lvault"));
            let payload = format!("payload-{index}");

            let envelope = create_envelope(MASTER_PASSWORD, payload.as_bytes()).unwrap();

            save_envelope_atomic_new(&path, &envelope).unwrap();

            expected.push((path, payload));
        }

        for (path, payload) in expected {
            let loaded = load_envelope(&path).unwrap();
            let plaintext = open_envelope(MASTER_PASSWORD, &loaded).unwrap();

            assert_eq!(plaintext.as_slice(), payload.as_bytes());
        }

        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn second_creation_attempt_for_same_path_is_refused_and_first_is_unchanged() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let first = create_envelope(MASTER_PASSWORD, b"first-creation").unwrap();
        let second = create_envelope(MASTER_PASSWORD, b"second-creation").unwrap();

        save_envelope_atomic_new(&path, &first).unwrap();

        let result = save_envelope_atomic_new(&path, &second);

        assert!(matches!(result, Err(StorageError::DestinationExists)));
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec(&first).unwrap()
        );
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn concurrent_creations_for_same_path_have_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        const ATTEMPTS: usize = 4;

        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        let barrier = Arc::new(Barrier::new(ATTEMPTS));

        let handles: Vec<_> = (0..ATTEMPTS)
            .map(|index| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);

                std::thread::spawn(move || {
                    let envelope =
                        create_envelope(MASTER_PASSWORD, format!("attempt-{index}").as_bytes())
                            .unwrap();

                    let bytes = serde_json::to_vec(&envelope).unwrap();

                    barrier.wait();

                    (save_envelope_atomic_new(&path, &envelope), bytes)
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let winners: Vec<_> = outcomes.iter().filter(|(r, _)| r.is_ok()).collect();

        assert_eq!(winners.len(), 1);

        for (result, _) in outcomes.iter().filter(|(r, _)| r.is_err()) {
            assert!(matches!(result, Err(StorageError::DestinationExists)));
        }

        // The published file is exactly the winner's bytes, never a mix.
        assert_eq!(fs::read(&path).unwrap(), winners[0].1);
        assert!(load_envelope(&path).is_ok());
        assert!(leftover_temp_files(dir.path()).is_empty());
    }

    #[test]
    fn no_clobber_errors_do_not_leak_paths_or_secrets() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");

        fs::write(&path, COMPETING_BYTES).unwrap();

        let envelope = create_envelope(MASTER_PASSWORD, TEST_PAYLOAD).unwrap();

        let error = save_envelope_atomic_new(&path, &envelope).unwrap_err();

        let rendered = format!("{error} {error:?}");

        assert!(!rendered.contains(MASTER_PASSWORD));
        assert!(!rendered.contains("STORAGE_TEST_ONLY_SECRET"));
        assert!(!rendered.contains("vault.lvault"));
        assert!(!rendered.contains(&*dir.path().to_string_lossy()));
    }

    #[test]
    fn save_with_backup_still_replaces_existing_vault_and_keeps_previous_as_backup() {
        let dir = scratch_dir();
        let path = dir.path().join("vault.lvault");
        let backup_path = dir.path().join("vault.lvault.backup");

        let first = create_envelope(MASTER_PASSWORD, b"first-version").unwrap();
        let second = create_envelope(MASTER_PASSWORD, b"second-version").unwrap();

        save_envelope_atomic_new(&path, &first).unwrap();
        save_envelope_atomic_with_backup(&path, &backup_path, &second).unwrap();

        // Intentional replacement semantics are unchanged.
        assert_eq!(load_envelope(&path).unwrap(), second);
        assert_eq!(load_envelope(&backup_path).unwrap(), first);
    }
}
