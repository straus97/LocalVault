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

#[cfg(windows)]
fn commit_new_temp_file(temp_path: &Path, destination: &Path) -> io::Result<()> {
    /*
     * On Windows rename does not replace an existing target.
     * The operation stays inside one directory/filesystem.
     */
    fs::rename(temp_path, destination)
}

#[cfg(not(windows))]
fn commit_new_temp_file(temp_path: &Path, destination: &Path) -> io::Result<()> {
    /*
     * hard_link is an atomic no-clobber publication step:
     * it fails if destination already exists.
     */
    fs::hard_link(temp_path, destination)?;

    let _ = fs::remove_file(temp_path);

    Ok(())
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

    reject_existing_new_destination(path)?;

    let (temp_path, mut temp_file) = create_atomic_temp_file(path)?;

    let result = (|| {
        temp_file.write_all(bytes).map_err(StorageError::Io)?;

        temp_file.flush().map_err(StorageError::Io)?;

        temp_file.sync_all().map_err(StorageError::Io)?;

        /*
         * Close the temporary file before publication,
         * which is important for Windows rename semantics.
         */
        drop(temp_file);

        commit_new_temp_file(&temp_path, path)
            .map_err(|error| map_new_destination_commit_error(path, error))?;

        Ok(())
    })();

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
}
