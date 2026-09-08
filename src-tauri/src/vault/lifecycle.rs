use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultLifecycleError {
    #[error("vault path is invalid")]
    InvalidPath,

    #[error("vault file was not found")]
    NotFound,

    #[error("vault path is a symbolic link")]
    SymlinkPath,

    #[error("vault path is not a regular file")]
    NotRegularFile,

    #[error("vault appears to be in use")]
    InUse,

    #[error("internal vault companion path is unsafe")]
    UnsafeInternalBackup,

    #[error("vault file deletion failed")]
    Io(#[source] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedVaultOutcome {
    pub canonical_path: PathBuf,
    pub internal_backup_removed: bool,
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());

    value.push(suffix);

    PathBuf::from(value)
}

fn has_vault_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lvault"))
}

fn validate_primary_vault(path: &Path) -> Result<(), VaultLifecycleError> {
    if !has_vault_extension(path) {
        return Err(VaultLifecycleError::InvalidPath);
    }

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            VaultLifecycleError::NotFound
        } else {
            VaultLifecycleError::Io(error)
        }
    })?;

    if metadata.file_type().is_symlink() {
        return Err(VaultLifecycleError::SymlinkPath);
    }

    if !metadata.is_file() {
        return Err(VaultLifecycleError::NotRegularFile);
    }

    Ok(())
}

fn acquire_delete_lock(vault_path: &Path) -> Result<File, VaultLifecycleError> {
    /*
     * LocalVault's .lvault.lock file is persistent by design.
     * Its mere existence does NOT mean that the vault is open.
     *
     * The active-session signal is the OS-level exclusive file
     * lock held by UnlockedVaultSession. Deletion must compete
     * for that exact same lock and keep it for the whole
     * destructive filesystem operation.
     */
    let lock_path = append_suffix(vault_path, ".lock");

    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(VaultLifecycleError::Io)?;

    match lock_file.try_lock() {
        Ok(()) => Ok(lock_file),

        Err(TryLockError::WouldBlock) => Err(VaultLifecycleError::InUse),

        Err(TryLockError::Error(error)) => Err(VaultLifecycleError::Io(error)),
    }
}

fn inspect_internal_backup(vault_path: &Path) -> Result<(PathBuf, bool), VaultLifecycleError> {
    let backup_path = append_suffix(vault_path, ".backup");

    match fs::symlink_metadata(&backup_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(VaultLifecycleError::UnsafeInternalBackup);
            }

            Ok((backup_path, true))
        }

        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((backup_path, false)),

        Err(error) => Err(VaultLifecycleError::Io(error)),
    }
}

pub fn delete_closed_vault_files(path: &Path) -> Result<DeletedVaultOutcome, VaultLifecycleError> {
    validate_primary_vault(path)?;

    let canonical_path = fs::canonicalize(path).map_err(VaultLifecycleError::Io)?;

    /*
     * Acquire the same OS-level coordination lock used by an
     * unlocked vault session. Keep this File alive until this
     * function returns.
     */
    let _delete_lock = acquire_delete_lock(&canonical_path)?;

    /*
     * Re-check the primary target after acquiring the lock.
     * This narrows the validation/delete TOCTOU window and
     * fails closed if the path became unsafe.
     */
    validate_primary_vault(&canonical_path)?;

    let (internal_backup_path, internal_backup_exists) = inspect_internal_backup(&canonical_path)?;

    /*
     * Delete the requested primary vault first. If this
     * operation fails, its internal backup is untouched.
     */
    fs::remove_file(&canonical_path).map_err(VaultLifecycleError::Io)?;

    /*
     * The adjacent .lvault.backup is LocalVault's internal
     * previous-version file. User-created *.lvbackup files
     * have a different name and are never addressed here.
     *
     * If cleanup fails after the primary was removed, report
     * that fact through the outcome instead of falsely
     * claiming that nothing was deleted.
     */
    let internal_backup_removed = if internal_backup_exists {
        fs::remove_file(internal_backup_path).is_ok()
    } else {
        true
    };

    /*
     * Do not remove .lvault.lock here. It contains no secrets
     * and is intentionally persistent. Removing its pathname
     * while releasing an OS lock would introduce a race where
     * another process could create/lock a different file.
     */
    Ok(DeletedVaultOutcome {
        canonical_path,
        internal_backup_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn delete_removes_vault_and_internal_backup_but_preserves_user_backup() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let internal = temp.path().join("vault.lvault.backup");

        let user_backup = temp.path().join("vault.lvbackup");

        fs::write(&vault, b"vault").unwrap();

        fs::write(&internal, b"internal backup").unwrap();

        fs::write(&user_backup, b"user backup").unwrap();

        let outcome = delete_closed_vault_files(&vault).unwrap();

        assert!(!vault.exists());

        assert!(!internal.exists());

        assert!(user_backup.exists());

        assert!(outcome.internal_backup_removed);
    }

    #[test]
    fn delete_refuses_non_vault_extension() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("notes.txt");

        fs::write(&path, b"keep").unwrap();

        let result = delete_closed_vault_files(&path);

        assert!(matches!(result, Err(VaultLifecycleError::InvalidPath)));

        assert!(path.exists());
    }

    #[test]
    fn delete_refuses_missing_vault() {
        let temp = tempdir().unwrap();

        let path = temp.path().join("missing.lvault");

        let result = delete_closed_vault_files(&path);

        assert!(matches!(result, Err(VaultLifecycleError::NotFound)));
    }

    #[test]
    fn delete_refuses_vault_with_active_os_lock() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        fs::write(&vault, b"vault").unwrap();

        let lock_path = append_suffix(&vault, ".lock");

        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .unwrap();

        lock_file.try_lock().unwrap();

        let result = delete_closed_vault_files(&vault);

        assert!(matches!(result, Err(VaultLifecycleError::InUse)));

        assert!(vault.exists());
    }

    #[test]
    fn stale_persistent_lock_file_does_not_block_closed_vault_deletion() {
        let temp = tempdir().unwrap();

        let vault = temp.path().join("vault.lvault");

        let lock_path = append_suffix(&vault, ".lock");

        fs::write(&vault, b"vault").unwrap();

        /*
         * Normal LocalVault sessions leave this coordination
         * file on disk after their File handle is dropped.
         */
        fs::write(&lock_path, b"").unwrap();

        let outcome = delete_closed_vault_files(&vault).unwrap();

        assert!(!vault.exists());

        assert!(lock_path.exists());

        assert!(outcome.internal_backup_removed);
    }
}
