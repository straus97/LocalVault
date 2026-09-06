use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const CONFIG_VERSION: u16 = 1;
const MAX_RECENT_VAULTS: usize = 5;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum RecentVaultError {
    #[error("recent vault path is invalid")]
    InvalidVaultPath,

    #[error("recent vault configuration file is invalid")]
    InvalidConfigFile,

    #[error("recent vault configuration is too large")]
    ConfigTooLarge,

    #[error("unsupported recent vault configuration version")]
    UnsupportedVersion,

    #[error("failed to access recent vault configuration")]
    Io(#[source] std::io::Error),

    #[error("failed to serialize recent vault configuration")]
    Serialization(#[source] serde_json::Error),

    #[error("failed to deserialize recent vault configuration")]
    Deserialization(#[source] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct RecentVaultConfig {
    version: u16,
    paths: Vec<String>,
}

impl Default for RecentVaultConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            paths: Vec::new(),
        }
    }
}

fn path_strings_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        left.eq_ignore_ascii_case(right)
    }

    #[cfg(not(windows))]
    {
        left == right
    }
}

fn normalize_existing_vault_path(path: &Path) -> Result<String, RecentVaultError> {
    let has_vault_extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lvault"));

    if !has_vault_extension {
        return Err(RecentVaultError::InvalidVaultPath);
    }

    let metadata = fs::symlink_metadata(path).map_err(|_| RecentVaultError::InvalidVaultPath)?;

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RecentVaultError::InvalidVaultPath);
    }

    let canonical = fs::canonicalize(path).map_err(|_| RecentVaultError::InvalidVaultPath)?;

    canonical
        .into_os_string()
        .into_string()
        .map_err(|_| RecentVaultError::InvalidVaultPath)
}

fn read_config(config_path: &Path) -> Result<RecentVaultConfig, RecentVaultError> {
    let metadata = match fs::symlink_metadata(config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(RecentVaultConfig::default());
        }
        Err(error) => {
            return Err(RecentVaultError::Io(error));
        }
    };

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RecentVaultError::InvalidConfigFile);
    }

    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(RecentVaultError::ConfigTooLarge);
    }

    let bytes = fs::read(config_path).map_err(RecentVaultError::Io)?;

    let config: RecentVaultConfig =
        serde_json::from_slice(&bytes).map_err(RecentVaultError::Deserialization)?;

    if config.version != CONFIG_VERSION {
        return Err(RecentVaultError::UnsupportedVersion);
    }

    Ok(config)
}

fn write_config(config_path: &Path, paths: &[String]) -> Result<(), RecentVaultError> {
    if let Ok(metadata) = fs::symlink_metadata(config_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RecentVaultError::InvalidConfigFile);
        }
    }

    let parent = config_path
        .parent()
        .ok_or(RecentVaultError::InvalidConfigFile)?;

    fs::create_dir_all(parent).map_err(RecentVaultError::Io)?;

    let config = RecentVaultConfig {
        version: CONFIG_VERSION,
        paths: paths.to_vec(),
    };

    let bytes = serde_json::to_vec_pretty(&config).map_err(RecentVaultError::Serialization)?;

    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(RecentVaultError::ConfigTooLarge);
    }

    /*
     * This file contains convenience metadata only:
     * recent vault paths, never vault contents or passwords.
     *
     * A failed/truncated write can only lose the recent-list
     * convenience feature and cannot affect a .lvault file.
     */
    fs::write(config_path, bytes).map_err(RecentVaultError::Io)
}

pub fn load_recent_vaults(config_path: &Path) -> Result<Vec<String>, RecentVaultError> {
    let config = read_config(config_path)?;

    let mut result: Vec<String> = Vec::new();

    for raw_path in config.paths {
        let path = PathBuf::from(&raw_path);

        let Ok(normalized) = normalize_existing_vault_path(&path) else {
            continue;
        };

        if result
            .iter()
            .any(|existing| path_strings_equal(existing, &normalized))
        {
            continue;
        }

        result.push(normalized);

        if result.len() == MAX_RECENT_VAULTS {
            break;
        }
    }

    Ok(result)
}

pub fn remember_recent_vault(
    config_path: &Path,
    vault_path: &Path,
) -> Result<Vec<String>, RecentVaultError> {
    let normalized = normalize_existing_vault_path(vault_path)?;

    let mut paths = load_recent_vaults(config_path)?;

    paths.retain(|existing| !path_strings_equal(existing, &normalized));

    paths.insert(0, normalized);
    paths.truncate(MAX_RECENT_VAULTS);

    write_config(config_path, &paths)?;

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn create_vault_file(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);

        fs::write(&path, b"test-vault-file").unwrap();

        path
    }

    #[test]
    fn missing_config_returns_empty_list() {
        let temp = tempdir().unwrap();

        let config_path = temp.path().join("recent-vaults.json");

        let result = load_recent_vaults(&config_path).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn remember_persists_and_moves_existing_path_to_front() {
        let temp = tempdir().unwrap();

        let config_path = temp.path().join("config").join("recent-vaults.json");

        let first = create_vault_file(temp.path(), "first.lvault");

        let second = create_vault_file(temp.path(), "second.lvault");

        remember_recent_vault(&config_path, &first).unwrap();

        remember_recent_vault(&config_path, &second).unwrap();

        let paths = remember_recent_vault(&config_path, &first).unwrap();

        assert_eq!(paths.len(), 2);

        assert_eq!(
            paths[0],
            fs::canonicalize(&first).unwrap().to_str().unwrap()
        );

        assert_eq!(
            paths[1],
            fs::canonicalize(&second).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn recent_list_is_limited_to_five() {
        let temp = tempdir().unwrap();

        let config_path = temp.path().join("recent-vaults.json");

        for index in 0..7 {
            let path = create_vault_file(temp.path(), &format!("vault-{index}.lvault"));

            remember_recent_vault(&config_path, &path).unwrap();
        }

        let paths = load_recent_vaults(&config_path).unwrap();

        assert_eq!(paths.len(), 5);

        assert!(paths[0].ends_with("vault-6.lvault"));
    }

    #[test]
    fn missing_vault_paths_are_filtered_on_load() {
        let temp = tempdir().unwrap();

        let config_path = temp.path().join("recent-vaults.json");

        let existing = create_vault_file(temp.path(), "existing.lvault");

        let missing = temp.path().join("missing.lvault");

        let config = RecentVaultConfig {
            version: CONFIG_VERSION,
            paths: vec![
                missing.to_string_lossy().into_owned(),
                existing.to_string_lossy().into_owned(),
            ],
        };

        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

        let paths = load_recent_vaults(&config_path).unwrap();

        assert_eq!(paths.len(), 1);

        assert_eq!(
            paths[0],
            fs::canonicalize(existing).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn malformed_config_is_rejected() {
        let temp = tempdir().unwrap();

        let config_path = temp.path().join("recent-vaults.json");

        fs::write(&config_path, b"{not-json").unwrap();

        assert!(matches!(
            load_recent_vaults(&config_path),
            Err(RecentVaultError::Deserialization(_))
        ));
    }
}
