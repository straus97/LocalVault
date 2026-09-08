use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::{
    app_state::AppState,
    recent_vaults::{
        forget_recent_vault, load_recent_vaults,
        remember_recent_vault as remember_recent_vault_path, RecentVaultError,
    },
};

use super::CommandError;

const CONFIG_FILE_NAME: &str = "recent-vaults.json";

fn recent_config_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(CONFIG_FILE_NAME))
        .map_err(|_| {
            CommandError::new(
                "recentVaultConfigFailed",
                "Recent vault configuration is unavailable.",
            )
        })
}

fn map_recent_error(error: RecentVaultError) -> CommandError {
    match error {
        RecentVaultError::InvalidVaultPath => CommandError::new(
            "invalidRecentVaultPath",
            "The recent vault path is invalid.",
        ),
        _ => CommandError::new(
            "recentVaultConfigFailed",
            "Recent vault configuration is unavailable.",
        ),
    }
}

#[tauri::command]
pub fn get_recent_vaults(app: AppHandle) -> Result<Vec<String>, CommandError> {
    let config_path = recent_config_path(&app)?;

    load_recent_vaults(&config_path).map_err(map_recent_error)
}

#[tauri::command]
pub fn remember_recent_vault(path: String, app: AppHandle) -> Result<Vec<String>, CommandError> {
    let config_path = recent_config_path(&app)?;

    let vault_path = PathBuf::from(path);

    remember_recent_vault_path(&config_path, &vault_path).map_err(map_recent_error)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteVaultResult {
    pub recent_vaults: Vec<String>,
    pub internal_backup_removed: bool,
}

#[tauri::command]
pub fn delete_closed_vault(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DeleteVaultResult, CommandError> {
    /*
     * Resolve the convenience-config location before deleting
     * anything. Failure here must leave the vault untouched.
     */
    let config_path = recent_config_path(&app)?;

    let outcome = state
        .delete_closed_vault(PathBuf::from(path))
        .map_err(CommandError::from)?;

    /*
     * Recent-vault metadata is convenience-only. Once the
     * actual vault has been deleted, a config write failure
     * must not turn that successful destructive operation into
     * a misleading "nothing happened" error.
     *
     * load_recent_vaults already filters missing files, so the
     * fallback still returns a safe visible list.
     */
    let recent_vaults = forget_recent_vault(&config_path, &outcome.canonical_path)
        .or_else(|_| load_recent_vaults(&config_path))
        .unwrap_or_default();

    Ok(DeleteVaultResult {
        recent_vaults,
        internal_backup_removed: outcome.internal_backup_removed,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_recent_path_has_stable_error() {
        let error = map_recent_error(RecentVaultError::InvalidVaultPath);

        assert_eq!(error.code, "invalidRecentVaultPath");
    }

    #[test]
    fn config_failure_has_stable_non_sensitive_error() {
        let error = map_recent_error(RecentVaultError::UnsupportedVersion);

        assert_eq!(error.code, "recentVaultConfigFailed");

        assert_eq!(error.message, "Recent vault configuration is unavailable.");
    }
}
