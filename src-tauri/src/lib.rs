use std::{thread, time::Duration};

use tauri::{AppHandle, Emitter, Manager};

const AUTO_LOCK_WATCH_INTERVAL: Duration = Duration::from_secs(1);

const AUTO_LOCK_EVENT: &str = "vault-session-expired";

fn start_auto_lock_watcher(app: AppHandle) {
    let _auto_lock_thread = thread::Builder::new()
        .name("localvault-auto-lock".to_owned())
        .spawn(move || loop {
            thread::sleep(AUTO_LOCK_WATCH_INTERVAL);

            let should_emit = {
                let state = app.state::<app_state::AppState>();

                state.expire_inactive_session().unwrap_or(true)
            };

            if should_emit {
                let clipboard = app.state::<secure_clipboard::SecureClipboard>();

                clipboard.clear_owned_best_effort();

                let _ = app.emit(AUTO_LOCK_EVENT, ());
            }
        })
        .expect("failed to start LocalVault auto-lock watcher");
}
pub mod app_state;
pub mod commands;
pub mod crypto;
mod password_generator;
mod recent_vaults;
mod secure_clipboard;
pub mod vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(secure_clipboard::SecureClipboard::default())
        .manage(app_state::AppState::default())
        .setup(|app| {
            start_auto_lock_watcher(app.handle().clone());

            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                let clipboard = window.state::<secure_clipboard::SecureClipboard>();

                clipboard.clear_owned_best_effort();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::touch_vault_activity,
            commands::backups::create_vault_backup,
            commands::backups::restore_vault_backup,
            commands::entries::list_entries,
            commands::entries::get_entry,
            commands::entries::copy_entry_password,
            commands::entries::create_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::categories::list_categories,
            commands::categories::get_category,
            commands::categories::create_category,
            commands::categories::update_category,
            commands::categories::delete_category,
            commands::passwords::generate_password,
            commands::recent_vaults::get_recent_vaults,
            commands::recent_vaults::remember_recent_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
