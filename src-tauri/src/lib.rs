pub mod app_state;
pub mod commands;
pub mod crypto;
mod recent_vaults;
pub mod vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::entries::list_entries,
            commands::entries::get_entry,
            commands::entries::create_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::categories::list_categories,
            commands::categories::get_category,
            commands::categories::create_category,
            commands::categories::update_category,
            commands::categories::delete_category,
            commands::recent_vaults::get_recent_vaults,
            commands::recent_vaults::remember_recent_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
