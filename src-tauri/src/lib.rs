pub mod app_state;
pub mod commands;
pub mod crypto;
pub mod vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
