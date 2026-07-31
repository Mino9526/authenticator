#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let service = tauri::async_runtime::block_on(vault::VaultService::open(app.handle()))?;
            app.manage(service);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault::vault_status,
            vault::initialize_vault,
            vault::unlock_vault,
            vault::change_master_password,
            vault::lock_vault,
            vault::touch_vault,
            vault::list_entries,
            vault::upsert_entry,
            vault::delete_entry,
            vault::generate_codes,
            vault::export_encrypted_backup,
            vault::import_backup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
