#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri_plugin_sql::{Migration, MigrationKind};

fn main() {
  let migrations = vec![Migration {
    version: 1,
    description: "create_entries_table",
    sql: "
      CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        account TEXT NOT NULL,
        issuer TEXT NOT NULL,
        secret TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        digits INTEGER NOT NULL,
        period INTEGER NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        createdAt INTEGER NOT NULL,
        updatedAt INTEGER NOT NULL
      );
    ",
    kind: MigrationKind::Up,
  }];

  tauri::Builder::default()
    .plugin(tauri_plugin_opener::init())
    .plugin(
      tauri_plugin_sql::Builder::default()
        .add_migrations("sqlite:authenticator.sqlite", migrations)
        .build(),
    )
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
