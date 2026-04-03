import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import Database from "@tauri-apps/plugin-sql";
import { openUrl } from "@tauri-apps/plugin-opener";
import { sanitizeEntry, validateEntry } from "./totp.js";

const DB_PATH = "sqlite:authenticator.sqlite";
const SELECT_ENTRIES_SQL = `
  SELECT id, label, account, issuer, secret, algorithm, digits, period, notes, website, createdAt, updatedAt
  FROM entries
  ORDER BY
    CASE WHEN issuer = '' THEN 1 ELSE 0 END,
    issuer COLLATE NOCASE,
    label COLLATE NOCASE,
    createdAt ASC
`;
const DELETE_ALL_SQL = "DELETE FROM entries";
const INSERT_ENTRY_SQL = `
  INSERT INTO entries (
    id, label, account, issuer, secret, algorithm, digits, period, notes, website, createdAt, updatedAt
  ) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
  )
`;

let dbPromise = null;

async function getDatabase() {
  dbPromise ??= Database.load(DB_PATH);
  return dbPromise;
}

function normalizeEntries(entries) {
  if (!Array.isArray(entries)) {
    throw new Error("要保存的数据格式无效。");
  }

  return entries.map((entry) => {
    const normalizedEntry = sanitizeEntry(entry);
    validateEntry(normalizedEntry);
    return normalizedEntry;
  });
}

export async function loadEntriesFromStore() {
  const db = await getDatabase();
  const rows = await db.select(SELECT_ENTRIES_SQL);
  return rows.map((row) => sanitizeEntry(row));
}

export async function saveEntriesToStore(entries) {
  const db = await getDatabase();
  const normalizedEntries = normalizeEntries(entries);

  await db.execute("BEGIN");
  try {
    await db.execute(DELETE_ALL_SQL);

    for (const entry of normalizedEntries) {
      await db.execute(INSERT_ENTRY_SQL, [
        entry.id,
        entry.label,
        entry.account,
        entry.issuer,
        entry.secret,
        entry.algorithm,
        entry.digits,
        entry.period,
        entry.notes,
        entry.website,
        entry.createdAt,
        entry.updatedAt,
      ]);
    }

    await db.execute("COMMIT");
  } catch (error) {
    try {
      await db.execute("ROLLBACK");
    } catch {
      // Ignore rollback errors and rethrow the original failure.
    }
    throw error;
  }

  return loadEntriesFromStore();
}

export async function openExternalUrl(url) {
  await openUrl(String(url || ""));
}

export async function exportBackupWithDialog(suggestedName, text) {
  const targetPath = await save({
    title: "导出 JSON 备份",
    defaultPath: suggestedName,
    filters: [
      {
        name: "JSON 文件",
        extensions: ["json"],
      },
    ],
  });

  if (!targetPath) {
    return "cancelled";
  }

  await writeTextFile(targetPath, text);
  return "saved";
}
