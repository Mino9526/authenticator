import { sanitizeEntry } from "./totp.js";
import { loadEntriesFromStore, saveEntriesToStore } from "./tauri.js";

function readDesktopEntries(entries) {
  if (!Array.isArray(entries)) {
    throw new Error("桌面端返回了无效的数据。");
  }

  return entries.map((entry) => sanitizeEntry(entry));
}

export async function loadEntries() {
  return readDesktopEntries(await loadEntriesFromStore());
}

export async function saveEntries(entries) {
  return readDesktopEntries(await saveEntriesToStore(entries));
}
