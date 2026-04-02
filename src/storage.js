import { sanitizeEntry } from "./totp.js";

function readDesktopEntries(entries) {
  if (!Array.isArray(entries)) {
    throw new Error("桌面端返回了无效的数据。");
  }

  return entries.map((entry) => sanitizeEntry(entry));
}

export async function loadEntries() {
  if (!window.desktopApp?.loadEntries) {
    throw new Error("当前版本仅支持 Electron 桌面模式。");
  }

  return readDesktopEntries(await window.desktopApp.loadEntries());
}

export async function saveEntries(entries) {
  if (!window.desktopApp?.saveEntries) {
    throw new Error("当前版本仅支持 Electron 桌面模式。");
  }

  return readDesktopEntries(await window.desktopApp.saveEntries(entries));
}
