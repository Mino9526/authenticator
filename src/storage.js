import { sanitizePublicEntry } from "./totp.js";
import {
  deleteVaultEntry,
  generateVaultCodes,
  listVaultEntries,
  upsertVaultEntry,
} from "./tauri.js";

function readPublicEntries(entries) {
  if (!Array.isArray(entries)) {
    throw new Error("桌面端返回了无效的数据。");
  }
  return entries.map((entry) => sanitizePublicEntry(entry));
}

export async function loadEntries() {
  return readPublicEntries(await listVaultEntries());
}

export async function saveEntry(entry) {
  return sanitizePublicEntry(await upsertVaultEntry(entry));
}

export async function removeEntry(id) {
  await deleteVaultEntry(id);
}

export async function loadCodes() {
  const codes = await generateVaultCodes();
  if (!Array.isArray(codes)) {
    throw new Error("桌面端返回了无效的验证码数据。");
  }
  return codes;
}
