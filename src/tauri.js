import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { openUrl } from "@tauri-apps/plugin-opener";
import { isSafeHttpUrl } from "./totp.js";

export function getErrorMessage(error) {
  if (typeof error === "string") {
    return error.replace(/^[A-Z_]+:\s*/, "");
  }
  if (error instanceof Error) {
    return error.message.replace(/^[A-Z_]+:\s*/, "");
  }
  return String(error || "发生未知错误。");
}

export function isVaultLockedError(error) {
  return String(error instanceof Error ? error.message : error).startsWith("VAULT_LOCKED:");
}

export function getVaultStatus() {
  return invoke("vault_status");
}

export function initializeVault(password) {
  return invoke("initialize_vault", { password });
}

export function unlockVault(password) {
  return invoke("unlock_vault", { password });
}

export function changeMasterPassword(currentPassword, newPassword) {
  return invoke("change_master_password", { currentPassword, newPassword });
}

export function lockVault() {
  return invoke("lock_vault");
}

export function touchVault() {
  return invoke("touch_vault");
}

export function listVaultEntries() {
  return invoke("list_entries");
}

export function upsertVaultEntry(entry) {
  return invoke("upsert_entry", { entry });
}

export function deleteVaultEntry(id) {
  return invoke("delete_entry", { id });
}

export function generateVaultCodes() {
  return invoke("generate_codes");
}

export function createEncryptedBackup(password) {
  return invoke("export_encrypted_backup", { password });
}

export function restoreBackup(backupText, password = null) {
  return invoke("import_backup", { backupText, password });
}

export async function openExternalUrl(url) {
  const normalizedUrl = String(url || "").trim();
  if (!isSafeHttpUrl(normalizedUrl)) {
    throw new Error("网址只支持 http 或 https。");
  }

  try {
    await openUrl(normalizedUrl);
  } catch {
    throw new Error("无法打开网址。");
  }
}

export async function exportBackupWithDialog(suggestedName, text) {
  const targetPath = await save({
    title: "导出加密备份",
    defaultPath: suggestedName,
    filters: [
      {
        name: "TOTP 加密备份",
        extensions: ["totp"],
      },
    ],
  });

  if (!targetPath) {
    return "cancelled";
  }

  await writeTextFile(targetPath, text);
  return "saved";
}
