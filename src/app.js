import {
  formatOtp,
  isEncryptedBackupText,
  isSafeHttpUrl,
  normalizeSecret,
  parseEntryKey,
  sanitizeEntry,
  validateEntry,
} from "./totp.js";
import {
  changeMasterPassword,
  createEncryptedBackup,
  exportBackupWithDialog,
  getErrorMessage,
  getVaultStatus,
  initializeVault,
  isVaultLockedError,
  lockVault,
  openExternalUrl,
  restoreBackup,
  touchVault,
  unlockVault,
} from "./tauri.js";
import { loadCodes, loadEntries, removeEntry, saveEntry } from "./storage.js";

const entryCount = document.querySelector("#entry-count");
const entriesGrid = document.querySelector("#entries-grid");
const listPanel = document.querySelector(".list-panel");
const listScroll = document.querySelector(".list-scroll");
const toast = document.querySelector("#toast");
const fabAddButton = document.querySelector("#fab-add-button");
const topMenu = document.querySelector("#top-menu");
const topMenuButton = document.querySelector("#top-menu-button");
const exportButton = document.querySelector("#export-button");
const changePasswordButton = document.querySelector("#change-password-button");
const lockButton = document.querySelector("#lock-button");
const resetFormButton = document.querySelector("#reset-form-button");
const editorBackdrop = document.querySelector("#editor-backdrop");
const editorTitle = document.querySelector("#editor-title");
const quickImportSection = document.querySelector("#quick-import-section");
const quickImportInput = document.querySelector("#quick-import-input");
const quickImportButton = document.querySelector("#quick-import-button");
const importFileInput = document.querySelector("#import-file-input");
const confirmBackdrop = document.querySelector("#confirm-backdrop");
const confirmTitle = document.querySelector("#confirm-title");
const confirmMessage = document.querySelector("#confirm-message");
const confirmCancelButton = document.querySelector("#confirm-cancel-button");
const confirmAcceptButton = document.querySelector("#confirm-accept-button");
const passwordBackdrop = document.querySelector("#password-backdrop");
const passwordDialogTitle = document.querySelector("#password-dialog-title");
const passwordDialogMessage = document.querySelector("#password-dialog-message");
const passwordDialogForm = document.querySelector("#password-dialog-form");
const passwordDialogInput = document.querySelector("#password-dialog-input");
const passwordDialogConfirmGroup = document.querySelector("#password-dialog-confirm-group");
const passwordDialogConfirmInput = document.querySelector("#password-dialog-confirm-input");
const passwordDialogError = document.querySelector("#password-dialog-error");
const passwordDialogCancel = document.querySelector("#password-dialog-cancel");
const passwordDialogAccept = document.querySelector("#password-dialog-accept");
const vaultGate = document.querySelector("#vault-gate");
const vaultForm = document.querySelector("#vault-form");
const vaultTitle = document.querySelector("#vault-title");
const vaultDescription = document.querySelector("#vault-description");
const vaultMigrationNotice = document.querySelector("#vault-migration-notice");
const vaultPasswordInput = document.querySelector("#vault-password-input");
const vaultConfirmGroup = document.querySelector("#vault-confirm-group");
const vaultConfirmInput = document.querySelector("#vault-confirm-input");
const vaultError = document.querySelector("#vault-error");
const vaultSubmitButton = document.querySelector("#vault-submit-button");
const template = document.querySelector("#entry-template");
const entryForm = document.querySelector("#entry-form");

const entryFields = {
  id: document.querySelector("#entry-id"),
  label: document.querySelector("#label-input"),
  account: document.querySelector("#account-input"),
  issuer: document.querySelector("#issuer-input"),
  secret: document.querySelector("#secret-input"),
  algorithm: document.querySelector("#algorithm-input"),
  digits: document.querySelector("#digits-input"),
  period: document.querySelector("#period-input"),
  website: document.querySelector("#website-input"),
  notes: document.querySelector("#notes-input"),
};

const state = {
  entries: [],
  codes: new Map(),
  entryNodes: new Map(),
  unlocked: false,
  vaultMode: "unlock",
  autoLockSeconds: 300,
};

let toastTimer;
let clipboardClearTimer;
let confirmResolver = null;
let passwordDialogResolver = null;
let passwordDialogOptions = null;
let activeMenuShell = null;
let activeMenuState = null;
let editorCloseTimer = null;
let lastVaultTouch = 0;
let refreshInFlight = false;

const EDITOR_TRANSITION_MS = 220;
const CLIPBOARD_CLEAR_MS = 30_000;
const MAX_IMPORT_BYTES = 10 * 1024 * 1024;

function setStatus(message, type = "") {
  clearTimeout(toastTimer);
  if (!message) {
    toast.textContent = "";
    toast.className = "toast";
    return;
  }

  toast.textContent = message;
  toast.className = `toast visible ${type}`.trim();
  toastTimer = window.setTimeout(() => {
    toast.className = "toast";
  }, type === "error" ? 5000 : 2800);
}

function updateMeta() {
  entryCount.textContent = String(state.entries.length);
}

function updateListFadeState() {
  const maxScrollTop = listScroll.scrollHeight - listScroll.clientHeight;
  const canScroll = maxScrollTop > 1;
  listPanel.classList.toggle("has-top-fade", canScroll && listScroll.scrollTop > 1);
  listPanel.classList.toggle("has-bottom-fade", canScroll && listScroll.scrollTop < maxScrollTop - 1);
}

function syncOverlayState() {
  const hasOverlay =
    editorBackdrop.classList.contains("open") ||
    editorBackdrop.classList.contains("closing") ||
    confirmBackdrop.classList.contains("open") ||
    passwordBackdrop.classList.contains("open");
  document.body.classList.toggle("overlay-open", hasOverlay);
}

function closeAllMenus() {
  for (const menuShell of document.querySelectorAll(".entry-menu.open, .top-menu.open")) {
    menuShell.classList.remove("open");
    menuShell.querySelector(".menu-button, .top-menu-button")?.setAttribute("aria-expanded", "false");
  }
  activeMenuShell = null;
  activeMenuState = null;
}

function closeActiveMenu() {
  closeAllMenus();
}

function handleMenuWheel() {
  if (activeMenuShell) {
    closeActiveMenu();
  }
}

function positionMenuPanel(menuShell) {
  const trigger = menuShell.querySelector(".menu-button, .top-menu-button");
  const panel = menuShell.querySelector(".entry-menu-panel, .top-menu-panel");
  if (!trigger || !panel) {
    return;
  }

  const triggerRect = trigger.getBoundingClientRect();
  const panelRect = panel.getBoundingClientRect();
  const spacing = 12;
  let left = Math.min(triggerRect.right - panelRect.width, window.innerWidth - panelRect.width - spacing);
  left = Math.max(spacing, left);
  let top = triggerRect.bottom + 8;
  if (top + panelRect.height > window.innerHeight - spacing) {
    top = triggerRect.top - panelRect.height - 8;
  }
  panel.style.left = `${left}px`;
  panel.style.top = `${Math.max(spacing, top)}px`;
}

function openMenu(menuShell, menuState) {
  closeAllMenus();
  menuShell.classList.add("open");
  menuShell.querySelector(".menu-button, .top-menu-button")?.setAttribute("aria-expanded", "true");
  activeMenuShell = menuShell;
  activeMenuState = menuState;
  requestAnimationFrame(() => {
    if (activeMenuShell === menuShell) {
      positionMenuPanel(menuShell);
    }
  });
}

function toggleEntryMenu(menuShell, menuState) {
  if (menuShell.classList.contains("open")) {
    closeAllMenus();
    return;
  }
  openMenu(menuShell, menuState);
}

function setSecretFieldMode(mode, secret = "") {
  const editing = mode === "edit";
  const imported = mode === "import";
  entryFields.secret.value = editing ? "" : secret;
  entryFields.secret.readOnly = editing || imported;
  entryFields.secret.required = !editing;
  entryFields.secret.toggleAttribute("data-locked", editing || imported);
  entryFields.secret.placeholder = editing ? "已加密保存，编辑时不会显示" : "Base32 密钥";
}

function setQuickImportLocked(locked) {
  quickImportInput.readOnly = locked;
  quickImportButton.disabled = locked;
}

function setQuickImportVisible(visible) {
  quickImportSection.classList.toggle("is-hidden", !visible);
}

function setResetButtonVisible(visible) {
  resetFormButton.classList.toggle("is-hidden", !visible);
}

function resetEntryForm() {
  entryForm.reset();
  entryFields.id.value = "";
  quickImportInput.value = "";
  setResetButtonVisible(true);
  setQuickImportVisible(true);
  setQuickImportLocked(false);
  setSecretFieldMode("new");
  entryFields.algorithm.value = "SHA1";
  entryFields.digits.value = "6";
  entryFields.period.value = "30";
  editorTitle.textContent = "添加条目";
}

function openEntryPanel({ reset = false } = {}) {
  window.clearTimeout(editorCloseTimer);
  editorBackdrop.classList.remove("closing");
  if (reset) {
    resetEntryForm();
  }
  editorBackdrop.classList.add("open");
  editorBackdrop.setAttribute("aria-hidden", "false");
  closeActiveMenu();
  syncOverlayState();
}

function closeEntryPanel({ reset = true } = {}) {
  if (!editorBackdrop.classList.contains("open") && !editorBackdrop.classList.contains("closing")) {
    return;
  }
  window.clearTimeout(editorCloseTimer);
  if (document.activeElement instanceof HTMLElement) {
    document.activeElement.blur();
  }
  editorBackdrop.classList.remove("open");
  editorBackdrop.classList.add("closing");
  syncOverlayState();
  editorCloseTimer = window.setTimeout(() => {
    editorBackdrop.classList.remove("closing");
    editorBackdrop.setAttribute("aria-hidden", "true");
    if (reset) {
      resetEntryForm();
    }
    syncOverlayState();
  }, EDITOR_TRANSITION_MS);
}

function openConfirmDialog({ title, message, confirmLabel = "确认", cancelLabel = "取消" }) {
  return new Promise((resolve) => {
    if (confirmResolver) {
      confirmResolver(false);
    }
    confirmResolver = resolve;
    confirmTitle.textContent = title;
    confirmMessage.textContent = message;
    confirmAcceptButton.textContent = confirmLabel;
    confirmCancelButton.textContent = cancelLabel;
    confirmBackdrop.classList.add("open");
    confirmBackdrop.setAttribute("aria-hidden", "false");
    syncOverlayState();
    confirmCancelButton.focus();
  });
}

function closeConfirmDialog(confirmed) {
  confirmBackdrop.classList.remove("open");
  confirmBackdrop.setAttribute("aria-hidden", "true");
  syncOverlayState();
  if (confirmResolver) {
    const resolver = confirmResolver;
    confirmResolver = null;
    resolver(confirmed);
  }
}

function openPasswordDialog({
  title,
  message,
  confirmLabel,
  requireConfirmation = false,
  minimumLength = 0,
}) {
  return new Promise((resolve) => {
    if (passwordDialogResolver) {
      passwordDialogResolver(null);
    }
    passwordDialogResolver = resolve;
    passwordDialogOptions = { requireConfirmation, minimumLength };
    passwordDialogTitle.textContent = title;
    passwordDialogMessage.textContent = message;
    passwordDialogAccept.textContent = confirmLabel;
    passwordDialogConfirmGroup.classList.toggle("is-hidden", !requireConfirmation);
    passwordDialogInput.autocomplete = requireConfirmation ? "new-password" : "current-password";
    passwordDialogInput.value = "";
    passwordDialogConfirmInput.value = "";
    passwordDialogError.textContent = "";
    passwordBackdrop.classList.add("open");
    passwordBackdrop.setAttribute("aria-hidden", "false");
    syncOverlayState();
    requestAnimationFrame(() => passwordDialogInput.focus());
  });
}

function closePasswordDialog(result) {
  passwordBackdrop.classList.remove("open");
  passwordBackdrop.setAttribute("aria-hidden", "true");
  passwordDialogInput.value = "";
  passwordDialogConfirmInput.value = "";
  passwordDialogError.textContent = "";
  passwordDialogOptions = null;
  syncOverlayState();
  if (passwordDialogResolver) {
    const resolver = passwordDialogResolver;
    passwordDialogResolver = null;
    resolver(result);
  }
}

function fillEntryForm(entry, options = {}) {
  const mode = options.mode || "edit";
  entryFields.id.value = options.keepId === false ? "" : entry.id || "";
  entryFields.label.value = entry.label || "";
  entryFields.account.value = entry.account || "";
  entryFields.issuer.value = entry.issuer || "";
  entryFields.algorithm.value = entry.algorithm || "SHA1";
  entryFields.digits.value = String(entry.digits || 6);
  entryFields.period.value = String(entry.period || 30);
  entryFields.website.value = entry.website || "";
  entryFields.notes.value = entry.notes || "";
  editorTitle.textContent = mode === "import" ? "导入后编辑" : "编辑条目";
  setResetButtonVisible(mode === "import");
  setQuickImportVisible(mode === "import");
  setQuickImportLocked(mode !== "import");
  setSecretFieldMode(mode, entry.secret || "");
  if (mode !== "import") {
    quickImportInput.value = "";
  }
  openEntryPanel();
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
  } else {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.append(textarea);
    textarea.select();
    const success = document.execCommand("copy");
    textarea.remove();
    if (!success) {
      throw new Error("当前环境不支持复制到剪贴板。");
    }
  }

  window.clearTimeout(clipboardClearTimer);
  clipboardClearTimer = window.setTimeout(async () => {
    try {
      if (navigator.clipboard?.readText && (await navigator.clipboard.readText()) === text) {
        await navigator.clipboard.writeText("");
      }
    } catch {
      // Clipboard access can be revoked while the timer is pending.
    }
  }, CLIPBOARD_CLEAR_MS);
}

function sortEntries() {
  return [...state.entries].sort((left, right) => {
    const createdDiff = Number(left.createdAt || 0) - Number(right.createdAt || 0);
    return createdDiff || left.label.localeCompare(right.label, "zh-CN");
  });
}

function updateEntryCard(node, entry) {
  const codeState = state.codes.get(entry.id);
  const remaining = Number(codeState?.remaining || 0);
  const elapsedProgress = remaining > 0 ? 1 - remaining / entry.period : 1;
  const timerRing = node.querySelector(".entry-timer-ring");
  node.querySelector(".entry-code").textContent = codeState?.code ? formatOtp(codeState.code) : "------";
  node.querySelector(".entry-timer").textContent = codeState?.error
    ? "错误"
    : remaining > 0
      ? `${remaining}s`
      : "--";
  timerRing.style.setProperty("--timer-progress", String(elapsedProgress));
  timerRing.classList.toggle("is-error", Boolean(codeState?.error));
}

function updateEntryDisplays() {
  for (const entry of sortEntries()) {
    const node = state.entryNodes.get(entry.id);
    if (node) {
      updateEntryCard(node, entry);
    }
  }
}

function renderEntries() {
  const previousMenuState = activeMenuState?.kind === "entry" ? activeMenuState : null;
  if (previousMenuState) {
    activeMenuShell = null;
    activeMenuState = null;
  }
  entriesGrid.innerHTML = "";
  state.entryNodes = new Map();
  const visibleEntries = sortEntries();

  if (!visibleEntries.length) {
    const empty = document.createElement("div");
    empty.className = "status-box";
    empty.textContent = "没有可显示的条目。可点击右下角 + 或从加密备份恢复。";
    entriesGrid.append(empty);
    requestAnimationFrame(updateListFadeState);
    return;
  }

  for (const entry of visibleEntries) {
    const node = template.content.firstElementChild.cloneNode(true);
    node.dataset.entryId = entry.id;
    node.querySelector(".entry-label").textContent = entry.issuer || entry.label;
    node.querySelector(".entry-account").textContent = entry.account || entry.label;

    const notes = node.querySelector(".entry-notes");
    const extraInfo = [
      entry.algorithm !== "SHA1" ? entry.algorithm : "",
      entry.period !== 30 ? `${entry.period}s` : "",
    ]
      .filter(Boolean)
      .join(" · ");
    if (extraInfo) {
      notes.textContent = extraInfo;
    } else {
      notes.remove();
    }

    const link = node.querySelector(".entry-link");
    if (isSafeHttpUrl(entry.website)) {
      link.title = entry.website;
      link.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        try {
          await openExternalUrl(entry.website);
        } catch (error) {
          handleOperationError(error);
        }
      });
    } else {
      link.remove();
    }

    node.addEventListener("click", async (event) => {
      if (event.target.closest(".entry-link, .entry-menu")) {
        return;
      }
      try {
        const currentCode = state.codes.get(entry.id)?.code;
        if (!currentCode) {
          throw new Error("当前验证码不可复制。");
        }
        await copyText(currentCode);
        setStatus("已复制，30 秒后自动清空剪贴板。", "success");
      } catch (error) {
        handleOperationError(error);
      }
    });

    const menuShell = node.querySelector(".entry-menu");
    node.querySelector(".menu-button").addEventListener("pointerdown", (event) => {
      event.preventDefault();
      event.stopPropagation();
      toggleEntryMenu(menuShell, { kind: "entry", id: entry.id });
    });
    node.querySelector(".edit-button").addEventListener("click", () => {
      closeActiveMenu();
      fillEntryForm(entry);
    });
    node.querySelector(".delete-button").addEventListener("click", async () => {
      closeActiveMenu();
      const confirmed = await openConfirmDialog({
        title: "删除条目",
        message: `确认删除“${entry.label}”吗？此操作不会自动恢复。`,
        confirmLabel: "删除",
      });
      if (!confirmed) {
        return;
      }
      try {
        await removeEntry(entry.id);
        await reloadEntries();
        await refreshCodes();
        setStatus(`已删除条目：${entry.label}`, "success");
      } catch (error) {
        handleOperationError(error);
      }
    });

    entriesGrid.append(node);
    state.entryNodes.set(entry.id, node);
    updateEntryCard(node, entry);
    if (previousMenuState && previousMenuState.id === entry.id) {
      openMenu(menuShell, previousMenuState);
    }
  }
  requestAnimationFrame(updateListFadeState);
}

async function reloadEntries() {
  state.entries = await loadEntries();
  updateMeta();
  renderEntries();
}

async function refreshCodes() {
  if (!state.unlocked || refreshInFlight) {
    return;
  }
  refreshInFlight = true;
  try {
    const results = await loadCodes();
    state.codes = new Map(
      results.map((result) => [
        result.id,
        {
          code: result.code || "",
          remaining: Number(result.remaining || 0),
          error: result.error || "",
        },
      ]),
    );
    updateEntryDisplays();
  } finally {
    refreshInFlight = false;
  }
}

function clearUnlockedState() {
  state.unlocked = false;
  state.entries = [];
  state.codes = new Map();
  state.entryNodes = new Map();
  updateMeta();
  entriesGrid.innerHTML = "";
  closeAllMenus();
  closeEntryPanel();
  if (confirmBackdrop.classList.contains("open")) {
    closeConfirmDialog(false);
  }
  if (passwordBackdrop.classList.contains("open")) {
    closePasswordDialog(null);
  }
}

function showVaultGate(status, message = "") {
  clearUnlockedState();
  state.autoLockSeconds = Number(status.autoLockSeconds || 300);
  state.vaultMode = status.initialized ? "unlock" : "setup";
  const isSetup = state.vaultMode === "setup";
  vaultTitle.textContent = isSetup ? "创建加密保险库" : "解锁保险库";
  vaultDescription.textContent = isSetup
    ? "设置主密码后，条目将使用本机加密密钥保护。主密码无法找回，请妥善保存。"
    : `输入主密码继续。保险库闲置 ${Math.round(state.autoLockSeconds / 60)} 分钟后会自动锁定。`;
  vaultMigrationNotice.textContent =
    isSetup && status.legacyEntryCount > 0
      ? `检测到 ${status.legacyEntryCount} 个旧版明文条目，创建保险库时会自动加密迁移。`
      : "";
  vaultMigrationNotice.classList.toggle(
    "is-hidden",
    !(isSetup && status.legacyEntryCount > 0),
  );
  vaultConfirmGroup.classList.toggle("is-hidden", !isSetup);
  vaultPasswordInput.autocomplete = isSetup ? "new-password" : "current-password";
  vaultPasswordInput.value = "";
  vaultConfirmInput.value = "";
  vaultSubmitButton.textContent = isSetup ? "创建并解锁" : "解锁";
  vaultError.textContent = message;
  vaultGate.classList.add("open");
  vaultGate.setAttribute("aria-hidden", "false");
  document.body.classList.add("vault-locked");
  requestAnimationFrame(() => vaultPasswordInput.focus());
}

async function activateVault(status) {
  state.unlocked = true;
  state.autoLockSeconds = Number(status.autoLockSeconds || 300);
  state.codes = new Map();
  lastVaultTouch = Date.now();
  vaultGate.classList.remove("open");
  vaultGate.setAttribute("aria-hidden", "true");
  document.body.classList.remove("vault-locked");
  vaultPasswordInput.value = "";
  vaultConfirmInput.value = "";
  vaultError.textContent = "";
  await reloadEntries();
  await refreshCodes();
}

async function handleLockedSession(message = "保险库已自动锁定，请重新输入主密码。") {
  let status;
  try {
    status = await getVaultStatus();
  } catch {
    status = {
      initialized: true,
      legacyEntryCount: 0,
      autoLockSeconds: state.autoLockSeconds,
    };
  }
  showVaultGate(status, message);
}

function handleOperationError(error) {
  if (isVaultLockedError(error)) {
    void handleLockedSession();
    return;
  }
  setStatus(getErrorMessage(error), "error");
}

function validateEntryMetadata() {
  if (!entryFields.label.value.trim()) {
    throw new Error("条目名称不能为空。");
  }
  if (entryFields.website.value.trim() && !isSafeHttpUrl(entryFields.website.value)) {
    throw new Error("网址只支持 http 或 https。");
  }
  if (!["SHA1", "SHA256", "SHA512"].includes(entryFields.algorithm.value)) {
    throw new Error("算法只支持 SHA1 / SHA256 / SHA512。");
  }
  if (![6, 8].includes(Number(entryFields.digits.value))) {
    throw new Error("位数只支持 6 或 8。");
  }
  if (![15, 30, 45, 60].includes(Number(entryFields.period.value))) {
    throw new Error("周期只支持 15 / 30 / 45 / 60 秒。");
  }
}

function handleQuickImportToForm() {
  const parsed = parseEntryKey(quickImportInput.value);
  fillEntryForm(parsed, { keepId: false, mode: "import" });
  setStatus("解析成功", "success");
}

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const editing = Boolean(entryFields.id.value);
  try {
    validateEntryMetadata();
    const input = {
      id: editing ? entryFields.id.value : null,
      label: entryFields.label.value,
      account: entryFields.account.value,
      issuer: entryFields.issuer.value,
      secret: editing ? null : normalizeSecret(entryFields.secret.value),
      algorithm: entryFields.algorithm.value,
      digits: Number(entryFields.digits.value),
      period: Number(entryFields.period.value),
      website: entryFields.website.value,
      notes: entryFields.notes.value,
    };
    if (!editing) {
      validateEntry(sanitizeEntry(input));
    }
    const saved = await saveEntry(input);
    entryFields.secret.value = "";
    quickImportInput.value = "";
    await reloadEntries();
    closeEntryPanel();
    await refreshCodes();
    setStatus(`已保存条目：${saved.label}`, "success");
  } catch (error) {
    handleOperationError(error);
  }
});

vaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = vaultPasswordInput.value;
  vaultError.textContent = "";
  if (state.vaultMode === "setup" && password !== vaultConfirmInput.value) {
    vaultError.textContent = "两次输入的主密码不一致。";
    return;
  }

  vaultSubmitButton.disabled = true;
  vaultSubmitButton.textContent = state.vaultMode === "setup" ? "正在加密迁移…" : "正在解锁…";
  try {
    const status =
      state.vaultMode === "setup" ? await initializeVault(password) : await unlockVault(password);
    await activateVault(status);
    setStatus(state.vaultMode === "setup" ? "加密保险库已创建。" : "保险库已解锁。", "success");
  } catch (error) {
    vaultError.textContent = getErrorMessage(error);
    vaultPasswordInput.select();
  } finally {
    vaultSubmitButton.disabled = false;
    vaultSubmitButton.textContent = state.vaultMode === "setup" ? "创建并解锁" : "解锁";
  }
});

passwordDialogForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const password = passwordDialogInput.value;
  const options = passwordDialogOptions || {};
  passwordDialogError.textContent = "";
  if (!password) {
    passwordDialogError.textContent = "请输入密码。";
    return;
  }
  if (options.minimumLength && [...password].length < options.minimumLength) {
    passwordDialogError.textContent = `密码至少需要 ${options.minimumLength} 个字符。`;
    return;
  }
  if (options.requireConfirmation && password !== passwordDialogConfirmInput.value) {
    passwordDialogError.textContent = "两次输入的密码不一致。";
    return;
  }
  closePasswordDialog(password);
});

passwordDialogCancel.addEventListener("click", () => closePasswordDialog(null));
passwordBackdrop.addEventListener("click", (event) => {
  if (event.target === passwordBackdrop) {
    closePasswordDialog(null);
  }
});

resetFormButton.addEventListener("click", resetEntryForm);
quickImportButton.addEventListener("click", () => {
  try {
    handleQuickImportToForm();
  } catch (error) {
    setStatus(`解析失败：${getErrorMessage(error)}`, "error");
  }
});
fabAddButton.addEventListener("click", () => openEntryPanel({ reset: true }));
editorBackdrop.addEventListener("click", (event) => {
  if (event.target === editorBackdrop) {
    closeEntryPanel();
  }
});
confirmBackdrop.addEventListener("click", (event) => {
  if (event.target === confirmBackdrop) {
    closeConfirmDialog(false);
  }
});
confirmCancelButton.addEventListener("click", () => closeConfirmDialog(false));
confirmAcceptButton.addEventListener("click", () => closeConfirmDialog(true));

topMenuButton.addEventListener("pointerdown", (event) => {
  event.preventDefault();
  event.stopPropagation();
  toggleEntryMenu(topMenu, { kind: "top" });
});

lockButton.addEventListener("click", async () => {
  closeActiveMenu();
  try {
    await lockVault();
    await handleLockedSession("保险库已锁定。");
  } catch (error) {
    handleOperationError(error);
  }
});

changePasswordButton.addEventListener("click", async () => {
  closeActiveMenu();
  const currentPassword = await openPasswordDialog({
    title: "验证当前主密码",
    message: "更改主密码前，需要先验证当前主密码。",
    confirmLabel: "继续",
  });
  if (currentPassword === null) {
    return;
  }
  const newPassword = await openPasswordDialog({
    title: "设置新的主密码",
    message: "修改后必须使用新密码解锁。已有条目不需要重新导入。",
    confirmLabel: "更新主密码",
    requireConfirmation: true,
    minimumLength: 8,
  });
  if (newPassword === null) {
    return;
  }
  try {
    const status = await changeMasterPassword(currentPassword, newPassword);
    state.autoLockSeconds = Number(status.autoLockSeconds || state.autoLockSeconds);
    setStatus("主密码已更新。", "success");
  } catch (error) {
    handleOperationError(error);
  }
});

exportButton.addEventListener("click", async () => {
  closeActiveMenu();
  const password = await openPasswordDialog({
    title: "导出加密备份",
    message: "设置独立的备份密码。恢复备份时必须使用相同密码。",
    confirmLabel: "加密并导出",
    requireConfirmation: true,
    minimumLength: 8,
  });
  if (password === null) {
    return;
  }

  try {
    const backupText = await createEncryptedBackup(password);
    const filename = `totp-backup-${new Date().toISOString().slice(0, 10)}.totp`;
    const exportResult = await exportBackupWithDialog(filename, backupText);
    if (exportResult !== "cancelled") {
      setStatus("已导出加密备份。", "success");
    }
  } catch (error) {
    handleOperationError(error);
  }
});

importFileInput.addEventListener("change", async () => {
  const [file] = importFileInput.files;
  if (!file) {
    return;
  }
  closeActiveMenu();
  try {
    if (file.size > MAX_IMPORT_BYTES) {
      throw new Error("备份文件不能超过 10 MB。");
    }
    const text = await file.text();
    const encrypted = isEncryptedBackupText(text);
    let password = null;
    if (encrypted) {
      password = await openPasswordDialog({
        title: "恢复加密备份",
        message: "输入创建此备份时使用的密码。",
        confirmLabel: "解密并恢复",
      });
      if (password === null) {
        return;
      }
    } else {
      const confirmed = await openConfirmDialog({
        title: "导入旧版明文备份",
        message: "此文件不是加密备份。确认导入后，条目会立即加密保存到当前保险库。",
        confirmLabel: "继续导入",
      });
      if (!confirmed) {
        return;
      }
    }

    const result = await restoreBackup(text, password);
    await reloadEntries();
    await refreshCodes();
    setStatus(
      `已恢复 ${result.added + result.replaced} 个条目，新增 ${result.added} 个，替换 ${result.replaced} 个。`,
      "success",
    );
  } catch (error) {
    handleOperationError(error);
  } finally {
    importFileInput.value = "";
  }
});

window.addEventListener("resize", () => {
  updateListFadeState();
  if (activeMenuShell) {
    positionMenuPanel(activeMenuShell);
  }
});
listScroll.addEventListener("scroll", updateListFadeState);
window.addEventListener("wheel", handleMenuWheel, { capture: true, passive: true });

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (passwordBackdrop.classList.contains("open")) {
    closePasswordDialog(null);
  } else if (activeMenuShell) {
    closeActiveMenu();
  } else if (confirmBackdrop.classList.contains("open")) {
    closeConfirmDialog(false);
  } else if (editorBackdrop.classList.contains("open")) {
    closeEntryPanel();
  }
});

document.addEventListener("click", (event) => {
  if (activeMenuShell && !activeMenuShell.contains(event.target)) {
    closeActiveMenu();
  }
});

async function registerVaultActivity() {
  if (!state.unlocked || Date.now() - lastVaultTouch < 10_000) {
    return;
  }
  lastVaultTouch = Date.now();
  try {
    if (!(await touchVault())) {
      await handleLockedSession();
    }
  } catch (error) {
    handleOperationError(error);
  }
}

document.addEventListener("pointerdown", () => void registerVaultActivity(), { passive: true });
document.addEventListener("keydown", () => void registerVaultActivity());

async function bootstrap() {
  resetEntryForm();
  updateMeta();
  try {
    const status = await getVaultStatus();
    if (status.unlocked) {
      await activateVault(status);
    } else {
      showVaultGate(status);
    }
  } catch (error) {
    showVaultGate(
      { initialized: true, legacyEntryCount: 0, autoLockSeconds: 300 },
      `无法打开保险库：${getErrorMessage(error)}`,
    );
    vaultSubmitButton.disabled = true;
  }
}

window.setInterval(() => {
  if (!state.unlocked) {
    return;
  }
  refreshCodes().catch((error) => handleOperationError(error));
}, 1000);

void bootstrap();
