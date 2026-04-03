import {
  createSnapshot,
  formatOtp,
  generateTotp,
  isSafeHttpUrl,
  mergeImportedEntries,
  normalizeSecret,
  parseEntryKey,
  parseImportText,
  sanitizeEntry,
  secondsRemaining,
  validateEntry,
} from "./totp.js";
import { exportBackupWithDialog, openExternalUrl } from "./tauri.js";
import { loadEntries, saveEntries } from "./storage.js";

const entryCount = document.querySelector("#entry-count");
const entriesGrid = document.querySelector("#entries-grid");
const listPanel = document.querySelector(".list-panel");
const toast = document.querySelector("#toast");
const fabAddButton = document.querySelector("#fab-add-button");
const topMenu = document.querySelector("#top-menu");
const topMenuButton = document.querySelector("#top-menu-button");
const exportButton = document.querySelector("#export-button");
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
};

let toastTimer;
let confirmResolver = null;
let activeMenuShell = null;
let activeMenuState = null;
let editorCloseTimer = null;

const EDITOR_TRANSITION_MS = 220;

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
  }, type === "error" ? 4200 : 2600);
}

function updateMeta() {
  entryCount.textContent = String(state.entries.length);
}

function updateListFadeState() {
  const maxScrollTop = listPanel.scrollHeight - listPanel.clientHeight;
  const canScroll = maxScrollTop > 1;
  listPanel.classList.toggle("has-top-fade", canScroll && listPanel.scrollTop > 1);
  listPanel.classList.toggle("has-bottom-fade", canScroll && listPanel.scrollTop < maxScrollTop - 1);
}

async function persistEntries() {
  state.entries = await saveEntries(state.entries);
  updateMeta();
  renderEntries();
}

function syncOverlayState() {
  const hasOverlay =
    editorBackdrop.classList.contains("open") ||
    editorBackdrop.classList.contains("closing") ||
    confirmBackdrop.classList.contains("open");
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

function positionMenuPanel(menuShell) {
  const trigger = menuShell.querySelector(".menu-button, .top-menu-button");
  const panel = menuShell.querySelector(".entry-menu-panel, .top-menu-panel");
  if (!trigger || !panel) {
    return;
  }

  const triggerRect = trigger.getBoundingClientRect();
  const panelRect = panel.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const spacing = 12;

  let left = triggerRect.right - panelRect.width;
  left = Math.min(left, viewportWidth - panelRect.width - spacing);
  left = Math.max(spacing, left);

  let top = triggerRect.bottom + 8;
  if (top + panelRect.height > viewportHeight - spacing) {
    top = triggerRect.top - panelRect.height - 8;
  }
  if (top < spacing) {
    top = spacing;
  }

  panel.style.left = `${left}px`;
  panel.style.top = `${top}px`;
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

function setSecretFieldsLocked(locked) {
  entryFields.secret.readOnly = locked;
  entryFields.secret.toggleAttribute("data-locked", locked);
  entryFields.algorithm.disabled = locked;
  entryFields.digits.disabled = locked;
  entryFields.period.readOnly = locked;
  entryFields.period.toggleAttribute("data-locked", locked);
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
  setSecretFieldsLocked(false);
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

function fillEntryForm(entry, options = {}) {
  entryFields.id.value = options.keepId === false ? "" : entry.id;
  entryFields.label.value = entry.label;
  entryFields.account.value = entry.account;
  entryFields.issuer.value = entry.issuer;
  entryFields.secret.value = entry.secret;
  entryFields.algorithm.value = entry.algorithm;
  entryFields.digits.value = String(entry.digits);
  entryFields.period.value = String(entry.period);
  entryFields.website.value = entry.website;
  entryFields.notes.value = entry.notes;
  editorTitle.textContent = options.mode === "import" ? "导入后编辑" : "编辑条目";
  setResetButtonVisible(false);
  setQuickImportVisible(options.mode === "import");
  setSecretFieldsLocked(true);
  setQuickImportLocked(options.mode !== "import");
  if (options.mode !== "import") {
    quickImportInput.value = "";
  }
  openEntryPanel();
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

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

function sortEntries() {
  return [...state.entries].sort((a, b) => {
    const createdDiff = Number(a.createdAt || 0) - Number(b.createdAt || 0);
    if (createdDiff !== 0) {
      return createdDiff;
    }
    return a.label.localeCompare(b.label, "zh-CN");
  });
}

function updateEntryCard(node, entry, now = Date.now()) {
  const codeState = state.codes.get(entry.id);
  const remaining = secondsRemaining(entry, now);
  const elapsedProgress = 1 - remaining / entry.period;
  const timerRing = node.querySelector(".entry-timer-ring");

  node.querySelector(".entry-code").textContent = codeState?.code ? formatOtp(codeState.code) : "------";
  node.querySelector(".entry-timer").textContent = codeState?.error ? "错误" : `${remaining}s`;
  timerRing.style.setProperty("--timer-progress", String(elapsedProgress));
  timerRing.classList.toggle("is-error", Boolean(codeState?.error));
}

function updateEntryDisplays(now = Date.now()) {
  for (const entry of sortEntries()) {
    const node = state.entryNodes.get(entry.id);
    if (!node) {
      continue;
    }
    updateEntryCard(node, entry, now);
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
    empty.textContent = "没有可显示的条目。可点击右下角 + 或从 JSON 备份恢复。";
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
    const extraInfo = [entry.algorithm !== "SHA1" ? entry.algorithm : "", entry.period !== 30 ? `${entry.period}s` : ""]
      .filter(Boolean)
      .join(" · ");

    if (extraInfo) {
      notes.textContent = extraInfo;
    } else {
      notes.remove();
    }

    const link = node.querySelector(".entry-link");
    if (isSafeHttpUrl(entry.website)) {
      link.href = entry.website;
      link.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();

        try {
          await openExternalUrl(entry.website);
        } catch (error) {
          setStatus(error.message, "error");
        }
      });
    } else {
      link.remove();
    }

    const copyCurrentCode = async () => {
      const currentCodeState = state.codes.get(entry.id);
      if (!currentCodeState?.code || currentCodeState.code === "ERROR") {
        throw new Error("当前验证码不可复制。");
      }
      await copyText(currentCodeState.code);
      setStatus("已复制", "success");
    };

    node.addEventListener("click", async (event) => {
      if (event.target.closest(".entry-link, .entry-menu")) {
        return;
      }
      try {
        await copyCurrentCode();
      } catch (error) {
        setStatus(error.message, "error");
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
        state.entries = state.entries.filter((item) => item.id !== entry.id);
        await persistEntries();
        await refreshCodes();
        setStatus(`已删除条目：${entry.label}`, "success");
      } catch (error) {
        setStatus(error.message, "error");
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

async function refreshCodes() {
  const visibleEntries = sortEntries();
  const results = await Promise.all(
    visibleEntries.map(async (entry) => {
      try {
        const code = await generateTotp(entry);
        return [entry.id, { code, error: "" }];
      } catch (error) {
        return [entry.id, { code: "ERROR", error: error.message }];
      }
    }),
  );

  state.codes = new Map(results);
  updateEntryDisplays();
}

async function handleImportBackup(text) {
  const importedEntries = parseImportText(text);
  importedEntries.forEach(validateEntry);
  const mergeResult = mergeImportedEntries(state.entries, importedEntries);
  state.entries = mergeResult.entries;
  await persistEntries();
  await refreshCodes();
  setStatus(`已恢复 ${importedEntries.length} 个条目，新增 ${mergeResult.added} 个，替换 ${mergeResult.replaced} 个。`, "success");
}

function handleQuickImportToForm() {
  const parsed = parseEntryKey(quickImportInput.value);
  fillEntryForm(parsed, { keepId: false, mode: "import" });
  setStatus("解析成功", "success");
}

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const entry = sanitizeEntry({
      id: entryFields.id.value || undefined,
      label: entryFields.label.value,
      account: entryFields.account.value,
      issuer: entryFields.issuer.value,
      secret: entryFields.secret.value,
      algorithm: entryFields.algorithm.value,
      digits: Number(entryFields.digits.value),
      period: Number(entryFields.period.value),
      website: entryFields.website.value,
      notes: entryFields.notes.value,
      createdAt: entryFields.id.value
        ? state.entries.find((item) => item.id === entryFields.id.value)?.createdAt
        : undefined,
    });

    validateEntry(entry);

    if (!entryFields.id.value) {
      const hasDuplicateSecret = state.entries.some((item) => item.secret === normalizeSecret(entry.secret));
      if (hasDuplicateSecret) {
        throw new Error("该密钥已存在，不能重复新增。");
      }
    }

    const existingIndex = state.entries.findIndex((item) => item.id === entry.id);
    if (existingIndex >= 0) {
      state.entries.splice(existingIndex, 1, entry);
    } else {
      state.entries.push(entry);
    }

    await persistEntries();
    closeEntryPanel();
    await refreshCodes();
    setStatus(`已保存条目：${entry.label}`, "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

resetFormButton.addEventListener("click", () => resetEntryForm());

quickImportButton.addEventListener("click", () => {
  try {
    handleQuickImportToForm();
  } catch (error) {
    setStatus(`解析失败：${error.message}`, "error");
  }
});

fabAddButton.addEventListener("click", () => {
  openEntryPanel({ reset: true });
});

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

confirmCancelButton.addEventListener("click", () => {
  closeConfirmDialog(false);
});

confirmAcceptButton.addEventListener("click", () => {
  closeConfirmDialog(true);
});

topMenuButton.addEventListener("pointerdown", (event) => {
  event.preventDefault();
  event.stopPropagation();
  toggleEntryMenu(topMenu, { kind: "top" });
});

window.addEventListener("resize", () => {
  updateListFadeState();
  if (activeMenuShell) {
    positionMenuPanel(activeMenuShell);
  }
});

listPanel.addEventListener("scroll", updateListFadeState);

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }

  if (activeMenuShell) {
    closeActiveMenu();
    return;
  }

  if (confirmBackdrop.classList.contains("open")) {
    closeConfirmDialog(false);
    return;
  }

  if (editorBackdrop.classList.contains("open")) {
    closeEntryPanel();
  }
});

document.addEventListener("click", (event) => {
  if (!activeMenuShell) {
    return;
  }

  if (!activeMenuShell.contains(event.target)) {
    closeActiveMenu();
  }
});

exportButton.addEventListener("click", async () => {
  closeActiveMenu();

  try {
    const snapshot = createSnapshot(state.entries);
    const filename = `totp-backup-${new Date().toISOString().slice(0, 10)}.json`;
    const snapshotText = JSON.stringify(snapshot, null, 2);
    const exportResult = await exportBackupWithDialog(filename, snapshotText);

    if (exportResult === "cancelled") {
      return;
    }

    setStatus("已导出当前备份。", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
});

importFileInput.addEventListener("change", async () => {
  const [file] = importFileInput.files;
  if (!file) {
    return;
  }

  try {
    closeActiveMenu();
    const text = await file.text();
    await handleImportBackup(text);
    importFileInput.value = "";
  } catch (error) {
    setStatus(error.message, "error");
  }
});

resetEntryForm();
updateMeta();

try {
  state.entries = await loadEntries();
  updateMeta();
  renderEntries();
  await refreshCodes();
} catch (error) {
  setStatus(`加载 SQLite 数据失败：${error.message}`, "error");
}

setInterval(() => {
  refreshCodes().catch((error) => {
    setStatus(error.message, "error");
  });
}, 1000);
