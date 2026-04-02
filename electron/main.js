import path from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, clipboard, ipcMain, shell } from "electron";
import { EntryStore } from "../db.js";
import { isSafeHttpUrl } from "../src/totp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let mainWindow;
let entryStore;

function getProjectRoot() {
  return path.resolve(__dirname, "..");
}

function getDatabasePath() {
  return path.join(app.getPath("userData"), "authenticator.sqlite");
}

function getEntryStore() {
  if (!entryStore) {
    entryStore = new EntryStore(getDatabasePath());
  }
  return entryStore;
}

ipcMain.handle("clipboard:write-text", (_event, text) => {
  clipboard.writeText(String(text || ""));
  return true;
});

ipcMain.handle("entries:load", () => {
  return getEntryStore().listEntries();
});

ipcMain.handle("entries:save", (_event, entries) => {
  return getEntryStore().replaceEntries(Array.isArray(entries) ? entries : []);
});

async function createMainWindow() {
  getEntryStore();

  mainWindow = new BrowserWindow({
    width: 412,
    height: 720,
    minWidth: 412,
    minHeight: 720,
    maxWidth: 412,
    maxHeight: 720,
    useContentSize: true,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    backgroundColor: "#f5f7fb",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      sandbox: false,
      preload: path.join(__dirname, "preload.cjs"),
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeHttpUrl(url)) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  await mainWindow.loadFile(path.join(getProjectRoot(), "index.html"));
}

app.whenReady().then(async () => {
  await createMainWindow();

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  if (entryStore) {
    entryStore.close();
    entryStore = null;
  }
});
