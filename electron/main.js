import path from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, clipboard, ipcMain, shell } from "electron";
import { startServer } from "../server.js";
import { isSafeHttpUrl } from "../src/totp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let appServer;
let mainWindow;
let isQuitting = false;

function getProjectRoot() {
  return path.resolve(__dirname, "..");
}

function getDatabasePath() {
  return path.join(app.getPath("userData"), "authenticator.sqlite");
}

ipcMain.handle("clipboard:write-text", (_event, text) => {
  clipboard.writeText(String(text || ""));
  return true;
});

async function createMainWindow() {
  appServer = await startServer({
    port: 0,
    root: getProjectRoot(),
    databasePath: getDatabasePath(),
  });

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
      sandbox: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeHttpUrl(url)) {
      shell.openExternal(url);
    }
    return { action: "deny" };
  });

  await mainWindow.loadURL(appServer.url);
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

app.on("before-quit", async (event) => {
  if (isQuitting || !appServer) {
    return;
  }

  event.preventDefault();
  isQuitting = true;
  const serverToStop = appServer;
  appServer = null;
  try {
    await serverToStop.stop();
  } finally {
    app.quit();
  }
});
