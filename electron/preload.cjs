const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopApp", {
  platform: "electron",
  copyText(text) {
    return ipcRenderer.invoke("clipboard:write-text", text);
  },
  loadEntries() {
    return ipcRenderer.invoke("entries:load");
  },
  saveEntries(entries) {
    return ipcRenderer.invoke("entries:save", entries);
  },
});
