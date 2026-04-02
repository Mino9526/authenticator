import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("desktopApp", {
  platform: "electron",
  copyText(text) {
    return ipcRenderer.invoke("clipboard:write-text", text);
  },
});
