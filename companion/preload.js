// The only bridge between the window and the app. No key value crosses it.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("vg", {
  getState: () => ipcRenderer.invoke("get-state"),
  retire: () => ipcRenderer.invoke("retire"),
  listKeys: () => ipcRenderer.invoke("list-keys"),
  dismiss: () => ipcRenderer.invoke("dismiss"),
  setProject: (project) => ipcRenderer.invoke("set-project", project),
  setWatching: (on) => ipcRenderer.invoke("set-watching", on),
  setOpenAtLogin: (on) => ipcRenderer.invoke("set-open-at-login", on),
  onState: (fn) => ipcRenderer.on("state", (_e, s) => fn(s)),
  onProgress: (fn) => ipcRenderer.on("progress", (_e, p) => fn(p)),
  onError: (fn) => ipcRenderer.on("error", (_e, m) => fn(m)),
});
