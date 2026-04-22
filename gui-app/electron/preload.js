const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getTools: () => ipcRenderer.invoke('get-tools'),
  selectFile: () => ipcRenderer.invoke('select-file'),
  executeTool: (toolId, args) => ipcRenderer.invoke('execute-tool', toolId, args),
  readFile: (filePath) => ipcRenderer.invoke('read-file', filePath),
  readOutputDir: (dirName) => ipcRenderer.invoke('read-output-dir', dirName),
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  requestPermissions: () => ipcRenderer.invoke('request-permissions'),
  onToolOutput: (callback) => ipcRenderer.on('tool-output', (event, data) => callback(data)),
  onToolError: (callback) => ipcRenderer.on('tool-error', (event, data) => callback(data)),
  removeListeners: () => {
    ipcRenderer.removeAllListeners('tool-output');
    ipcRenderer.removeAllListeners('tool-error');
  }
});
