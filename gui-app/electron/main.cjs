const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const os = require('os');

let mainWindow;

const isDev = !app.isPackaged;

// Get the parent directory (project root) regardless of where Electron is launched from
const projectRoot = path.join(__dirname, '..', '..');

// Load tool catalog from external config file
let TOOLS = {};
try {
  const toolsConfigPath = path.join(__dirname, 'tools-config.json');
  const toolsConfig = JSON.parse(fs.readFileSync(toolsConfigPath, 'utf-8'));
  TOOLS = toolsConfig;
} catch (error) {
  console.error('Failed to load tools config:', error);
  // Fallback to empty catalog if config fails to load
  TOOLS = { collect: [], analyze: [], score: [], ios: [] };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0a0a0a',
    show: false
  });

  if (isDev) {
    const devUrl = process.env.ELECTRON_RENDERER_URL || 'http://localhost:5173';
    mainWindow.loadURL(devUrl);
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    const indexPath = path.join(__dirname, '..', 'dist', 'index.html');
    if (!fs.existsSync(indexPath)) {
      dialog.showErrorBox(
        'UI Build Missing',
        `Could not find the UI build at:\n\n${indexPath}\n\nRun "npm run build" in gui-app and try again.`
      );
    }
    mainWindow.loadFile(indexPath);
  }
  
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC handlers
ipcMain.handle('get-tools', () => TOOLS);

ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'Sysdiagnose', extensions: ['tar.gz', 'zip'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });
  return result.filePaths[0] || null;
});

ipcMain.handle('request-permissions', async () => {
  // Request Full Disk Access and other necessary permissions
  try {
    // On macOS, we need to guide the user to grant Full Disk Access
    // This is done through System Preferences > Security & Privacy > Privacy > Full Disk Access
    const result = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      buttons: ['OK', 'Open System Preferences'],
      defaultId: 0,
      title: 'Permissions Required',
      message: 'Full Disk Access Required',
      detail: 'This forensic analyzer requires Full Disk Access to scan TCC databases and perform comprehensive analysis. Please grant Full Disk Access to this app in System Preferences > Security & Privacy > Privacy > Full Disk Access.'
    });

    if (result.response === 1) {
      // Open System Preferences
      exec('open /System/Preferences/Security.prefPane');
    }
    return { granted: false, needsAction: true };
  } catch (error) {
    console.error('Permission request error:', error);
    return { granted: false, needsAction: true };
  }
});

ipcMain.handle('execute-tool', async (event, toolId, args = []) => {
  return new Promise((resolve, reject) => {
    // Find tool
    let tool = null;
    for (const category in TOOLS) {
      tool = TOOLS[category].find(t => t.id === toolId);
      if (tool) break;
    }

    if (!tool) {
      reject(new Error('Tool not found'));
      return;
    }

    // Resolve script path relative to project root
    const scriptPath = path.join(projectRoot, tool.script);
    const toolArgs = args.length > 0 ? args : tool.args;

    // Determine interpreter based on file extension
    const isPython = scriptPath.endsWith('.py');
    const interpreter = isPython ? 'python3' : 'bash';

    // Run with sudo for root privileges
    const child = spawn('sudo', [interpreter, scriptPath, ...toolArgs], {
      cwd: projectRoot,
      env: { ...process.env, PATH: process.env.PATH }
    });

    let output = '';
    let errorOutput = '';

    child.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      event.sender.send('tool-output', text);
    });

    child.stderr.on('data', (data) => {
      const text = data.toString();
      errorOutput += text;
      event.sender.send('tool-output', text); // Send stderr as output too
    });

    child.on('close', (code) => {
      resolve({
        exitCode: code,
        output: output + errorOutput,
        error: errorOutput,
        success: code === 0
      });
    });

    child.on('error', (err) => {
      reject(err);
    });
  });
});

ipcMain.handle('run-full-scan', async (event) => {
  const results = [];
  const allTools = [];

  // Collect all tools in order
  for (const category in TOOLS) {
    allTools.push(...TOOLS[category]);
  }

  for (const tool of allTools) {
    event.sender.send('tool-output', `\n=== Executing: ${tool.name} ===\n`);
    event.sender.send('tool-output', `${tool.description}\n\n`);

    try {
      const result = await new Promise((resolve, reject) => {
        const scriptPath = path.join(projectRoot, tool.script);
        const toolArgs = tool.args;
        const isPython = scriptPath.endsWith('.py');
        const interpreter = isPython ? 'python3' : 'bash';

        const child = spawn('sudo', [interpreter, scriptPath, ...toolArgs], {
          cwd: projectRoot,
          env: { ...process.env, PATH: process.env.PATH }
        });

        let output = '';
        let errorOutput = '';

        child.stdout.on('data', (data) => {
          const text = data.toString();
          output += text;
          event.sender.send('tool-output', text);
        });

        child.stderr.on('data', (data) => {
          const text = data.toString();
          errorOutput += text;
          event.sender.send('tool-output', text);
        });

        child.on('close', (code) => {
          resolve({
            toolId: tool.id,
            toolName: tool.name,
            exitCode: code,
            output: output + errorOutput,
            success: code === 0
          });
        });

        child.on('error', (err) => {
          resolve({
            toolId: tool.id,
            toolName: tool.name,
            exitCode: -1,
            output: err.message,
            success: false
          });
        });
      });

      results.push(result);
      event.sender.send('tool-output', `\n--- ${tool.name} completed (Exit: ${result.exitCode}) ---\n`);
    } catch (error) {
      results.push({
        toolId: tool.id,
        toolName: tool.name,
        exitCode: -1,
        output: error.message,
        success: false
      });
      event.sender.send('tool-output', `\n--- ${tool.name} failed: ${error.message} ---\n`);
    }
  }

  event.sender.send('tool-output', `\n=== FULL SCAN COMPLETE ===\n`);
  event.sender.send('tool-output', `Total tools executed: ${results.length}\n`);
  event.sender.send('tool-output', `Successful: ${results.filter(r => r.success).length}\n`);
  event.sender.send('tool-output', `Failed: ${results.filter(r => !r.success).length}\n`);

  return results;
});

ipcMain.handle('read-file', async (event, filePath) => {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return content;
  } catch (error) {
    throw error;
  }
});

ipcMain.handle('read-output-dir', async (event, dirName) => {
  try {
    const dirPath = path.join(__dirname, '..', dirName);
    if (!fs.existsSync(dirPath)) {
      return [];
    }
    const files = fs.readdirSync(dirPath).map(file => ({
      name: file,
      path: path.join(dirPath, file),
      stats: fs.statSync(path.join(dirPath, file))
    })).sort((a, b) => b.stats.mtimeMs - a.stats.mtimeMs);
    return files;
  } catch (error) {
    console.error('Error reading output dir:', error);
    return [];
  }
});

ipcMain.handle('get-system-info', () => {
  return {
    platform: os.platform(),
    arch: os.arch(),
    hostname: os.hostname(),
    release: os.release(),
    totalmem: os.totalmem(),
    cpus: os.cpus().length
  };
});

// Forensic Air-Gap: Toggle network interfaces
let networkDisabled = false;
let originalNetworkStates = {};

ipcMain.handle('toggle-network-air-gap', async () => {
  return new Promise((resolve, reject) => {
    if (process.platform !== 'darwin') {
      reject(new Error('Air-Gap mode only supported on macOS'));
      return;
    }

    // Get list of network services
    exec('networksetup -listallnetworkservices', (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }

      const services = stdout.split('\n')
        .filter(line => line && !line.includes('An asterisk (*) denotes that a network service is disabled.'))
        .slice(1); // Skip header

      if (networkDisabled) {
        // Re-enable all network interfaces
        let enabledCount = 0;
        services.forEach(service => {
          const serviceName = service.trim();
          if (serviceName && originalNetworkStates[serviceName] === 'enabled') {
            exec(`networksetup -setnetworkserviceenabled ${serviceName} on`, (err) => {
              if (!err) enabledCount++;
            });
          }
        });

        networkDisabled = false;
        originalNetworkStates = {};
        resolve({ enabled: true, message: `Re-enabled ${enabledCount} network interfaces` });
      } else {
        // Disable all network interfaces
        let disabledCount = 0;
        services.forEach(service => {
          const serviceName = service.trim();
          if (serviceName) {
            // Store current state
            exec(`networksetup -getinfo ${serviceName}`, (err, stdout) => {
              if (!err && stdout.includes('IP address:')) {
                originalNetworkStates[serviceName] = 'enabled';
              }
            });

            // Disable interface
            exec(`networksetup -setnetworkserviceenabled ${serviceName} off`, (err) => {
              if (!err) disabledCount++;
            });
          }
        });

        networkDisabled = true;
        resolve({ enabled: false, message: `Disabled ${disabledCount} network interfaces for air-gap mode` });
      }
    });
  });
});

ipcMain.handle('get-network-status', async () => {
  return new Promise((resolve) => {
    if (process.platform !== 'darwin') {
      resolve({ airGapEnabled: false, platform: process.platform });
      return;
    }

    exec('networksetup -listallnetworkservices', (error, stdout) => {
      if (error) {
        resolve({ airGapEnabled: false, error: error.message });
        return;
      }

      const services = stdout.split('\n')
        .filter(line => line && !line.includes('An asterisk (*) denotes that a network service is disabled.'))
        .slice(1);

      let activeCount = 0;
      services.forEach(service => {
        const serviceName = service.trim();
        if (serviceName) {
          exec(`networksetup -getinfo ${serviceName}`, (err, stdout) => {
            if (!err && stdout.includes('IP address:')) {
              activeCount++;
            }
          });
        }
      });

      // If no active interfaces, assume air-gap is enabled
      resolve({ airGapEnabled: networkDisabled || activeCount === 0, activeInterfaces: activeCount });
    });
  });
});
