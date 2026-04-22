const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const os = require('os');

let mainWindow;

// Tool catalog with metadata
const TOOLS = {
  collect: [
    {
      id: 'extract_ids_all',
      name: 'Extract Identifiers',
      description: 'Extract all com.apple.* identifiers from live system and plists',
      script: '../collect/extract_ids.sh',
      args: ['--all'],
      category: 'Collection',
      icon: 'search'
    },
    {
      id: 'extract_ids_live',
      name: 'Extract Live Services',
      description: 'Extract identifiers from running launchctl services',
      script: '../collect/extract_ids.sh',
      args: ['--live'],
      category: 'Collection',
      icon: 'activity'
    },
    {
      id: 'extract_ids_plists',
      name: 'Extract from Plists',
      description: 'Extract identifiers from launchd plist directories',
      script: '../collect/extract_ids.sh',
      args: ['--plists'],
      category: 'Collection',
      icon: 'file-text'
    },
    {
      id: 'manifest_generator',
      name: 'Generate Evidence Manifest',
      description: 'Create machine-readable manifest with hashes and timestamps',
      script: '../collect/manifest_generator.sh',
      args: [],
      category: 'Collection',
      icon: 'hash'
    },
    {
      id: 'save_baseline',
      name: 'Save Baseline',
      description: 'Save current state as baseline for differential comparison',
      script: '../collect/extract_ids.sh',
      args: ['--baseline'],
      category: 'Collection',
      icon: 'save'
    },
    {
      id: 'diff_baseline',
      name: 'Compare to Baseline',
      description: 'Detect changes since baseline',
      script: '../collect/extract_ids.sh',
      args: ['--diff'],
      category: 'Collection',
      icon: 'git-diff'
    }
  ],
  analyze: [
    {
      id: 'validate_nodes',
      name: 'Validate Nodes',
      description: 'Validate identifiers against dynamic system whitelist',
      script: '../analyze/validate_nodes.py',
      args: ['--demo'],
      category: 'Analysis',
      icon: 'check-circle'
    }
  ],
  score: [
    {
      id: 'detect_agents',
      name: 'Detect Suspicious Agents',
      description: 'Scan for namespace squatting and suspicious persistence',
      script: '../score/detect_agents.sh',
      args: [],
      category: 'Scoring',
      icon: 'shield-alert'
    },
    {
      id: 'verify_trust',
      name: 'Verify Trust',
      description: 'Verify signatures, entitlements, and paths',
      script: '../score/verify_trust.sh',
      args: [],
      category: 'Scoring',
      icon: 'shield-check'
    },
    {
      id: 'verify_extracted_ids',
      name: 'Deep Verify Extracted IDs',
      description: 'Cryptographic verification of extracted identifiers',
      script: '../score/verify_extracted_ids.sh',
      args: [],
      category: 'Scoring',
      icon: 'fingerprint'
    },
    {
      id: 'xpc_scanner',
      name: 'XPC Scanner',
      description: 'Check for XPC service squatting',
      script: '../score/xpc_scanner.sh',
      args: [],
      category: 'Scoring',
      icon: 'network'
    },
    {
      id: 'dns_monitor',
      name: 'DNS Monitor',
      description: 'Monitor DNS for hijacking and drift',
      script: '../score/dns_monitor.sh',
      args: ['--check'],
      category: 'Scoring',
      icon: 'globe'
    },
    {
      id: 'confidence_scorer',
      name: 'Confidence Scorer',
      description: 'Risk scoring engine (0-100)',
      script: '../score/confidence_scorer.py',
      args: ['--input', '../extract_ids_output/apple_ids_*.txt'],
      category: 'Scoring',
      icon: 'bar-chart-2'
    },
    {
      id: 'tcc_scanner',
      name: 'TCC Scanner',
      description: 'Scan privacy permissions',
      script: '../score/tcc_scanner.sh',
      args: [],
      category: 'Scoring',
      icon: 'lock'
    },
    {
      id: 'browser_auditor',
      name: 'Browser Extension Auditor',
      description: 'Audit browser extensions for persistence',
      script: '../score/browser_extension_auditor.sh',
      args: [],
      category: 'Scoring',
      icon: 'browser'
    },
    {
      id: 'login_items_checker',
      name: 'Login Items Checker',
      description: 'Check login items and background tasks',
      script: '../score/login_items_checker.sh',
      args: [],
      category: 'Scoring',
      icon: 'log-in'
    }
  ],
  ios: [
    {
      id: 'ios_sysdiagnose',
      name: 'iOS Sysdiagnose Analyzer',
      description: 'Analyze iOS sysdiagnose or backup',
      script: '../ios/analyze_ios_sysdiagnose.sh',
      args: [],
      category: 'iOS',
      icon: 'smartphone'
    }
  ]
};

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

  mainWindow.loadFile('dist/index.html');
  
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

    // Resolve script path relative to the app resources
    const scriptPath = path.join(__dirname, tool.script);
    const toolArgs = args.length > 0 ? args : tool.args;

    // Run with sudo for root privileges
    const child = spawn('sudo', ['bash', scriptPath, ...toolArgs], {
      cwd: path.join(__dirname, '..'),
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
      event.sender.send('tool-error', text);
    });

    child.on('close', (code) => {
      resolve({
        exitCode: code,
        output,
        error: errorOutput,
        success: code === 0
      });
    });

    child.on('error', (err) => {
      reject(err);
    });
  });
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
