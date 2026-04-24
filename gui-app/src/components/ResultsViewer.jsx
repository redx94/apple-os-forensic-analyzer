import React, { useState, useEffect } from 'react';
import { FolderOpen, FileText, Clock, AlertTriangle, CheckCircle, Search, RefreshCw, GitBranch, ChevronDown, ChevronRight } from 'lucide-react';

const OUTPUT_DIRS = [
  { id: 'extract_ids_output', name: 'Identifier Extraction' },
  { id: 'manifest_output', name: 'Evidence Manifests' },
  { id: 'validate_output', name: 'Validation Reports' },
  { id: 'verify_trust_output', name: 'Trust Verification' },
  { id: 'xpc_scan_output', name: 'XPC Scans' },
  { id: 'dns_monitor_output', name: 'DNS Monitoring' },
  { id: 'score_output', name: 'Confidence Scores' },
  { id: 'tcc_scan_output', name: 'TCC Permissions' },
  { id: 'browser_audit_output', name: 'Browser Audits' },
  { id: 'login_items_output', name: 'Login Items' },
  { id: 'ios_forensic_output', name: 'iOS Analysis' },
  { id: 'defense_checklist_output', name: 'Defense Checklist' },
];

// Process Tree Node Component
function ProcessTreeNode({ node, level = 0, onNodeClick }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div className="select-none">
      <div
        className={`flex items-center gap-2 py-1 px-2 hover:bg-muted/50 rounded cursor-pointer transition-colors`}
        style={{ paddingLeft: `${level * 20 + 8}px` }}
        onClick={() => {
          if (hasChildren) setExpanded(!expanded);
          onNodeClick?.(node);
        }}
      >
        {hasChildren && (
          <button className="p-0.5 hover:bg-muted rounded">
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        )}
        <span className={`font-mono text-sm ${node.suspicious ? 'text-red-500 font-bold' : 'text-foreground'}`}>
          {node.name}
        </span>
        {node.pid && <span className="text-xs text-muted-foreground">({node.pid})</span>}
        {node.suspicious && <AlertTriangle className="w-4 h-4 text-red-500" />}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children.map((child, idx) => (
            <ProcessTreeNode key={idx} node={child} level={level + 1} onNodeClick={onNodeClick} />
          ))}
        </div>
      )}
    </div>
  );
}

// Process Tree Visualization Component
function ProcessTreeViewer({ content }) {
  const [processTree, setProcessTree] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!content) return;

    // Parse parent_process_analyzer.sh output
    const lines = content.split('\n');
    const processMap = new Map();
    const rootProcesses = [];

    lines.forEach(line => {
      // Parse lines like: "Process: com.apple.shell (PID: 1234, Parent: Terminal)"
      const match = line.match(/Process:\s*(.+?)\s*\(PID:\s*(\d+),\s*Parent:\s*(.+?)\)/);
      if (match) {
        const [, name, pid, parentName] = match;
        const process = {
          name: name.trim(),
          pid: pid,
          parent: parentName.trim(),
          children: [],
          suspicious: line.includes('SUSPICIOUS') || line.includes('ALERT')
        };
        processMap.set(pid, process);
      }
    });

    // Build tree structure
    processMap.forEach((process, pid) => {
      // Find parent by name
      let parent = null;
      for (const [pPid, pProc] of processMap) {
        if (pProc.name === process.parent) {
          parent = pProc;
          break;
        }
      }

      if (parent) {
        parent.children.push(process);
      } else {
        rootProcesses.push(process);
      }
    });

    setProcessTree(rootProcesses);
  }, [content]);

  if (!processTree || processTree.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <div className="text-center">
          <GitBranch className="w-16 h-16 mx-auto mb-4 opacity-50" />
          <p>No process tree data available</p>
          <p className="text-sm mt-2">Select a parent_process_analyzer output file</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <h3 className="font-semibold flex items-center gap-2">
          <GitBranch className="w-5 h-5" />
          Process Tree Visualization
        </h3>
      </div>
      <div className="flex-1 overflow-auto p-4 bg-muted/20">
        {processTree.map((root, idx) => (
          <ProcessTreeNode key={idx} node={root} onNodeClick={setSelectedNode} />
        ))}
      </div>
      {selectedNode && (
        <div className="p-4 border-t border-border bg-muted/30">
          <div className="text-sm">
            <span className="font-semibold">Selected:</span> {selectedNode.name} (PID: {selectedNode.pid})
            {selectedNode.suspicious && <span className="ml-2 text-red-500 font-bold">⚠️ Suspicious</span>}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ResultsViewer() {
  const [selectedDir, setSelectedDir] = useState('extract_ids_output');
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState('text'); // 'text' or 'tree'

  useEffect(() => {
    loadFiles(selectedDir);
  }, [selectedDir]);

  const loadFiles = async (dirId) => {
    setLoading(true);
    try {
      const filesData = await window.electronAPI.readOutputDir(dirId);
      setFiles(filesData);
    } catch (error) {
      console.error('Failed to load files:', error);
      setFiles([]);
    } finally {
      setLoading(false);
    }
  };

  const loadFileContent = async (file) => {
    setLoading(true);
    try {
      const content = await window.electronAPI.readFile(file.path);
      setFileContent(content);
      setSelectedFile(file);
      // Auto-switch to tree view if it's a parent_process_analyzer output
      if (file.name.includes('parentage') || file.name.includes('parent_process')) {
        setViewMode('tree');
      } else {
        setViewMode('text');
      }
    } catch (error) {
      console.error('Failed to read file:', error);
      setFileContent('Failed to read file');
    } finally {
      setLoading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  const formatDate = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const selectedDirName = OUTPUT_DIRS.find(d => d.id === selectedDir)?.name || selectedDir;

  return (
    <div className="flex h-full gap-4">
      {/* Directory Sidebar */}
      <div className="w-64 bg-card rounded-lg border border-border flex flex-col">
        <div className="p-4 border-b border-border">
          <h2 className="font-semibold text-lg">Output Directories</h2>
        </div>
        <div className="flex-1 p-2 space-y-1 overflow-auto">
          {OUTPUT_DIRS.map(dir => (
            <button
              key={dir.id}
              onClick={() => setSelectedDir(dir.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                selectedDir === dir.id
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-muted text-muted-foreground hover:text-foreground'
              }`}
            >
              <FolderOpen className="w-4 h-4" />
              <span className="font-medium text-sm">{dir.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* File List */}
      <div className="w-80 bg-card rounded-lg border border-border flex flex-col">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="font-semibold">{selectedDirName}</h2>
          <button
            onClick={() => loadFiles(selectedDir)}
            className="p-2 hover:bg-muted rounded transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="p-8 text-center text-muted-foreground">Loading...</div>
          ) : files.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No files in this directory
            </div>
          ) : (
            <div className="divide-y divide-border">
              {files.map(file => (
                <button
                  key={file.path}
                  onClick={() => loadFileContent(file)}
                  className={`w-full px-4 py-3 text-left hover:bg-muted transition-colors ${
                    selectedFile?.path === file.path ? 'bg-muted' : ''
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <FileText className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium truncate">{file.name}</div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {formatFileSize(file.stats.size)} • {formatDate(file.stats.mtimeMs)}
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* File Content Viewer */}
      <div className="flex-1 bg-card rounded-lg border border-border flex flex-col overflow-hidden">
        {selectedFile ? (
          <>
            <div className="p-4 border-b border-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4" />
                <span className="font-semibold">{selectedFile.name}</span>
              </div>
              <div className="flex items-center gap-3">
                {(selectedFile.name.includes('parentage') || selectedFile.name.includes('parent_process')) && (
                  <button
                    onClick={() => setViewMode(viewMode === 'text' ? 'tree' : 'text')}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg hover:bg-muted transition-colors"
                  >
                    <GitBranch className="w-4 h-4" />
                    {viewMode === 'tree' ? 'Text View' : 'Tree View'}
                  </button>
                )}
                <div className="text-sm text-muted-foreground">
                  {formatFileSize(selectedFile.stats.size)}
                </div>
              </div>
            </div>
            <div className="flex-1 overflow-auto">
              {loading ? (
                <div className="text-center text-muted-foreground p-4">Loading...</div>
              ) : viewMode === 'tree' && (selectedFile.name.includes('parentage') || selectedFile.name.includes('parent_process')) ? (
                <ProcessTreeViewer content={fileContent} />
              ) : (
                <pre className="font-mono text-sm whitespace-pre-wrap break-words p-4">{fileContent}</pre>
              )}
            </div>
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center">
              <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <p>Select a file to view its contents</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
