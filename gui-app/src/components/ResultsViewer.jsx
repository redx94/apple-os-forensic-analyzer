import React, { useState, useEffect } from 'react';
import { FolderOpen, FileText, Clock, AlertTriangle, CheckCircle, Search, RefreshCw } from 'lucide-react';

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
];

export default function ResultsViewer() {
  const [selectedDir, setSelectedDir] = useState('extract_ids_output');
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [loading, setLoading] = useState(false);

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
              <div className="text-sm text-muted-foreground">
                {formatFileSize(selectedFile.stats.size)}
              </div>
            </div>
            <div className="flex-1 overflow-auto p-4">
              {loading ? (
                <div className="text-center text-muted-foreground">Loading...</div>
              ) : (
                <pre className="font-mono text-sm whitespace-pre-wrap break-words">{fileContent}</pre>
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
