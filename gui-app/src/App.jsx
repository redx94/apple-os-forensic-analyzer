import React, { useState, useEffect } from 'react';
import { Shield, PlaySquare, FileText, Activity, Terminal, ChevronRight, Cpu, HardDrive, Monitor, Copy } from 'lucide-react';
import ToolCatalog from './components/ToolCatalog';
import ExecutionPanel from './components/ExecutionPanel';
import ResultsViewer from './components/ResultsViewer';
import Dashboard from './components/Dashboard';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedTool, setSelectedTool] = useState(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionOutput, setExecutionOutput] = useState('');
  const [executionResult, setExecutionResult] = useState(null);
  const [tools, setTools] = useState(null);
  const [systemInfo, setSystemInfo] = useState(null);

  useEffect(() => {
    loadTools();
    loadSystemInfo();
  }, []);

  const loadTools = async () => {
    try {
      const toolsData = await window.electronAPI.getTools();
      setTools(toolsData);
    } catch (error) {
      console.error('Failed to load tools:', error);
    }
  };

  const loadSystemInfo = async () => {
    try {
      const info = await window.electronAPI.getSystemInfo();
      setSystemInfo(info);
    } catch (error) {
      console.error('Failed to load system info:', error);
    }
  };

  const handleToolSelect = (tool) => {
    setSelectedTool(tool);
    setActiveTab('execution');
  };

  const handleToolExecute = async (tool, args = []) => {
    setIsExecuting(true);
    setExecutionOutput('');
    setExecutionResult(null);

    const outputHandler = (data) => {
      setExecutionOutput(prev => prev + data);
    };

    const errorHandler = (data) => {
      setExecutionOutput(prev => prev + data);
    };

    window.electronAPI.onToolOutput(outputHandler);
    window.electronAPI.onToolError(errorHandler);

    try {
      const result = await window.electronAPI.executeTool(tool.id, args);
      setExecutionResult(result);
    } catch (error) {
      setExecutionResult({
        exitCode: -1,
        output: executionOutput,
        error: error.message,
        success: false
      });
    } finally {
      window.electronAPI.removeListeners();
      setIsExecuting(false);
    }
  };

  const handleRunFullScan = async () => {
    setIsExecuting(true);
    setExecutionOutput('');
    setExecutionResult(null);
    setSelectedTool(null);
    setActiveTab('execution');

    const outputHandler = (data) => {
      setExecutionOutput(prev => prev + data);
    };

    window.electronAPI.onToolOutput(outputHandler);

    try {
      const results = await window.electronAPI.runFullScan();
      setExecutionResult({
        exitCode: 0,
        output: executionOutput,
        success: true,
        scanResults: results
      });
    } catch (error) {
      setExecutionResult({
        exitCode: -1,
        output: executionOutput,
        error: error.message,
        success: false
      });
    } finally {
      window.electronAPI.removeListeners();
      setIsExecuting(false);
    }
  };

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'tools', label: 'Tools', icon: Shield },
    { id: 'execution', label: 'Execution', icon: PlaySquare },
    { id: 'results', label: 'Results', icon: FileText },
  ];

  const copySystemSummary = async () => {
    if (!systemInfo) return;
    const summary = [
      `Platform: ${systemInfo.platform}`,
      `Arch: ${systemInfo.arch}`,
      `Hostname: ${systemInfo.hostname}`,
      `CPU Cores: ${systemInfo.cpus}`,
      `Memory: ${systemInfo.totalmem ? `${(systemInfo.totalmem / 1024 / 1024 / 1024).toFixed(1)} GB` : 'Unknown'}`,
    ].join('\n');
    try {
      await navigator.clipboard.writeText(summary);
    } catch (e) {
      console.error('Failed to copy system summary:', e);
    }
  };

  return (
    <div className="h-screen bg-background text-foreground">
      <div className="h-full grid-faint">
        <div className="h-full flex">
          {/* Sidebar */}
          <div className="w-72 bg-card/95 backdrop-blur border-r border-border flex flex-col">
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-ring flex items-center justify-center shadow">
                    <Shield className="w-5 h-5 text-primary-foreground" />
                  </div>
                  <div>
                    <h1 className="font-semibold tracking-tight">Apple OS Forensic Analyzer</h1>
                    <p className="text-xs text-muted-foreground">Advanced threat hunting console</p>
                  </div>
                </div>
                <div className="text-xs text-muted-foreground">v2.0.0</div>
              </div>
            </div>

            <nav className="flex-1 p-4 space-y-1">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`group w-full flex items-center justify-between px-4 py-3 rounded-xl transition-colors ${
                    activeTab === tab.id
                      ? 'bg-muted text-foreground'
                      : 'hover:bg-muted/70 text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <span className="flex items-center gap-3">
                    <tab.icon className="w-5 h-5" />
                    <span className="font-medium">{tab.label}</span>
                  </span>
                  <ChevronRight className={`w-4 h-4 transition-opacity ${activeTab === tab.id ? 'opacity-80' : 'opacity-0 group-hover:opacity-60'}`} />
                </button>
              ))}
            </nav>

            {/* System Capsule */}
            {systemInfo && (
              <div className="p-4 border-t border-border">
                <div className="rounded-xl bg-background/40 border border-border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="text-xs font-semibold text-muted-foreground tracking-wide">SYSTEM</div>
                    <button
                      onClick={copySystemSummary}
                      className="p-2 rounded-lg hover:bg-muted/60 transition-colors"
                      title="Copy system summary"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex items-center justify-between gap-3">
                      <span className="flex items-center gap-2 text-muted-foreground"><Monitor className="w-4 h-4" /> Host</span>
                      <span className="font-medium truncate max-w-[11rem]" title={systemInfo.hostname}>{systemInfo.hostname}</span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="flex items-center gap-2 text-muted-foreground"><Cpu className="w-4 h-4" /> CPU</span>
                      <span className="font-medium">{systemInfo.arch} • {systemInfo.cpus}</span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="flex items-center gap-2 text-muted-foreground"><HardDrive className="w-4 h-4" /> RAM</span>
                      <span className="font-medium">{systemInfo.totalmem ? `${(systemInfo.totalmem / 1024 / 1024 / 1024).toFixed(1)} GB` : 'Unknown'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Main Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Command Bar */}
            <div className="h-16 border-b border-border flex items-center justify-between px-6 bg-background/60 backdrop-blur">
              <div className="flex items-center gap-3">
                <h2 className="text-lg font-semibold tracking-tight">
                  {tabs.find(t => t.id === activeTab)?.label}
                </h2>
                {selectedTool && activeTab === 'execution' && (
                  <span className="text-xs px-2 py-1 rounded-full bg-muted text-muted-foreground border border-border">
                    {selectedTool.name}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                {isExecuting && (
                  <div className="flex items-center gap-2 text-sm">
                    <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
                    <span className="text-accent font-medium">Executing</span>
                  </div>
                )}
                <div className="hidden md:flex items-center gap-2 text-xs text-muted-foreground">
                  <Terminal className="w-4 h-4" />
                  <span>Root-enabled workflows supported</span>
                </div>
              </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-auto p-6">
              {activeTab === 'dashboard' && (
                <Dashboard
                  tools={tools}
                  onToolSelect={handleToolSelect}
                  systemInfo={systemInfo}
                  onRunFullScan={handleRunFullScan}
                />
              )}

              {activeTab === 'tools' && tools && (
                <ToolCatalog
                  tools={tools}
                  onToolSelect={handleToolSelect}
                />
              )}

              {activeTab === 'execution' && (
                <ExecutionPanel
                  tool={selectedTool}
                  isExecuting={isExecuting}
                  output={executionOutput}
                  result={executionResult}
                  onExecute={handleToolExecute}
                />
              )}

              {activeTab === 'results' && (
                <ResultsViewer />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
