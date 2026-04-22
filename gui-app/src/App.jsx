import React, { useState, useEffect } from 'react';
import { Shield, Search, BarChart3, Smartphone, PlaySquare, FileText, Settings, Activity, Terminal } from 'lucide-react';
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

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'tools', label: 'Tools', icon: Shield },
    { id: 'execution', label: 'Execution', icon: PlaySquare },
    { id: 'results', label: 'Results', icon: FileText },
  ];

  return (
    <div className="flex h-screen bg-background text-foreground">
      {/* Sidebar */}
      <div className="w-64 bg-card border-r border-border flex flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-lg">Forensic Analyzer</h1>
              <p className="text-xs text-muted-foreground">v2.0.0</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-muted text-muted-foreground hover:text-foreground'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              <span className="font-medium">{tab.label}</span>
            </button>
          ))}
        </nav>

        {systemInfo && (
          <div className="p-4 border-t border-border">
            <div className="text-xs text-muted-foreground space-y-1">
              <div className="flex justify-between">
                <span>Platform:</span>
                <span className="text-foreground">{systemInfo.platform}</span>
              </div>
              <div className="flex justify-between">
                <span>Arch:</span>
                <span className="text-foreground">{systemInfo.arch}</span>
              </div>
              <div className="flex justify-between">
                <span>Hostname:</span>
                <span className="text-foreground">{systemInfo.hostname}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="h-16 border-b border-border flex items-center justify-between px-6 bg-background">
          <h2 className="text-xl font-semibold">
            {tabs.find(t => t.id === activeTab)?.label}
          </h2>
          <div className="flex items-center gap-4">
            {isExecuting && (
              <div className="flex items-center gap-2 text-sm text-accent">
                <div className="w-2 h-2 bg-accent rounded-full animate-pulse" />
                <span>Executing...</span>
              </div>
            )}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {activeTab === 'dashboard' && (
            <Dashboard
              tools={tools}
              onToolSelect={handleToolSelect}
              systemInfo={systemInfo}
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
  );
}

export default App;
