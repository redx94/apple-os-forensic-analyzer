import React, { useState, useEffect, useRef } from 'react';
import { Play, Square, Terminal, AlertCircle, CheckCircle, XCircle, Copy, Download } from 'lucide-react';

export default function ExecutionPanel({ tool, isExecuting, output, result, onExecute }) {
  const [customArgs, setCustomArgs] = useState('');
  const outputRef = useRef(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const handleExecute = () => {
    const args = customArgs.split(' ').filter(arg => arg.length > 0);
    onExecute(tool, args);
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output);
  };

  const downloadOutput = () => {
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${tool.id}_output.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!tool) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center text-muted-foreground">
          <Terminal className="w-16 h-16 mx-auto mb-4 opacity-50" />
          <p>Select a tool from the Tools tab to execute</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Tool Info */}
      <div className="bg-card rounded-lg p-6 border border-border">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold mb-2">{tool.name}</h2>
            <p className="text-muted-foreground">{tool.description}</p>
          </div>
          <div className="px-3 py-1 bg-primary/10 text-primary rounded-full text-sm font-medium">
            {tool.category}
          </div>
        </div>

        {/* Custom Args Input */}
        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Custom arguments (optional)"
            value={customArgs}
            onChange={(e) => setCustomArgs(e.target.value)}
            disabled={isExecuting}
            className="flex-1 px-4 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
          />
          <button
            onClick={handleExecute}
            disabled={isExecuting}
            className="px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isExecuting ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Executing...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Execute
              </>
            )}
          </button>
        </div>
      </div>

      {/* Execution Result Status */}
      {result && (
        <div className={`rounded-lg p-4 border ${
          result.success 
            ? 'bg-accent/10 border-accent' 
            : 'bg-destructive/10 border-destructive'
        }`}>
          <div className="flex items-center gap-3">
            {result.success ? (
              <CheckCircle className="w-5 h-5 text-accent" />
            ) : (
              <XCircle className="w-5 h-5 text-destructive" />
            )}
            <div>
              <span className="font-semibold">
                {result.success ? 'Execution Completed Successfully' : 'Execution Failed'}
              </span>
              <span className="text-muted-foreground ml-2">
                (Exit Code: {result.exitCode})
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Terminal Output */}
      <div className="flex-1 bg-card rounded-lg border border-border flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            <span className="font-medium">Output</span>
          </div>
          <div className="flex items-center gap-2">
            {output && (
              <>
                <button
                  onClick={copyOutput}
                  className="p-2 hover:bg-background rounded transition-colors"
                  title="Copy output"
                >
                  <Copy className="w-4 h-4" />
                </button>
                <button
                  onClick={downloadOutput}
                  className="p-2 hover:bg-background rounded transition-colors"
                  title="Download output"
                >
                  <Download className="w-4 h-4" />
                </button>
              </>
            )}
          </div>
        </div>
        <div
          ref={outputRef}
          className="flex-1 p-4 font-mono text-sm overflow-auto bg-background"
        >
          <pre className="whitespace-pre-wrap break-words">{output || 'No output yet. Execute the tool to see output here.'}</pre>
        </div>
      </div>
    </div>
  );
}
