import React from 'react';
import { Search, Shield, BarChart3, Smartphone, Activity, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

export default function Dashboard({ tools, onToolSelect, systemInfo }) {
  const categories = [
    { id: 'collect', name: 'Collection', icon: Search, color: 'bg-blue-500' },
    { id: 'analyze', name: 'Analysis', icon: Shield, color: 'bg-purple-500' },
    { id: 'score', name: 'Scoring', icon: BarChart3, color: 'bg-green-500' },
    { id: 'ios', name: 'iOS', icon: Smartphone, color: 'bg-orange-500' },
  ];

  const recentActivity = [
    { tool: 'Extract Identifiers', status: 'completed', time: '2 hours ago' },
    { tool: 'Detect Suspicious Agents', status: 'completed', time: '3 hours ago' },
    { tool: 'Generate Evidence Manifest', status: 'completed', time: '5 hours ago' },
  ];

  const systemStatus = [
    { label: 'Platform', value: systemInfo?.platform || 'Unknown' },
    { label: 'Architecture', value: systemInfo?.arch || 'Unknown' },
    { label: 'CPU Cores', value: systemInfo?.cpus || 'Unknown' },
    { label: 'Memory', value: systemInfo?.totalmem ? `${(systemInfo.totalmem / 1024 / 1024 / 1024).toFixed(1)} GB` : 'Unknown' },
  ];

  const handleRequestPermissions = async () => {
    await window.electronAPI.requestPermissions();
  };

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-primary/20 to-accent/20 rounded-xl p-8 border border-border">
        <h1 className="text-3xl font-bold mb-2">Welcome to Apple OS Forensic Analyzer</h1>
        <p className="text-muted-foreground text-lg">
          Professional forensic analysis suite for macOS and iOS security investigation
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-card rounded-lg p-6 border border-border">
          <div className="flex items-center justify-between mb-2">
            <Shield className="w-8 h-8 text-primary" />
            <span className="text-2xl font-bold">12</span>
          </div>
          <p className="text-sm text-muted-foreground">Total Tools</p>
        </div>
        <div className="bg-card rounded-lg p-6 border border-border">
          <div className="flex items-center justify-between mb-2">
            <CheckCircle className="w-8 h-8 text-accent" />
            <span className="text-2xl font-bold">3</span>
          </div>
          <p className="text-sm text-muted-foreground">Recent Scans</p>
        </div>
        <div className="bg-card rounded-lg p-6 border border-border">
          <div className="flex items-center justify-between mb-2">
            <AlertTriangle className="w-8 h-8 text-destructive" />
            <span className="text-2xl font-bold">0</span>
          </div>
          <p className="text-sm text-muted-foreground">Active Alerts</p>
        </div>
        <div className="bg-card rounded-lg p-6 border border-border">
          <div className="flex items-center justify-between mb-2">
            <Activity className="w-8 h-8 text-yellow-500" />
            <span className="text-2xl font-bold">v2.0</span>
          </div>
          <p className="text-sm text-muted-foreground">Suite Version</p>
        </div>
      </div>

      {/* Tool Categories */}
      <div>
        <h2 className="text-xl font-semibold mb-4">Tool Categories</h2>
        <div className="grid grid-cols-4 gap-4">
          {categories.map(category => {
            const toolCount = tools?.[category.id]?.length || 0;
            return (
              <button
                key={category.id}
                onClick={() => {
                  const firstTool = tools?.[category.id]?.[0];
                  if (firstTool) onToolSelect(firstTool);
                }}
                className="bg-card rounded-lg p-6 border border-border hover:border-primary transition-colors group"
              >
                <div className={`w-12 h-12 ${category.color} rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                  <category.icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="font-semibold text-lg mb-1">{category.name}</h3>
                <p className="text-sm text-muted-foreground">{toolCount} tools</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* System Info & Recent Activity */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-card rounded-lg p-6 border border-border">
          <h2 className="text-xl font-semibold mb-4">System Information</h2>
          <div className="space-y-3">
            {systemStatus.map(item => (
              <div key={item.label} className="flex justify-between items-center py-2 border-b border-border/50">
                <span className="text-muted-foreground">{item.label}</span>
                <span className="font-mono text-sm">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-card rounded-lg p-6 border border-border">
          <h2 className="text-xl font-semibold mb-4">Recent Activity</h2>
          <div className="space-y-3">
            {recentActivity.map((activity, index) => (
              <div key={index} className="flex items-center justify-between py-2 border-b border-border/50">
                <div className="flex items-center gap-3">
                  <Clock className="w-4 h-4 text-muted-foreground" />
                  <span>{activity.tool}</span>
                </div>
                <div className="flex items-center gap-2">
                  {activity.status === 'completed' && (
                    <CheckCircle className="w-4 h-4 text-accent" />
                  )}
                  <span className="text-sm text-muted-foreground">{activity.time}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-xl font-semibold mb-4">Quick Actions</h2>
        <div className="grid grid-cols-4 gap-4">
          <button
            onClick={() => {
              const tool = tools?.collect?.find(t => t.id === 'extract_ids_all');
              if (tool) onToolSelect(tool);
            }}
            className="bg-primary text-primary-foreground rounded-lg p-4 hover:bg-primary/90 transition-colors"
          >
            <div className="font-semibold mb-1">Full Scan</div>
            <div className="text-sm opacity-90">Extract all identifiers</div>
          </button>
          <button
            onClick={() => {
              const tool = tools?.score?.find(t => t.id === 'detect_agents');
              if (tool) onToolSelect(tool);
            }}
            className="bg-secondary text-secondary-foreground rounded-lg p-4 hover:bg-secondary/80 transition-colors"
          >
            <div className="font-semibold mb-1">Persistence Scan</div>
            <div className="text-sm opacity-90">Check for suspicious agents</div>
          </button>
          <button
            onClick={() => {
              const tool = tools?.collect?.find(t => t.id === 'manifest_generator');
              if (tool) onToolSelect(tool);
            }}
            className="bg-secondary text-secondary-foreground rounded-lg p-4 hover:bg-secondary/80 transition-colors"
          >
            <div className="font-semibold mb-1">Generate Manifest</div>
            <div className="text-sm opacity-90">Create evidence manifest</div>
          </button>
          <button
            onClick={handleRequestPermissions}
            className="bg-destructive text-destructive-foreground rounded-lg p-4 hover:bg-destructive/90 transition-colors"
          >
            <div className="font-semibold mb-1">Request Permissions</div>
            <div className="text-sm opacity-90">Grant Full Disk Access</div>
          </button>
        </div>
      </div>
    </div>
  );
}
