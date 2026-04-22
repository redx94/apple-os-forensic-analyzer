import React, { useState } from 'react';
import { Search, Shield, BarChart3, Smartphone, Play, ChevronRight } from 'lucide-react';

export default function ToolCatalog({ tools, onToolSelect }) {
  const [selectedCategory, setSelectedCategory] = useState('collect');
  const [searchQuery, setSearchQuery] = useState('');

  const categories = [
    { id: 'collect', name: 'Collection', icon: Search, color: 'bg-blue-500' },
    { id: 'analyze', name: 'Analysis', icon: Shield, color: 'bg-purple-500' },
    { id: 'score', name: 'Scoring', icon: BarChart3, color: 'bg-green-500' },
    { id: 'ios', name: 'iOS', icon: Smartphone, color: 'bg-orange-500' },
  ];

  const filteredTools = tools?.[selectedCategory]?.filter(tool =>
    tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    tool.description.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <div className="flex h-full gap-6">
      {/* Category Sidebar */}
      <div className="w-64 bg-card rounded-lg border border-border flex flex-col">
        <div className="p-4 border-b border-border">
          <h2 className="font-semibold text-lg">Categories</h2>
        </div>
        <div className="flex-1 p-2 space-y-1">
          {categories.map(category => (
            <button
              key={category.id}
              onClick={() => setSelectedCategory(category.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                selectedCategory === category.id
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-muted text-muted-foreground hover:text-foreground'
              }`}
            >
              <div className={`w-8 h-8 ${category.color} rounded-lg flex items-center justify-center`}>
                <category.icon className="w-4 h-4 text-white" />
              </div>
              <span className="font-medium">{category.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tool List */}
      <div className="flex-1 bg-card rounded-lg border border-border flex flex-col">
        {/* Search Bar */}
        <div className="p-4 border-b border-border">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search tools..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
        </div>

        {/* Tools Grid */}
        <div className="flex-1 p-4 overflow-auto">
          <div className="grid grid-cols-2 gap-4">
            {filteredTools.map(tool => (
              <div
                key={tool.id}
                className="bg-background rounded-lg p-5 border border-border hover:border-primary transition-colors cursor-pointer group"
                onClick={() => onToolSelect(tool)}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                    <Play className="w-5 h-5 text-primary" />
                  </div>
                  <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-foreground transition-colors" />
                </div>
                <h3 className="font-semibold text-lg mb-2">{tool.name}</h3>
                <p className="text-sm text-muted-foreground mb-3">{tool.description}</p>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-1 bg-muted rounded text-xs font-medium">
                    {tool.category}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {filteredTools.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              No tools found matching "{searchQuery}"
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
