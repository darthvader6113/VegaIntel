import React, { useState } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Database,
  Users,
  Binary,
  Code2,
  Share2,
  Workflow,
  Download,
  Search,
  ExternalLink
} from 'lucide-react';

export type TabType = 
  | 'overview' 
  | 'detections'
  | 'cves' 
  | 'iocs' 
  | 'graph' 
  | 'apt' 
  | 'malware' 
  | 'pocs' 
  | 'feeds' 
  | 'export';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  dedupRatio?: number;
}

interface NavItem {
  id: TabType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  name: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const [navSearch, setNavSearch] = useState('');

  const navGroups: NavGroup[] = [
    {
      name: 'Intelligence',
      items: [
        { id: 'overview', label: 'Overview', icon: LayoutDashboard },
        { id: 'detections', label: 'Detections Flow', icon: Workflow },
      ],
    },
    {
      name: 'Repository',
      items: [
        { id: 'cves', label: 'Vulnerabilities', icon: ShieldAlert },
        { id: 'iocs', label: 'Indicators (IOCs)', icon: Database },
        { id: 'apt', label: 'Threat Actors', icon: Users },
        { id: 'malware', label: 'Malware & C2', icon: Binary },
      ],
    },
    {
      name: 'Investigation',
      items: [
        { id: 'graph', label: 'Threat Graph', icon: Share2 },
        { id: 'pocs', label: 'Exploit Library', icon: Code2 },
      ],
    },
    {
      name: 'Integrations',
      items: [
        { id: 'export', label: 'Export & SIEM', icon: Download },
      ],
    },
  ];

  // Filter items if searching in navigation
  const filteredGroups = navGroups.map(group => ({
    ...group,
    items: group.items.filter(item => 
      !navSearch || 
      item.label.toLowerCase().includes(navSearch.toLowerCase()) ||
      item.id.toLowerCase().includes(navSearch.toLowerCase())
    )
  })).filter(group => group.items.length > 0);

  return (
    <aside className="w-60 bg-white border-r border-slate-200 flex flex-col h-screen shrink-0 select-none z-30">
      {/* Brand Header */}
      <div className="h-14 flex items-center px-4 border-b border-slate-200 gap-3 shrink-0">
        <div className="w-7 h-7 rounded-lg bg-orange-500 text-white flex items-center justify-center font-bold text-sm shadow-xs">
          V
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-semibold text-xs tracking-tight text-slate-900 flex items-center gap-1.5">
            <span>VegaIntel</span>
            <span className="text-[10px] px-1 py-0.2 rounded bg-slate-100 text-slate-600 font-medium border border-slate-200">
              CTI
            </span>
          </div>
        </div>
      </div>

      {/* Quick Search */}
      <div className="p-3 border-b border-slate-100 shrink-0">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search navigation..."
            value={navSearch}
            onChange={(e) => setNavSearch(e.target.value)}
            className="w-full pl-8 pr-2 py-1.5 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-md text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>
      </div>

      {/* Clean Navigation Groups */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-2.5 space-y-4 min-h-0">
        {filteredGroups.map((group) => (
          <div key={group.name} className="space-y-1">
            <div className="px-2 py-1 text-[11px] font-medium tracking-wide text-slate-400 uppercase">
              {group.name}
            </div>

            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs transition-colors text-left ${
                      isActive
                        ? 'bg-orange-50 text-orange-600 font-semibold'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-normal'
                    }`}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        isActive ? 'text-orange-600' : 'text-slate-400 group-hover:text-slate-600'
                      }`}
                    />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Clean Minimal Footer */}
      <div className="p-3 border-t border-slate-200 text-[11px] text-slate-400 flex items-center justify-between">
        <span>VegaIntel Cloud</span>
        <span className="inline-flex items-center gap-1 text-emerald-600 font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          Active
        </span>
      </div>
    </aside>
  );
};
