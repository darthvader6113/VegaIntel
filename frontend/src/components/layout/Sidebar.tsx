import React, { useState } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Database,
  Users,
  Binary,
  Code2,
  Activity,
  Download,
  Share2,
  Workflow,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
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
  dedupRatio: number;
}

interface NavItem {
  id: TabType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  badgeColor?: string;
}

interface NavGroup {
  name: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, dedupRatio }) => {
  const [navSearch, setNavSearch] = useState('');
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({
    'OPERATIONS': true,
    'THREAT REPOSITORY': true,
    'CORRELATION & RESEARCH': true,
    'PIPELINE & ADMIN': true,
  });

  const toggleGroup = (groupName: string) => {
    setExpandedGroups(prev => ({
      ...prev,
      [groupName]: !prev[groupName]
    }));
  };

  const navGroups: NavGroup[] = [
    {
      name: 'OPERATIONS',
      items: [
        { id: 'overview', label: 'Platform Overview', icon: LayoutDashboard, badge: 'LIVE', badgeColor: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
        { id: 'detections', label: 'New Detections Flow', icon: Workflow, badge: 'FLOW', badgeColor: 'bg-amber-50 text-amber-700 border-amber-200' },
      ],
    },
    {
      name: 'THREAT REPOSITORY',
      items: [
        { id: 'cves', label: 'CVE Explorer', icon: ShieldAlert, badge: 'NVD/KEV', badgeColor: 'bg-red-50 text-red-700 border-red-200' },
        { id: 'iocs', label: 'Canonical IOCs', icon: Database, badge: `${dedupRatio}% saved`, badgeColor: 'bg-orange-50 text-orange-700 border-orange-200' },
        { id: 'apt', label: 'Threat Actors & APTs', icon: Users, badge: 'MITRE', badgeColor: 'bg-purple-50 text-purple-700 border-purple-200' },
        { id: 'malware', label: 'Malware & Payloads', icon: Binary, badge: 'C2/YARA', badgeColor: 'bg-rose-50 text-rose-700 border-rose-200' },
      ],
    },
    {
      name: 'CORRELATION & RESEARCH',
      items: [
        { id: 'graph', label: 'Threat Graph Topology', icon: Share2, badge: 'CORRELATION', badgeColor: 'bg-blue-50 text-blue-700 border-blue-200' },
        { id: 'pocs', label: 'PoC Exploit Library', icon: Code2, badge: 'EXPLOITS', badgeColor: 'bg-amber-50 text-amber-700 border-amber-200' },
      ],
    },
    {
      name: 'PIPELINE & ADMIN',
      items: [
        { id: 'feeds', label: 'Feed Ingestion & Health', icon: Activity, badge: '5 FEEDS', badgeColor: 'bg-teal-50 text-teal-700 border-teal-200' },
        { id: 'export', label: 'Export & SIEM API', icon: Download, badge: 'STIX 2.1', badgeColor: 'bg-slate-100 text-slate-700 border-slate-200' },
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
    <aside className="w-64 xl:w-72 bg-white border-r border-slate-200/90 flex flex-col h-screen shrink-0 select-none shadow-[1px_0_4px_rgba(0,0,0,0.02)] z-30">
      {/* Brand & Organization Header */}
      <div className="h-16 flex items-center px-5 border-b border-slate-200 gap-3 shrink-0 bg-white">
        <div className="relative">
          <img
            src="/logo.png"
            alt="VegaIntel"
            className="w-9 h-9 object-contain rounded-xl shadow-sm border border-slate-200/80 p-0.5 bg-slate-50"
          />
          <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-500 ring-2 ring-white" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-bold text-sm tracking-wide text-slate-900 flex items-center gap-1.5 truncate">
            <span>VEGA</span>
            <span className="text-orange-600 font-extrabold">INTEL</span>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-orange-100 text-orange-800 font-mono font-bold">
              PRO
            </span>
          </div>
          <div className="text-[10px] text-slate-400 font-mono tracking-tight uppercase truncate">
            Enterprise Threat Platform
          </div>
        </div>
      </div>

      {/* Quick Navigation Search */}
      <div className="p-3 border-b border-slate-100 shrink-0">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Quick jump (e.g. CVE, IOC)..."
            value={navSearch}
            onChange={(e) => setNavSearch(e.target.value)}
            className="w-full pl-8 pr-2 py-1.5 bg-slate-50 hover:bg-slate-100/80 focus:bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>
      </div>

      {/* Nested Navigation Groups (Zero Overflow, custom scrollbar) */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-3 space-y-4 min-h-0">
        {filteredGroups.map((group) => {
          const isExpanded = expandedGroups[group.name] ?? true;
          return (
            <div key={group.name} className="space-y-1">
              {/* Nested Group Header with Collapse Toggle */}
              <button
                type="button"
                onClick={() => toggleGroup(group.name)}
                className="w-full flex items-center justify-between px-2.5 py-1 text-[10px] font-bold tracking-wider text-slate-400 hover:text-slate-600 uppercase font-mono rounded transition-colors"
              >
                <span>{group.name}</span>
                {isExpanded ? (
                  <ChevronDown className="w-3 h-3 text-slate-400" />
                ) : (
                  <ChevronRight className="w-3 h-3 text-slate-400" />
                )}
              </button>

              {/* Nested Nav Items */}
              {isExpanded && (
                <div className="space-y-0.5 pt-0.5">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setActiveTab(item.id)}
                        className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                          isActive
                            ? 'bg-orange-50 text-orange-700 border border-orange-200/80 shadow-xs font-semibold'
                            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/70 border border-transparent'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            className={`w-4 h-4 shrink-0 transition-colors ${
                              isActive
                                ? 'text-orange-600'
                                : 'text-slate-400 group-hover:text-slate-700'
                            }`}
                          />
                          <span className="truncate">{item.label}</span>
                        </div>

                        {item.badge && (
                          <span
                            className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold border shrink-0 ${
                              isActive
                                ? 'bg-orange-600 text-white border-orange-600 shadow-xs'
                                : item.badgeColor || 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Enterprise System Diagnostics Footer */}
      <div className="p-3.5 border-t border-slate-200 bg-slate-50/70 shrink-0 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-1.5 text-slate-600 text-[11px] font-mono font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Ingestion Engine</span>
          </div>
          <span className="text-[10px] font-mono font-bold text-emerald-700 px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200">
            HEALTHY
          </span>
        </div>

        <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-200/60">
          <span className="flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5 text-slate-400" />
            STIX 2.1 Standard
          </span>
          <span className="text-slate-700 font-semibold">{dedupRatio}% dedup</span>
        </div>
      </div>
    </aside>
  );
};
