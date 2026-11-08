import React, { useState } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Database,
  Users,
  Binary,
  Code2,
  Workflow,
  Download,
  Search,
  ChevronLeft,
  ChevronRight,
  Sparkles
} from 'lucide-react';
import { Tooltip } from '../ui/Tooltip';

export type TabType = 
  | 'overview' 
  | 'detections'
  | 'cves' 
  | 'iocs' 
  | 'apt' 
  | 'malware' 
  | 'pocs' 
  | 'feeds' 
  | 'export';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

interface NavItem {
  id: TabType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavGroup {
  name: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  isCollapsed,
  onToggleCollapse
}) => {
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
        { id: 'pocs', label: 'Exploit Library', icon: Code2 },
      ],
    },
    {
      name: 'Integrations',
      items: [
        { id: 'export', label: 'Export & SIEM', icon: Download, badge: 'Coming Soon' },
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
    <aside
      className={`bg-white border-r border-slate-200 flex flex-col h-screen shrink-0 select-none z-30 transition-all duration-200 ease-in-out ${
        isCollapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Brand Header & Collapse Toggle */}
      <div className={`h-14 flex items-center border-b border-slate-200 shrink-0 ${
        isCollapsed ? 'justify-center px-2' : 'justify-between px-4'
      }`}>
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-7 h-7 rounded-md bg-orange-500 text-white flex items-center justify-center font-bold text-sm shadow-xs shrink-0">
            V
          </div>
          {!isCollapsed && (
            <div className="min-w-0 flex-1">
              <div className="font-semibold text-xs tracking-tight text-slate-900 flex items-center gap-1.5">
                <span>VegaIntel</span>
                <span className="text-[10px] px-1 py-0.2 rounded bg-slate-100 text-slate-600 font-medium border border-slate-200">
                  CTI
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Collapse / Expand Toggle Button */}
        <button
          type="button"
          onClick={onToggleCollapse}
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-colors"
          title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Quick Search (only when expanded) */}
      {!isCollapsed && (
        <div className="p-3 border-b border-slate-100 shrink-0">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search navigation..."
              value={navSearch}
              onChange={(e) => setNavSearch(e.target.value)}
              className="w-full pl-8 pr-2 py-1.5 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-md text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all font-sans"
            />
          </div>
        </div>
      )}

      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-2 space-y-3 min-h-0">
        {filteredGroups.map((group) => (
          <div key={group.name} className="space-y-1">
            {!isCollapsed ? (
              <div className="px-2 py-1 text-[10px] font-semibold tracking-wider text-slate-400 uppercase">
                {group.name}
              </div>
            ) : (
              <div className="my-1.5 border-t border-slate-100" />
            )}

            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;

                const buttonElement = (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center rounded-md text-xs transition-colors ${
                      isCollapsed ? 'justify-center p-2.5' : 'gap-2.5 px-2.5 py-1.5 text-left'
                    } ${
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
                    {!isCollapsed && (
                      <span className="truncate flex-1">{item.label}</span>
                    )}
                    {!isCollapsed && item.badge && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 border border-amber-200 shrink-0 font-medium">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );

                if (isCollapsed) {
                  return (
                    <Tooltip key={item.id} content={item.badge ? `${item.label} (${item.badge})` : item.label}>
                      {buttonElement}
                    </Tooltip>
                  );
                }

                return buttonElement;
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Clean Minimal Footer */}
      <div className={`p-3 border-t border-slate-200 text-[11px] text-slate-400 flex items-center ${
        isCollapsed ? 'justify-center' : 'justify-between'
      }`}>
        {!isCollapsed && <span>VegaIntel Cloud</span>}
        <span className="inline-flex items-center gap-1 text-emerald-600 font-medium" title="Active Platform Engine">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          {!isCollapsed && <span>Active</span>}
        </span>
      </div>
    </aside>
  );
};
