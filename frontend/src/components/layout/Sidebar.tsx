import React from 'react';
import { Tabs } from '@ark-ui/react';
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
  Workflow
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

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, dedupRatio }) => {
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'detections', label: 'New Detections (Flow)', icon: Workflow, badge: 'React Flow' },
    { id: 'cves', label: 'CVE Explorer', icon: ShieldAlert },
    { id: 'iocs', label: 'IOC Repository', icon: Database, badge: `${dedupRatio}% saved` },
    { id: 'graph', label: 'Threat Graph', icon: Share2 },
    { id: 'apt', label: 'APT Groups', icon: Users },
    { id: 'malware', label: 'Malware & Payloads', icon: Binary },
    { id: 'pocs', label: 'PoC Library', icon: Code2 },
    { id: 'feeds', label: 'Feed Monitoring', icon: Activity },
    { id: 'export', label: 'Export & API', icon: Download },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between shrink-0 select-none shadow-sm">
      <div>
        {/* Brand Logo */}
        <div className="h-16 flex items-center px-6 border-b border-slate-200 gap-3">
          <img
            src="/logo.png"
            alt="VegaIntel"
            className="w-9 h-9 object-contain rounded-lg shadow-sm border border-slate-200"
          />
          <div>
            <div className="font-bold text-base tracking-wider text-slate-900 flex items-center gap-1.5">
              VEGA<span className="text-orange-600 font-extrabold">INTEL</span>
            </div>
            <div className="text-[10px] text-slate-500 font-mono tracking-tight uppercase">
              Threat Intelligence Platform
            </div>
          </div>
        </div>

        {/* Ark UI Vertical Navigation Tabs */}
        <Tabs.Root
          value={activeTab}
          onValueChange={(details) => setActiveTab(details.value as TabType)}
          orientation="vertical"
          className="p-3 space-y-1"
        >
          <div className="px-3 py-2 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-mono">
            Intelligence Modules
          </div>
          <Tabs.List className="space-y-1 w-full">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <Tabs.Trigger
                  key={item.id}
                  value={item.id}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-orange-50 text-orange-600 border border-orange-200 shadow-sm font-semibold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-orange-600' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold border ${
                      item.id === 'detections'
                        ? 'bg-amber-100 text-amber-800 border-amber-200'
                        : 'bg-orange-100 text-orange-800 border-orange-200'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </Tabs.Trigger>
              );
            })}
          </Tabs.List>
        </Tabs.Root>
      </div>

      {/* System Status footer */}
      <div className="p-4 border-t border-slate-200 bg-slate-50">
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-slate-500 font-medium">Ingestion Pipeline</span>
          <span className="flex items-center gap-1.5 text-emerald-600 font-mono text-[11px] font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            OPERATIONAL
          </span>
        </div>
        <div className="text-[11px] text-slate-500 font-mono">
          5 OSINT Feeds · Auto-Deduplication
        </div>
      </div>
    </aside>
  );
};
