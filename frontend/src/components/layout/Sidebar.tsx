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
  SlidersHorizontal,
  X,
  Flame,
  Check,
  ShieldCheck,
  Globe,
  Filter
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

export interface FilterState {
  searchQuery: string;
  severity: string;
  hasPoc: boolean | null;
  iocType: string;
  actorRegion: string;
  minConfidence: number;
}

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  filters: FilterState;
  setFilters: React.Dispatch<React.SetStateAction<FilterState>>;
  isNestedOpen: boolean;
  setIsNestedOpen: (open: boolean) => void;
}

interface NavItem {
  id: TabType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  filters,
  setFilters,
  isNestedOpen,
  setIsNestedOpen
}) => {
  const primaryNavItems: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'detections', label: 'Detections Flow', icon: Workflow },
    { id: 'cves', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'iocs', label: 'Indicators (IOCs)', icon: Database },
    { id: 'apt', label: 'Threat Actors', icon: Users },
    { id: 'malware', label: 'Malware & C2', icon: Binary },
    { id: 'pocs', label: 'Exploit Library', icon: Code2 },
    { id: 'export', label: 'Export & SIEM', icon: Download, badge: 'Coming Soon' },
  ];

  const severities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const iocTypes = ['ALL', 'IP', 'DOMAIN', 'SHA256', 'URL'];
  const regions = ['ALL', 'Russia', 'China', 'North Korea', 'Iran', 'Transnational'];

  const activeFilterCount = (
    (filters.severity && filters.severity !== 'ALL' ? 1 : 0) +
    (filters.hasPoc !== null ? 1 : 0) +
    (filters.iocType && filters.iocType !== 'ALL' ? 1 : 0) +
    (filters.actorRegion && filters.actorRegion !== 'ALL' ? 1 : 0) +
    (filters.minConfidence > 0 ? 1 : 0) +
    (filters.searchQuery ? 1 : 0)
  );

  const resetFilters = () => {
    setFilters({
      searchQuery: '',
      severity: 'ALL',
      hasPoc: null,
      iocType: 'ALL',
      actorRegion: 'ALL',
      minConfidence: 0
    });
  };

  return (
    <div className="flex h-screen shrink-0 select-none z-30">
      {/* 1. Primary Fixed Slim Navigation Rail (Fixed h-screen, 0 scroll) */}
      <aside className="w-16 bg-white border-r border-slate-200 flex flex-col justify-between items-center py-3 h-screen shrink-0 z-30">
        {/* Top: Official Logo */}
        <div className="flex flex-col items-center gap-4">
          <div className="w-9 h-9 rounded-lg bg-orange-50 border border-orange-200/80 p-1 flex items-center justify-center shadow-xs">
            <img src="/logo.png" alt="VegaIntel Logo" className="w-full h-full object-contain" />
          </div>

          {/* Primary Nav Icons */}
          <nav className="flex flex-col items-center gap-1.5 mt-2">
            {primaryNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <Tooltip key={item.id} content={item.badge ? `${item.label} (${item.badge})` : item.label}>
                  <button
                    type="button"
                    onClick={() => setActiveTab(item.id)}
                    className={`w-10 h-10 rounded-lg flex items-center justify-center transition-all ${
                      isActive
                        ? 'bg-orange-50 text-orange-600 font-bold border border-orange-200 shadow-2xs'
                        : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/80'
                    }`}
                    aria-label={item.label}
                  >
                    <Icon className="w-5 h-5 shrink-0" />
                  </button>
                </Tooltip>
              );
            })}
          </nav>
        </div>

        {/* Bottom: Filter Drawer Toggle & System Health */}
        <div className="flex flex-col items-center gap-3">
          <Tooltip content={isNestedOpen ? "Hide Filter Drawer" : "Open Filter Drawer"}>
            <button
              type="button"
              onClick={() => setIsNestedOpen(!isNestedOpen)}
              className={`w-10 h-10 rounded-lg flex items-center justify-center transition-all relative ${
                isNestedOpen
                  ? 'bg-slate-900 text-white shadow-xs'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
              }`}
              aria-label="Toggle nested filter sidebar"
            >
              <SlidersHorizontal className="w-4 h-4" />
              {activeFilterCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-orange-500 text-white text-[9px] font-mono font-bold flex items-center justify-center shadow-xs">
                  {activeFilterCount}
                </span>
              )}
            </button>
          </Tooltip>

          <div className="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20" title="All 10 Threat Feeds Active" />
        </div>
      </aside>

      {/* 2. Nested Secondary Filter Sidebar (Fixed h-screen, fixed layout, internal scroll only) */}
      {isNestedOpen && (
        <aside className="w-60 bg-slate-50/90 border-r border-slate-200 flex flex-col h-screen shrink-0 z-20 shadow-2xs animate-in slide-in-from-left-4 duration-150">
          {/* Header */}
          <div className="h-14 px-4 border-b border-slate-200 flex items-center justify-between shrink-0 bg-white">
            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-orange-600" />
              <span className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider">
                Telemetry Filters
              </span>
              {activeFilterCount > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-orange-100 text-orange-800 font-bold">
                  {activeFilterCount}
                </span>
              )}
            </div>

            {activeFilterCount > 0 ? (
              <button
                type="button"
                onClick={resetFilters}
                className="text-[11px] font-mono text-slate-400 hover:text-rose-600 font-semibold"
              >
                Reset
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setIsNestedOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-700"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Quick Search inside Filter Panel */}
          <div className="p-3 border-b border-slate-200/80 bg-white shrink-0">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter current view..."
                value={filters.searchQuery}
                onChange={(e) => setFilters(prev => ({ ...prev, searchQuery: e.target.value }))}
                className="w-full pl-8 pr-6 py-1.5 bg-slate-50 border border-slate-200 rounded-md text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:bg-white transition-all"
              />
              {filters.searchQuery && (
                <button
                  type="button"
                  onClick={() => setFilters(prev => ({ ...prev, searchQuery: '' }))}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>

          {/* Scrollable Filter Options (Internal scroll with clean styling) */}
          <div className="flex-1 overflow-y-auto p-3 space-y-4 font-mono text-xs">
            {/* Quick Threat Presets */}
            <div className="space-y-1.5">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Threat Presets
              </div>
              <div className="space-y-1">
                <button
                  type="button"
                  onClick={() => setFilters(prev => ({
                    ...prev,
                    severity: prev.severity === 'CRITICAL' ? 'ALL' : 'CRITICAL',
                    hasPoc: prev.hasPoc === true ? null : true
                  }))}
                  className={`w-full flex items-center justify-between p-2 rounded-md text-xs transition-colors border ${
                    filters.severity === 'CRITICAL' && filters.hasPoc === true
                      ? 'bg-rose-50 border-rose-300 text-rose-800 font-bold'
                      : 'bg-white border-slate-200/80 text-slate-700 hover:bg-slate-100/70'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <Flame className="w-3.5 h-3.5 text-rose-600" />
                    Critical In The Wild
                  </span>
                  {filters.severity === 'CRITICAL' && filters.hasPoc === true && (
                    <Check className="w-3.5 h-3.5 text-rose-600" />
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => setFilters(prev => ({
                    ...prev,
                    hasPoc: prev.hasPoc === true ? null : true
                  }))}
                  className={`w-full flex items-center justify-between p-2 rounded-md text-xs transition-colors border ${
                    filters.hasPoc === true
                      ? 'bg-amber-50 border-amber-300 text-amber-800 font-bold'
                      : 'bg-white border-slate-200/80 text-slate-700 hover:bg-slate-100/70'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <Code2 className="w-3.5 h-3.5 text-amber-600" />
                    Weaponized PoC
                  </span>
                  {filters.hasPoc === true && (
                    <Check className="w-3.5 h-3.5 text-amber-600" />
                  )}
                </button>
              </div>
            </div>

            {/* Severity Filter */}
            <div className="space-y-1.5">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                CVSS Severity
              </div>
              <div className="grid grid-cols-2 gap-1">
                {severities.map((sev) => {
                  const isSelected = (filters.severity || 'ALL') === sev;
                  return (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setFilters(prev => ({ ...prev, severity: sev }))}
                      className={`px-2 py-1.5 rounded-md text-[11px] font-semibold text-center transition-all border ${
                        isSelected
                          ? 'bg-orange-500 text-white border-orange-600 shadow-2xs font-bold'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100/80'
                      }`}
                    >
                      {sev}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Indicator Type Filter */}
            <div className="space-y-1.5">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Indicator (IOC) Type
              </div>
              <div className="flex flex-wrap gap-1">
                {iocTypes.map((type) => {
                  const isSelected = (filters.iocType || 'ALL') === type;
                  return (
                    <button
                      key={type}
                      type="button"
                      onClick={() => setFilters(prev => ({ ...prev, iocType: type }))}
                      className={`px-2 py-1 rounded text-[10px] font-mono transition-all border ${
                        isSelected
                          ? 'bg-slate-900 text-white border-slate-900 font-bold'
                          : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                      }`}
                    >
                      {type}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Threat Actor Origin Region */}
            <div className="space-y-1.5">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Adversary Origin
              </div>
              <div className="space-y-1">
                {regions.map((reg) => {
                  const isSelected = (filters.actorRegion || 'ALL') === reg;
                  return (
                    <button
                      key={reg}
                      type="button"
                      onClick={() => setFilters(prev => ({ ...prev, actorRegion: reg }))}
                      className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-[11px] transition-colors border ${
                        isSelected
                          ? 'bg-purple-50 border-purple-300 text-purple-900 font-bold'
                          : 'bg-white border-slate-200/80 text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <Globe className="w-3 h-3 text-slate-400" />
                        {reg}
                      </span>
                      {isSelected && <Check className="w-3 h-3 text-purple-700" />}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Confidence Threshold */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                <span>Min Confidence</span>
                <span className="text-slate-800 font-bold">{filters.minConfidence}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="95"
                step="5"
                value={filters.minConfidence}
                onChange={(e) => setFilters(prev => ({ ...prev, minConfidence: Number(e.target.value) }))}
                className="w-full accent-orange-500 cursor-pointer h-1.5 bg-slate-200 rounded-lg"
              />
              <div className="flex justify-between text-[9px] text-slate-400">
                <span>All (0%)</span>
                <span>Verified (85%)</span>
                <span>High (95%)</span>
              </div>
            </div>
          </div>

          {/* Fixed Status Footer */}
          <div className="p-3 border-t border-slate-200 bg-white text-[11px] font-mono text-slate-500 flex items-center justify-between shrink-0">
            <span className="flex items-center gap-1.5 text-emerald-700 font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" />
              10 Feeds Active
            </span>
            <span className="text-slate-400">v2.4 CTI</span>
          </div>
        </aside>
      )}
    </div>
  );
};
