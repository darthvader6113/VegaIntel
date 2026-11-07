import React from 'react';
import { RefreshCw, Shield, Sparkles, Plus, LogOut, ChevronRight, User } from 'lucide-react';
import { TabType } from './Sidebar';

interface HeaderProps {
  activeTab: TabType;
  isSyncing: boolean;
  onTriggerSync: () => void;
  onRequestIocOpen: () => void;
  onLogout: () => void;
  currentUser: any | null;
  uniqueIocs: number;
  dedupRatio: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  isSyncing,
  onTriggerSync,
  onRequestIocOpen,
  onLogout,
  currentUser,
  uniqueIocs,
  dedupRatio,
}) => {
  const titles: Record<TabType, { category: string; name: string; desc: string }> = {
    overview: { category: 'Operations', name: 'Platform Overview', desc: 'Real-time telemetry, deduplication efficiency, and OSINT feed state' },
    detections: { category: 'Operations', name: 'New Threat Detections (Flow)', desc: 'Live multi-feed visual correlation pipeline connecting IOCs, CVEs, APTs, and Payloads' },
    cves: { category: 'Threat Repository', name: 'CVE Vulnerabilities Explorer', desc: 'Vulnerability discovery, CVSS metrics, mapped IOC infrastructure & PoCs' },
    iocs: { category: 'Threat Repository', name: 'Canonical IOC Repository', desc: 'Deduplicated indicator database with granular sighting histories' },
    graph: { category: 'Correlation & Research', name: 'Threat Correlation Graph', desc: 'Interactive topology visualizer correlating CVEs, IOCs, APTs, and Malware' },
    apt: { category: 'Threat Repository', name: 'APT Threat Groups', desc: 'Nation-state actors, MITRE ATT&CK techniques, and active campaigns' },
    malware: { category: 'Threat Repository', name: 'Malware & Payloads', desc: 'Ransomware strains, C2 beacons, sample hashes, and delivery URLs' },
    pocs: { category: 'Correlation & Research', name: 'PoC & Exploit Library', desc: 'Weaponized exploit metadata and GitHub/Exploit-DB verification records' },
    feeds: { category: 'Pipeline & Admin', name: 'Feed Health & Ingestion', desc: 'Abuse.ch, CISA KEV, Emerging Threats, OpenPhish, and MITRE pipeline monitors' },
    export: { category: 'Pipeline & Admin', name: 'Export & SIEM Integration', desc: 'STIX 2.1 JSON bundle generator, CSV exporter, and RESTful query APIs' },
  };

  const current = titles[activeTab] || { category: 'Intelligence', name: 'Threat Intel', desc: 'Enterprise security intelligence' };

  return (
    <header className="h-16 bg-white/95 backdrop-blur-md border-b border-slate-200/90 px-6 lg:px-8 flex items-center justify-between shrink-0 shadow-xs z-20 min-w-0">
      {/* Breadcrumb & Module Title */}
      <div className="flex items-center gap-3 min-w-0 pr-4">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-0.5">
            <span>SOC Intel</span>
            <ChevronRight className="w-3 h-3 text-slate-300 shrink-0" />
            <span>{current.category}</span>
            <ChevronRight className="w-3 h-3 text-slate-300 shrink-0" />
            <span className="text-orange-600 font-semibold">{current.name}</span>
          </div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-slate-900 tracking-tight truncate">
              {current.name}
            </h1>
            <span className="hidden sm:inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 font-semibold shrink-0">
              STIX 2.1
            </span>
          </div>
        </div>
      </div>

      {/* Right Action Bar */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Deduplication Metric Pill */}
        <div className="hidden xl:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-600">
            <Shield className="w-3.5 h-3.5 text-orange-600" />
            <span>Canonical IOCs:</span>
            <span className="text-slate-900 font-bold">{uniqueIocs.toLocaleString()}</span>
          </div>
          <div className="h-3 w-px bg-slate-200" />
          <div className="flex items-center gap-1.5 text-slate-600">
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            <span>Deduplication:</span>
            <span className="text-emerald-700 font-bold">{dedupRatio}%</span>
          </div>
        </div>

        {/* CVE-Driven IOC Discovery button */}
        <button
          type="button"
          onClick={onRequestIocOpen}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 text-xs font-mono font-semibold border border-slate-200 shadow-xs hover:border-slate-300 transition-all"
        >
          <Plus className="w-3.5 h-3.5 text-orange-600" />
          <span className="hidden sm:inline">Fetch IOCs by CVE</span>
        </button>

        {/* Manual Trigger Sync Button */}
        <button
          type="button"
          onClick={onTriggerSync}
          disabled={isSyncing}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider font-mono transition-all ${
            isSyncing
              ? 'bg-orange-100 text-orange-700 border border-orange-200 cursor-wait'
              : 'bg-orange-500 hover:bg-orange-600 text-white shadow-xs active:scale-95'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">{isSyncing ? 'Syncing...' : 'Sync Feeds'}</span>
        </button>

        {/* User Profile Pill & Logout */}
        {currentUser && (
          <div className="flex items-center gap-2 pl-3 border-l border-slate-200">
            <div className="w-7 h-7 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 shrink-0">
              <User className="w-4 h-4 text-slate-600" />
            </div>
            <div className="hidden md:block text-left min-w-0 max-w-[130px]">
              <div className="text-[11px] font-mono text-slate-900 font-bold truncate">
                {currentUser.email}
              </div>
              <div className="text-[9px] font-mono text-slate-400 uppercase tracking-tight">
                {currentUser.role || 'SecOps Analyst'}
              </div>
            </div>
            <button
              type="button"
              onClick={onLogout}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 border border-transparent hover:border-rose-200 transition-all ml-1"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
