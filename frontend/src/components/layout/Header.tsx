import React from 'react';
import { RefreshCw, Shield, Sparkles, Plus, LogOut } from 'lucide-react';
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
  const titles: Record<TabType, { name: string; desc: string }> = {
    overview: { name: 'Platform Overview', desc: 'Real-time telemetry, deduplication efficiency, and OSINT feed state' },
    detections: { name: 'New Threat Detections (React Flow)', desc: 'Live multi-feed visual correlation pipeline connecting IOCs, CVEs, APTs, and Payloads' },
    cves: { name: 'CVE Explorer', desc: 'Vulnerability discovery, CVSS metrics, mapped IOC infrastructure & PoCs' },
    iocs: { name: 'Canonical IOC Repository', desc: 'Deduplicated indicator database with granular sighting histories' },
    graph: { name: 'Threat Correlation Graph', desc: 'Interactive topology visualizer correlating CVEs, IOCs, APTs, and Malware' },
    apt: { name: 'APT Threat Groups', desc: 'Nation-state actors, MITRE ATT&CK techniques, and active campaigns' },
    malware: { name: 'Malware & Payloads', desc: 'Ransomware strains, C2 beacons, sample hashes, and delivery URLs' },
    pocs: { name: 'PoC & Exploit Library', desc: 'Weaponized exploit metadata and GitHub/Exploit-DB verification records' },
    feeds: { name: 'Feed Health & Ingestion', desc: 'Abuse.ch, CISA KEV, Emerging Threats, OpenPhish, and MITRE pipeline monitors' },
    export: { name: 'Export & SIEM Integration', desc: 'STIX 2.1 JSON bundle generator, CSV exporter, and RESTful query APIs' },
  };

  const current = titles[activeTab];

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-8 flex items-center justify-between shrink-0 shadow-sm">
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-lg font-semibold text-slate-900 tracking-tight flex items-center gap-2">
            {current.name}
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 font-semibold">
              STIX 2.1 READY
            </span>
          </h1>
          <p className="text-xs text-slate-500 tracking-wide">{current.desc}</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Deduplication Metric Pill */}
        <div className="hidden lg:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-600">
            <Shield className="w-3.5 h-3.5 text-orange-600" />
            <span>Canonical IOCs:</span>
            <span className="text-slate-900 font-bold">{uniqueIocs}</span>
          </div>
          <div className="h-3 w-px bg-slate-300" />
          <div className="flex items-center gap-1.5 text-slate-600">
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            <span>Deduplication:</span>
            <span className="text-emerald-700 font-bold">{dedupRatio}%</span>
          </div>
        </div>

        {/* On-Demand Request IOC button */}
        <button
          onClick={onRequestIocOpen}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 text-xs font-mono font-semibold border border-slate-300 shadow-sm transition-colors"
        >
          <Plus className="w-3.5 h-3.5 text-orange-600" />
          <span>Request IOC</span>
        </button>

        {/* Manual Trigger Sync Button */}
        <button
          onClick={onTriggerSync}
          disabled={isSyncing}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider font-mono transition-all ${
            isSyncing
              ? 'bg-orange-100 text-orange-700 border border-orange-300 cursor-wait'
              : 'bg-orange-500 hover:bg-orange-600 text-white shadow-sm active:scale-95'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
          <span>{isSyncing ? 'Syncing...' : 'Sync Feeds'}</span>
        </button>

        {/* User Profile Pill & Logout */}
        {currentUser && (
          <div className="flex items-center gap-2 pl-2 border-l border-slate-200">
            <div className="hidden sm:block text-right">
              <div className="text-[11px] font-mono text-slate-900 font-bold truncate max-w-[140px]">
                {currentUser.email}
              </div>
              <div className="text-[9px] font-mono text-orange-600 font-semibold uppercase">
                {currentUser.role || 'Analyst'}
              </div>
            </div>
            <button
              onClick={onLogout}
              className="p-1.5 rounded-lg bg-slate-100 hover:bg-red-50 hover:text-red-600 text-slate-500 border border-slate-200 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
