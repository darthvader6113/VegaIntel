import React from 'react';
import { RefreshCw, Plus, LogOut, User } from 'lucide-react';
import { TabType } from './Sidebar';
import { Tooltip } from '../ui/Tooltip';

interface HeaderProps {
  activeTab: TabType;
  isSyncing: boolean;
  onTriggerSync: () => void;
  onRequestIocOpen: () => void;
  onLogout: () => void;
  currentUser: any | null;
  uniqueIocs?: number;
  dedupRatio?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  isSyncing,
  onTriggerSync,
  onRequestIocOpen,
  onLogout,
  currentUser,
}) => {
  const titles: Record<TabType, { name: string; desc: string }> = {
    overview: { name: 'Overview', desc: 'Real-time threat intelligence and vulnerability telemetry' },
    detections: { name: 'Detections Flow', desc: 'Interactive correlation pipeline connecting IOCs, CVEs, APTs, and Payloads' },
    cves: { name: 'Vulnerabilities', desc: 'CVE vulnerability intelligence, CVSS scores, and weaponized exploit references' },
    iocs: { name: 'Indicators (IOCs)', desc: 'Canonical indicator database with deterministic deduplication and sighting history' },
    apt: { name: 'Threat Actors', desc: 'Adversary profiles, MITRE ATT&CK techniques, and active campaigns' },
    malware: { name: 'Malware & Payloads', desc: 'Ransomware strains, C2 infrastructure, and hash artifacts' },
    pocs: { name: 'Exploit Library', desc: 'Weaponized exploit metadata and proof-of-concept repository' },
    feeds: { name: 'Feed Sources', desc: 'Active threat intelligence feeds' },
    export: { name: 'Export & SIEM', desc: 'STIX 2.1 bundles, CSV data exports, and SIEM connectors' },
  };

  const current = titles[activeTab] || { name: 'Threat Intel', desc: 'Enterprise cybersecurity intelligence' };

  return (
    <header className="h-14 bg-white border-b border-slate-200 px-6 lg:px-8 flex items-center justify-between shrink-0 z-20 min-w-0">
      {/* Title & Description */}
      <div className="flex items-center gap-4 min-w-0">
        <div>
          <h1 className="text-sm font-semibold text-slate-900 tracking-tight">
            {current.name}
          </h1>
          <p className="text-[11px] text-slate-500 hidden md:block">
            {current.desc}
          </p>
        </div>
      </div>

      {/* Right Actions - Clean SaaS Toolbar with Ark UI Tooltips & Motion */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Fetch IOCs by CVE button */}
        <Tooltip content="Ingest and correlate threat indicators for any CVE ID">
          <button
            type="button"
            onClick={onRequestIocOpen}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 active:scale-[0.98] text-white text-xs font-medium shadow-xs transition-all cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Fetch by CVE</span>
          </button>
        </Tooltip>

        {/* Sync Button */}
        <Tooltip content={isSyncing ? "Ingesting live threat intelligence..." : "Trigger OSINT collection cycle"}>
          <button
            type="button"
            onClick={onTriggerSync}
            disabled={isSyncing}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 hover:border-slate-300 transition-all cursor-pointer ${
              isSyncing ? 'cursor-wait opacity-70' : 'active:scale-[0.98]'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${isSyncing ? 'animate-spin text-orange-500' : ''}`} />
            <span className="hidden sm:inline">{isSyncing ? 'Syncing...' : 'Sync'}</span>
          </button>
        </Tooltip>

        {/* User Profile & Logout */}
        {currentUser && (
          <div className="flex items-center gap-2 pl-2.5 ml-1 border-l border-slate-200">
            <div className="flex items-center gap-2 text-xs">
              <div className="w-7 h-7 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 font-medium text-[11px]">
                {currentUser.email ? currentUser.email.charAt(0).toUpperCase() : <User className="w-3.5 h-3.5" />}
              </div>
              <span className="font-medium text-slate-700 hidden lg:inline max-w-[140px] truncate">
                {currentUser.email}
              </span>
            </div>

            <Tooltip content="Sign Out">
              <button
                type="button"
                onClick={onLogout}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </Tooltip>
          </div>
        )}
      </div>
    </header>
  );
};
