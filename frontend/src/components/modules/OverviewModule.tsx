import React from 'react';
import {
  ShieldAlert,
  Database,
  Users,
  Binary,
  ArrowUpRight,
  Activity,
  Code2
} from 'lucide-react';
import { OverviewStats } from '../../types';

interface OverviewModuleProps {
  stats: OverviewStats | null;
  onNavigate: (tab: any) => void;
}

const safeNumber = (val: number | undefined | null): string => {
  if (val === null || val === undefined || isNaN(val)) return '0';
  return val.toLocaleString();
};

export const OverviewModule: React.FC<OverviewModuleProps> = ({ stats, onNavigate }) => {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 text-xs gap-2">
        <Activity className="w-4 h-4 animate-spin text-orange-500" />
        <span>Loading telemetry...</span>
      </div>
    );
  }

  const { metrics, recent_sightings = [], ioc_type_distribution = [] } = stats;

  return (
    <div className="w-full space-y-6">
      {/* Sleek KPI Cards - Vercel / Neon style */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Vulnerabilities */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-1">
              <span className="text-xs font-medium text-slate-500">Vulnerabilities</span>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-2xl font-bold text-slate-900 tracking-tight">
              {safeNumber(metrics?.monitored_cves)}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
            <span className="text-rose-600 font-medium">{safeNumber(metrics?.critical_cves)} Critical</span>
            <button 
              type="button"
              onClick={() => onNavigate('cves')}
              className="text-slate-600 hover:text-slate-900 font-medium flex items-center gap-0.5"
            >
              View <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Indicators */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-1">
              <span className="text-xs font-medium text-slate-500">Indicators (IOCs)</span>
              <Database className="w-4 h-4 text-orange-500" />
            </div>
            <div className="text-2xl font-bold text-slate-900 tracking-tight">
              {safeNumber(metrics?.total_canonical_iocs)}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
            <span>Verified Indicators</span>
            <button 
              type="button"
              onClick={() => onNavigate('iocs')}
              className="text-slate-600 hover:text-slate-900 font-medium flex items-center gap-0.5"
            >
              View <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Threat Actors */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-1">
              <span className="text-xs font-medium text-slate-500">Threat Actors</span>
              <Users className="w-4 h-4 text-purple-500" />
            </div>
            <div className="text-2xl font-bold text-slate-900 tracking-tight">
              {safeNumber(metrics?.active_threat_actors)}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
            <span>MITRE ATT&CK Profiles</span>
            <button 
              type="button"
              onClick={() => onNavigate('apt')}
              className="text-slate-600 hover:text-slate-900 font-medium flex items-center gap-0.5"
            >
              View <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Malware Families */}
        <div className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-1">
              <span className="text-xs font-medium text-slate-500">Malware & C2</span>
              <Binary className="w-4 h-4 text-amber-500" />
            </div>
            <div className="text-2xl font-bold text-slate-900 tracking-tight">
              {safeNumber(metrics?.malware_families)}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
            <span>{safeNumber(metrics?.poc_references)} Exploit PoCs</span>
            <button 
              type="button"
              onClick={() => onNavigate('malware')}
              className="text-slate-600 hover:text-slate-900 font-medium flex items-center gap-0.5"
            >
              View <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Middle Section: Indicator Distribution & Platform Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Indicator Type Breakdown */}
        <div className="p-5 rounded-xl border border-slate-200 bg-white space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h3 className="text-xs font-semibold text-slate-900">
              Indicator Distribution
            </h3>
            <span className="text-xs text-slate-500">
              {safeNumber(metrics?.total_canonical_iocs)} total
            </span>
          </div>

          <div className="space-y-3">
            {ioc_type_distribution.map((item) => {
              const total = metrics?.total_canonical_iocs || 1;
              const pct = Math.round(((item.count || 0) / total) * 100);
              return (
                <div key={item.type} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="uppercase text-slate-600 font-medium">{item.type}</span>
                    <span className="text-slate-500">{safeNumber(item.count)} ({pct}%)</span>
                  </div>
                  <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                    <div 
                      className="bg-orange-500 h-full rounded-full transition-all duration-300"
                      style={{ width: `${Math.min(pct, 100)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Quick Intelligence Shortcuts */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-200 bg-white space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-xs font-semibold text-slate-900">
                Threat Intelligence Correlation
              </h3>
              <span className="text-xs text-emerald-600 font-medium">Real-time sync</span>
            </div>
            <p className="text-xs text-slate-500 mt-3 leading-relaxed">
              VegaIntel continuously correlates incoming vulnerabilities with observed cyber threat infrastructure, weaponized proof-of-concept scripts, and nation-state threat campaigns.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
            <button
              type="button"
              onClick={() => onNavigate('detections')}
              className="p-3 rounded-lg border border-slate-200 hover:border-orange-300 hover:bg-orange-50/50 text-left transition-all group"
            >
              <div className="text-xs font-medium text-slate-900 group-hover:text-orange-600">Detections Flow</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Live visual threat graph</div>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('cves')}
              className="p-3 rounded-lg border border-slate-200 hover:border-orange-300 hover:bg-orange-50/50 text-left transition-all group"
            >
              <div className="text-xs font-medium text-slate-900 group-hover:text-orange-600">CVE Explorer</div>
              <div className="text-[11px] text-slate-500 mt-0.5">CVSS & exploit analysis</div>
            </button>
            <button
              type="button"
              onClick={() => onNavigate('export')}
              className="p-3 rounded-lg border border-slate-200 hover:border-orange-300 hover:bg-orange-50/50 text-left transition-all group"
            >
              <div className="text-xs font-medium text-slate-900 group-hover:text-orange-600">SIEM Export</div>
              <div className="text-[11px] text-slate-500 mt-0.5">STIX 2.1 & CSV bundles</div>
            </button>
          </div>
        </div>
      </div>

      {/* Live Threat Sightings Stream */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
            <Activity className="w-4 h-4 text-orange-500" />
            <span>Recent Threat Observations</span>
          </div>
          <span className="text-xs text-slate-400">
            {recent_sightings.length} observations
          </span>
        </div>

        <div className="overflow-x-auto min-w-0">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 text-slate-500 text-[11px] bg-slate-50/50">
                <th className="py-2.5 px-4 font-medium">Time</th>
                <th className="py-2.5 px-4 font-medium">Indicator Fingerprint</th>
                <th className="py-2.5 px-4 font-medium">Feed</th>
                <th className="py-2.5 px-4 font-medium">Associated Threat</th>
                <th className="py-2.5 px-4 font-medium text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {recent_sightings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400 font-sans text-xs">
                    No threat observations in current window.
                  </td>
                </tr>
              ) : (
                recent_sightings.slice(0, 10).map((s, idx) => (
                  <tr key={s.sighting_id || idx} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-2.5 px-4 text-slate-500 font-sans text-xs">
                      {s.observed_at ? new Date(s.observed_at).toLocaleTimeString() : 'Recent'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-800 font-medium truncate max-w-xs text-xs">
                      {s.ioc_fingerprint}
                    </td>
                    <td className="py-2.5 px-4 font-sans text-xs">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[11px]">
                        {s.source}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-700 text-xs">
                      {s.associated_cve && (
                        <span className="text-orange-600 font-medium mr-2">{s.associated_cve}</span>
                      )}
                      {s.associated_malware && (
                        <span className="text-purple-600 font-medium">{s.associated_malware}</span>
                      )}
                      {!s.associated_cve && !s.associated_malware && <span className="text-slate-400">—</span>}
                    </td>
                    <td className="py-2.5 px-4 text-right font-sans text-xs">
                      <span className="text-emerald-600 font-medium">
                        {s.feed_confidence || 85}%
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
