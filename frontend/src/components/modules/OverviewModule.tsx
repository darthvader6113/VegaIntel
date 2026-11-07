import React from 'react';
import {
  ShieldAlert,
  Database,
  Layers,
  Sparkles,
  Server,
  Activity,
  ArrowUpRight,
  Clock,
  Radio,
  CheckCircle2,
  Users,
  Binary
} from 'lucide-react';
import { OverviewStats } from '../../types';

interface OverviewModuleProps {
  stats: OverviewStats | null;
  onNavigate: (tab: any) => void;
}

export const OverviewModule: React.FC<OverviewModuleProps> = ({ stats, onNavigate }) => {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-xs gap-2">
        <Activity className="w-5 h-5 animate-spin text-orange-600" />
        <span>Loading enterprise intelligence metrics...</span>
      </div>
    );
  }

  const { metrics, feed_statuses, recent_sightings, ioc_type_distribution } = stats;

  return (
    <div className="w-full space-y-6">
      {/* Top Enterprise KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Canonical IOCs */}
        <div className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs relative overflow-hidden flex flex-col justify-between group hover:border-orange-300 transition-all">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-2">
              <span className="text-[11px] uppercase font-mono tracking-wider font-bold">Canonical IOCs</span>
              <Database className="w-4 h-4 text-orange-600" />
            </div>
            <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
              {metrics.total_canonical_iocs.toLocaleString()}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between font-mono">
            <span>Collision-Free Records</span>
            <button 
              type="button"
              onClick={() => onNavigate('iocs')}
              className="text-orange-600 hover:text-orange-700 font-semibold flex items-center gap-1 transition-colors"
            >
              Explore <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Monitored CVEs */}
        <div className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-col justify-between group hover:border-red-300 transition-all">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-2">
              <span className="text-[11px] uppercase font-mono tracking-wider font-bold">Monitored CVEs</span>
              <ShieldAlert className="w-4 h-4 text-rose-600" />
            </div>
            <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
              {metrics.monitored_cves.toLocaleString()}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between font-mono">
            <span className="text-rose-600 font-semibold">{metrics.critical_cves} Critical (KEV)</span>
            <button 
              type="button"
              onClick={() => onNavigate('cves')}
              className="text-orange-600 hover:text-orange-700 font-semibold flex items-center gap-1 transition-colors"
            >
              Inspect <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Threat Actors & Campaigns */}
        <div className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-col justify-between group hover:border-purple-300 transition-all">
          <div>
            <div className="flex items-center justify-between text-slate-500 mb-2">
              <span className="text-[11px] uppercase font-mono tracking-wider font-bold">Attributed APTs</span>
              <Users className="w-4 h-4 text-purple-600" />
            </div>
            <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
              {metrics.active_threat_actors}
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between font-mono">
            <span>{metrics.malware_families} Malware Tools</span>
            <button 
              type="button"
              onClick={() => onNavigate('apt')}
              className="text-purple-600 hover:text-purple-700 font-semibold flex items-center gap-1 transition-colors"
            >
              Actors <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Deduplication Savings Ratio */}
        <div className="p-5 rounded-xl border border-orange-200/90 bg-gradient-to-br from-orange-50/60 to-white shadow-xs flex flex-col justify-between group hover:border-orange-300 transition-all">
          <div>
            <div className="flex items-center justify-between text-orange-700 mb-2">
              <span className="text-[11px] uppercase font-mono tracking-wider font-bold">Deduplication Savings</span>
              <Sparkles className="w-4 h-4 text-orange-600" />
            </div>
            <div className="text-3xl font-extrabold text-orange-600 font-mono tracking-tight">
              {metrics.deduplication_ratio_pct}%
            </div>
          </div>
          <div className="mt-3 pt-2 border-t border-orange-100 text-xs text-slate-600 flex items-center justify-between font-mono">
            <span><strong>{metrics.duplicates_prevented.toLocaleString()}</strong> duplicate alerts filtered</span>
          </div>
        </div>
      </div>

      {/* OSINT Feeds Status & Indicator Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active OSINT Feeds Matrix */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h3 className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-orange-600" />
              OSINT Threat Feeds &amp; Ingestion Pipeline
            </h3>
            <span className="text-[11px] font-mono text-emerald-700 font-bold px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              {feed_statuses.length} ACTIVE FEEDS
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {feed_statuses.map((feed) => (
              <div 
                key={feed.feed_name}
                className="p-3.5 rounded-xl bg-slate-50/70 border border-slate-200/80 hover:bg-white hover:border-slate-300 transition-all flex items-start justify-between"
              >
                <div className="space-y-1 min-w-0">
                  <div className="font-bold text-xs font-mono text-slate-900 truncate">{feed.feed_name}</div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    {feed.total_records_ingested.toLocaleString()} records ingested · {feed.unique_iocs_contributed} canonical
                  </div>
                  {feed.last_successful_sync && (
                    <div className="text-[10px] text-slate-400 font-mono flex items-center gap-1 pt-0.5">
                      <Clock className="w-3 h-3 text-slate-400" />
                      Last synced: {new Date(feed.last_successful_sync).toLocaleTimeString()}
                    </div>
                  )}
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${
                  feed.status === 'HEALTHY' 
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : feed.status === 'SYNCING'
                    ? 'bg-amber-50 text-amber-800 border-amber-200 animate-pulse'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  {feed.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* IOC Indicator Distribution */}
        <div className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-col justify-between space-y-4">
          <div className="space-y-4">
            <div className="border-b border-slate-100 pb-3 flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Database className="w-4 h-4 text-orange-600" />
                Indicator Breakdown
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                {metrics.total_canonical_iocs} Total
              </span>
            </div>

            <div className="space-y-3 font-mono">
              {ioc_type_distribution.map((item) => {
                const total = metrics.total_canonical_iocs || 1;
                const pct = Math.round((item.count / total) * 100);
                return (
                  <div key={item.type} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="uppercase text-slate-700 font-bold">{item.type}</span>
                      <span className="text-slate-500 font-medium">{item.count.toLocaleString()} ({pct}%)</span>
                    </div>
                    <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                      <div 
                        className="bg-orange-500 h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-mono text-slate-500">
            <span>Threat Actors: <strong className="text-slate-900">{metrics.active_threat_actors}</strong></span>
            <span>Malware: <strong className="text-slate-900">{metrics.malware_families}</strong></span>
            <span>PoCs: <strong className="text-slate-900">{metrics.poc_references}</strong></span>
          </div>
        </div>
      </div>

      {/* Live Threat Sightings Stream */}
      <div className="rounded-xl border border-slate-200/90 bg-white shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-900 uppercase tracking-wider">
            <Activity className="w-4 h-4 text-orange-600" />
            <span>Real-Time Incoming Sightings Stream</span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Immutable observation log across feeds
          </span>
        </div>

        <div className="overflow-x-auto min-w-0">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50/80">
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Canonical Fingerprint</th>
                <th className="py-3 px-4 font-semibold">Source Feed</th>
                <th className="py-3 px-4 font-semibold">Correlated Threat Entity</th>
                <th className="py-3 px-4 font-semibold text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recent_sightings.map((s, idx) => (
                <tr key={s.sighting_id || idx} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-2.5 px-4 text-slate-500">
                    {new Date(s.observed_at).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-4 text-slate-900 font-bold truncate max-w-xs">
                    {s.ioc_fingerprint}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-medium">
                      {s.source}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-600">
                    {s.associated_cve && (
                      <span className="text-orange-600 font-bold mr-2">{s.associated_cve}</span>
                    )}
                    {s.associated_malware && (
                      <span className="text-purple-700 font-semibold">{s.associated_malware}</span>
                    )}
                    {!s.associated_cve && !s.associated_malware && <span className="text-slate-400">—</span>}
                  </td>
                  <td className="py-2.5 px-4 text-right font-bold text-emerald-600">
                    {s.feed_confidence}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
