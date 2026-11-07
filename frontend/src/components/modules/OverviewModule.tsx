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
} from 'lucide-react';
import { OverviewStats } from '../../types';

interface OverviewModuleProps {
  stats: OverviewStats | null;
  onNavigate: (tab: any) => void;
}

export const OverviewModule: React.FC<OverviewModuleProps> = ({ stats, onNavigate }) => {
  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 font-mono text-sm">
        <Activity className="w-5 h-5 animate-spin mr-2 text-orange-600" />
        Loading threat intelligence metrics...
      </div>
    );
  }

  const { metrics, feed_statuses, recent_sightings, ioc_type_distribution } = stats;

  return (
    <div className="space-y-6">
      {/* Top Telemetry Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Canonical IOCs */}
        <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs uppercase font-mono tracking-wider font-semibold">Canonical IOCs</span>
            <Database className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
            {metrics.total_canonical_iocs}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between font-mono">
            <span>Deduplicated Records</span>
            <button 
              onClick={() => onNavigate('iocs')}
              className="text-orange-600 hover:text-orange-700 font-semibold flex items-center gap-0.5"
            >
              Explore <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Total Sightings */}
        <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs uppercase font-mono tracking-wider font-semibold">Total Sightings</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
            {metrics.total_sightings}
          </div>
          <div className="mt-2 text-xs text-slate-500 font-mono">
            Across 5 OSINT Feeds
          </div>
        </div>

        {/* Deduplication Efficiency */}
        <div className="cyber-card p-5 rounded-xl border border-orange-200 bg-gradient-to-br from-orange-50 to-white shadow-sm">
          <div className="flex items-center justify-between text-orange-700 mb-2">
            <span className="text-xs uppercase font-mono tracking-wider font-semibold">Deduplication Savings</span>
            <Sparkles className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-3xl font-extrabold text-orange-600 font-mono tracking-tight">
            {metrics.deduplication_ratio_pct}%
          </div>
          <div className="mt-2 text-xs text-slate-600 font-mono">
            <span className="text-slate-900 font-semibold">{metrics.duplicates_prevented}</span> duplicate alerts avoided
          </div>
        </div>

        {/* Monitored CVEs */}
        <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs uppercase font-mono tracking-wider font-semibold">Monitored CVEs</span>
            <ShieldAlert className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-3xl font-extrabold text-slate-900 font-mono tracking-tight">
            {metrics.monitored_cves}
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between font-mono">
            <span className="text-red-600 font-semibold">{metrics.critical_cves} Critical Severity</span>
            <button 
              onClick={() => onNavigate('cves')}
              className="text-orange-600 hover:text-orange-700 font-semibold flex items-center gap-0.5"
            >
              View <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Section 3 Deduplication Architecture Feature Box */}
      <div className="cyber-card p-6 rounded-xl border border-orange-200 bg-white shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 gap-2">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-orange-500 shadow-sm" />
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider font-mono">
              Deterministic Deduplication Pipeline (Section 3 Spec)
            </h2>
          </div>
          <span className="text-xs text-orange-700 font-mono bg-orange-50 px-2.5 py-1 rounded border border-orange-200 font-medium">
            fingerprint = normalized_ioc_type + &quot;:&quot; + normalized_ioc_value
          </span>
        </div>
        
        <p className="text-xs text-slate-600 leading-relaxed mb-4">
          When multiple OSINT feeds report identical indicators for vulnerabilities (e.g. AlienVault OTX, ThreatFox, and URLhaus tracking <code className="text-orange-700 bg-orange-50 px-1 py-0.5 rounded border border-orange-200">oast.live</code> or <code className="text-orange-700 bg-orange-50 px-1 py-0.5 rounded border border-orange-200">tempmicrosoft.com</code>), VegaIntel upserts a single canonical record with an atomic counter, while cataloging every observation in an immutable sightings log and maintaining decoupled threat relationships.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 block mb-1">Raw Observations</span>
            <span className="text-lg font-bold text-slate-900">{metrics.total_sightings} Sightings</span>
            <span className="text-[10px] text-slate-500 block mt-1">Multi-source telemetry</span>
          </div>
          <div className="p-3 rounded-lg bg-orange-50 border border-orange-200">
            <span className="text-orange-700 block mb-1 font-semibold">Canonical Database</span>
            <span className="text-lg font-bold text-orange-700">{metrics.total_canonical_iocs} Unique IOCs</span>
            <span className="text-[10px] text-orange-600 block mt-1">100% collision-free</span>
          </div>
          <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200">
            <span className="text-emerald-700 block mb-1 font-semibold">Noise Reduction</span>
            <span className="text-lg font-bold text-emerald-700">{metrics.deduplication_ratio_pct}% Deduplicated</span>
            <span className="text-[10px] text-emerald-600 block mt-1">{metrics.duplicates_prevented} duplicate records prevented</span>
          </div>
        </div>
      </div>

      {/* Grid: Feed Health & IOC Type Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Feed Health Panel */}
        <div className="lg:col-span-2 cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Server className="w-4 h-4 text-orange-600" />
              OSINT Feeds &amp; Enrichment Sources
            </h3>
            <span className="text-xs font-mono text-slate-500">
              {feed_statuses.length} Sources Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {feed_statuses.map((feed) => (
              <div 
                key={feed.feed_name}
                className="p-3 rounded-lg bg-slate-50 border border-slate-200 hover:border-slate-300 transition-all flex items-start justify-between"
              >
                <div>
                  <div className="font-semibold text-xs text-slate-900">{feed.feed_name}</div>
                  <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                    {feed.total_records_ingested} ingested · {feed.unique_iocs_contributed} unique
                  </div>
                  {feed.last_successful_sync && (
                    <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1 mt-1">
                      <Clock className="w-3 h-3" />
                      {new Date(feed.last_successful_sync).toLocaleTimeString()}
                    </div>
                  )}
                </div>
                <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${
                  feed.status === 'HEALTHY' 
                    ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                    : feed.status === 'SYNCING'
                    ? 'bg-amber-100 text-amber-800 border-amber-200 animate-pulse'
                    : 'bg-red-100 text-red-800 border-red-200'
                }`}>
                  {feed.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* IOC Type Breakdown */}
        <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Database className="w-4 h-4 text-orange-600" />
              IOC Type Distribution
            </h3>
            <div className="space-y-3">
              {ioc_type_distribution.map((item) => {
                const total = metrics.total_canonical_iocs || 1;
                const pct = Math.round((item.count / total) * 100);
                return (
                  <div key={item.type}>
                    <div className="flex justify-between text-xs mb-1 font-mono">
                      <span className="uppercase text-slate-700 font-semibold">{item.type}</span>
                      <span className="text-slate-500">{item.count} ({pct}%)</span>
                    </div>
                    <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
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

          <div className="mt-4 pt-4 border-t border-slate-200 flex items-center justify-between text-xs font-mono text-slate-500">
            <span>Threat Actors: <strong className="text-slate-900">{metrics.active_threat_actors}</strong></span>
            <span>Malware: <strong className="text-slate-900">{metrics.malware_families}</strong></span>
            <span>PoCs: <strong className="text-slate-900">{metrics.poc_references}</strong></span>
          </div>
        </div>
      </div>

      {/* Recent Feed Sightings Stream */}
      <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-600" />
            Live Ingestion Sightings Stream
          </h3>
          <span className="text-xs text-slate-500 font-mono">Real-time incoming telemetry</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Canonical Fingerprint</th>
                <th className="py-2.5 px-3">Source Feed</th>
                <th className="py-2.5 px-3">Associated Context</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {recent_sightings.map((s, idx) => (
                <tr key={s.sighting_id || idx} className="hover:bg-slate-50 transition-colors">
                  <td className="py-2.5 px-3 text-slate-500">
                    {new Date(s.observed_at).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 text-slate-900 font-semibold">
                    {s.ioc_fingerprint}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                      {s.source}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-600">
                    {s.associated_cve && (
                      <span className="text-orange-600 font-semibold mr-2">{s.associated_cve}</span>
                    )}
                    {s.associated_malware && (
                      <span className="text-amber-700 font-medium">{s.associated_malware}</span>
                    )}
                    {!s.associated_cve && !s.associated_malware && <span className="text-slate-400">—</span>}
                  </td>
                  <td className="py-2.5 px-3 text-right font-bold text-emerald-600">
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
