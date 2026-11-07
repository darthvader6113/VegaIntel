import React, { useState, useEffect } from 'react';
import { Tabs } from '@ark-ui/react';
import {
  Search,
  Database,
  X,
  Clock,
  Plus,
  SlidersHorizontal,
  Calendar
} from 'lucide-react';
import { IOC } from '../../types';
import { api } from '../../services/api';

interface IocRepositoryModuleProps {
  onRequestIocOpen?: () => void;
}

export const IocRepositoryModule: React.FC<IocRepositoryModuleProps> = ({ onRequestIocOpen }) => {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedSource, setSelectedSource] = useState('');
  const [timeRange, setTimeRange] = useState('all');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [selectedDetail, setSelectedDetail] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchIocs = async () => {
    try {
      setLoading(true);
      const res = await api.getIOCs({
        q: searchTerm || undefined,
        ioc_type: selectedType || undefined,
        source: selectedSource || undefined,
        time_range: timeRange !== 'all' ? timeRange : undefined,
        min_confidence: minConfidence > 0 ? minConfidence : undefined,
      });
      setIocs(res.items);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, [searchTerm, selectedType, selectedSource, timeRange, minConfidence]);

  const openDetail = async (fingerprint: string) => {
    try {
      const data = await api.getIOCDetail(fingerprint);
      setSelectedDetail(data);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Ark UI Time Range Quick Filter Tabs ("From the day get new ioc") */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <Tabs.Root
          value={timeRange}
          onValueChange={(details) => setTimeRange(details.value)}
          className="flex items-center"
        >
          <Tabs.List className="flex items-center gap-1.5 p-1 rounded-xl bg-white border border-slate-200 shadow-sm font-mono text-xs">
            <Calendar className="w-4 h-4 text-orange-600 ml-2 mr-1" />
            <Tabs.Trigger
              value="all"
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
                timeRange === 'all'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All Historical IOCs
            </Tabs.Trigger>
            <Tabs.Trigger
              value="today"
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold flex items-center gap-1.5 ${
                timeRange === 'today'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Today&apos;s New IOCs
            </Tabs.Trigger>
            <Tabs.Trigger
              value="24h"
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
                timeRange === '24h'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Last 24 Hours
            </Tabs.Trigger>
            <Tabs.Trigger
              value="7d"
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
                timeRange === '7d'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Last 7 Days
            </Tabs.Trigger>
          </Tabs.List>
        </Tabs.Root>

        {onRequestIocOpen && (
          <button
            onClick={onRequestIocOpen}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-bold font-mono text-xs shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Request / Submit IOC</span>
          </button>
        )}
      </div>

      {/* Advanced Search and Filter Bar */}
      <div className="cyber-card p-4 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search canonical IOC value, tag, or C2 domain..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* IOC Type filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
          >
            <option value="">All Types (IP/Domain/URL/Hash)</option>
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="url">URL</option>
            <option value="sha256">SHA-256</option>
            <option value="md5">MD5</option>
          </select>

          {/* Source Feed filter */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
          >
            <option value="">All Threat Feeds</option>
            <option value="Feodo Tracker">Feodo Tracker</option>
            <option value="OpenPhish">OpenPhish</option>
            <option value="Emerging Threats">Emerging Threats</option>
            <option value="AlienVault OTX">AlienVault OTX</option>
            <option value="ThreatFox">ThreatFox</option>
            <option value="URLhaus">URLhaus</option>
            <option value="Analyst Submission">Analyst Submission</option>
          </select>

          {/* Confidence Slider */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px]">
            <SlidersHorizontal className="w-3.5 h-3.5 text-orange-600" />
            <span className="text-slate-600 font-medium">Min Conf:</span>
            <input
              type="range"
              min="0"
              max="95"
              step="5"
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-16 accent-orange-500"
            />
            <span className="text-emerald-700 font-bold">{minConfidence}%</span>
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="cyber-card rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-orange-600" />
            <h3 className="text-sm font-semibold text-slate-900">
              Deduplicated Intelligence Repository
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-500">
            {iocs.length} Canonical Records
          </span>
        </div>

        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-slate-400">Loading indicators...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50">
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Canonical Value</th>
                  <th className="py-3 px-4 text-center">Sightings</th>
                  <th className="py-3 px-4">Reporting Sources</th>
                  <th className="py-3 px-4">Tags</th>
                  <th className="py-3 px-4 text-right">Confidence</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {iocs.map((ioc) => (
                  <tr
                    key={ioc.fingerprint}
                    className="hover:bg-slate-50 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-bold text-[10px] uppercase border border-slate-200">
                        {ioc.ioc_type}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-semibold text-slate-900 max-w-xs truncate" title={ioc.ioc_value}>
                      {ioc.ioc_value}
                    </td>

                    <td className="py-3 px-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        ioc.sighting_count > 1
                          ? 'bg-orange-100 text-orange-800 border border-orange-200'
                          : 'bg-slate-100 text-slate-600'
                      }`}>
                        {ioc.sighting_count}x
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {ioc.sources.map((src) => (
                          <span
                            key={src}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-700 border border-slate-200"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {ioc.tags.slice(0, 3).map((tag) => (
                          <span
                            key={tag}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-600 border border-slate-200"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <span className="font-bold text-emerald-600">
                        {ioc.overall_confidence}%
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => openDetail(ioc.fingerprint)}
                        className="px-2.5 py-1 rounded bg-slate-100 hover:bg-orange-500 hover:text-white text-slate-700 transition-colors font-semibold text-[11px] border border-slate-200 shadow-sm"
                      >
                        Sightings
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Sighting History and Deduplication Modal */}
      {selectedDetail && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl max-h-[85vh] rounded-2xl border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl">
            {/* Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50">
              <div>
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded bg-orange-100 text-orange-800 font-mono text-xs uppercase font-bold border border-orange-200">
                    {selectedDetail.canonical_ioc.ioc_type}
                  </span>
                  <h3 className="text-lg font-bold font-mono text-slate-900 break-all">
                    {selectedDetail.canonical_ioc.ioc_value}
                  </h3>
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1 flex items-center gap-3">
                  <span>Fingerprint: <strong className="text-slate-800">{selectedDetail.canonical_ioc.fingerprint}</strong></span>
                  <span>Confidence: <strong className="text-emerald-700">{selectedDetail.canonical_ioc.overall_confidence}%</strong></span>
                </div>
              </div>
              <button
                onClick={() => setSelectedDetail(null)}
                className="p-1 rounded-lg bg-slate-200 text-slate-600 hover:text-slate-900 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Deduplication Statistics Box */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs font-mono">
              <div className="p-4 rounded-xl bg-orange-50 border border-orange-200 flex items-center justify-between">
                <div>
                  <span className="text-orange-800 font-bold block mb-1">Deduplication Summary</span>
                  <span className="text-slate-700">
                    Observed <strong className="text-slate-900">{selectedDetail.deduplication_summary.total_sightings} times</strong> across{' '}
                    <strong className="text-slate-900">{selectedDetail.canonical_ioc.sources.length} OSINT feeds</strong>.
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-emerald-700 font-extrabold text-base block">
                    {selectedDetail.deduplication_summary.duplicate_sightings_merged} duplicates saved
                  </span>
                  <span className="text-[10px] text-slate-500">Zero duplicated storage</span>
                </div>
              </div>

              {/* Sighting Observation Log */}
              <div>
                <h4 className="font-semibold text-slate-800 uppercase tracking-wider text-[11px] mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-orange-600" />
                  Independent Sightings &amp; Raw Evidence ({selectedDetail.sightings.length})
                </h4>
                <div className="space-y-3">
                  {selectedDetail.sightings.map((sighting: any, idx: number) => (
                    <div
                      key={sighting.sighting_id || idx}
                      className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-900 text-[12px]">{sighting.source}</span>
                          <span className="text-slate-500 text-[10px]">
                            {new Date(sighting.observed_at).toLocaleString()}
                          </span>
                        </div>
                        <span className="text-emerald-700 font-bold text-[11px]">
                          Feed Confidence: {sighting.feed_confidence}%
                        </span>
                      </div>

                      {sighting.evidence_notes && (
                        <p className="text-slate-700 text-[11px]">
                          {sighting.evidence_notes}
                        </p>
                      )}

                      <details className="mt-2 text-[10px]">
                        <summary className="text-orange-600 hover:text-orange-700 cursor-pointer font-semibold">
                          View Raw Feed Payload
                        </summary>
                        <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-100 overflow-x-auto">
                          {JSON.stringify(sighting.raw_payload, null, 2)}
                        </pre>
                      </details>
                    </div>
                  ))}
                </div>
              </div>

              {/* Correlated Threat Context */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="font-semibold text-slate-800 text-[11px] block mb-2">
                    Correlated Vulnerabilities
                  </span>
                  {selectedDetail.associated_cves.length === 0 ? (
                    <span className="text-slate-400 text-[11px]">No mapped CVEs</span>
                  ) : (
                    selectedDetail.associated_cves.map((c: any) => (
                      <div key={c.cve_id} className="text-orange-600 font-bold text-xs">
                        {c.cve_id} <span className="text-slate-500 text-[10px]">({c.severity} {c.cvss_score})</span>
                      </div>
                    ))
                  )}
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="font-semibold text-slate-800 text-[11px] block mb-2">
                    Correlated Malware Families
                  </span>
                  {selectedDetail.associated_malware.length === 0 ? (
                    <span className="text-slate-400 text-[11px]">No mapped malware</span>
                  ) : (
                    selectedDetail.associated_malware.map((m: any) => (
                      <div key={m.malware_id} className="text-amber-700 font-bold text-xs">
                        {m.name} <span className="text-slate-500 text-[10px]">({m.malware_type})</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
