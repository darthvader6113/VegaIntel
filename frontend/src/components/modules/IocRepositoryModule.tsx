import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Portal } from '../common/Portal';
import {
  Search,
  Database,
  X,
  Clock,
  Plus,
  SlidersHorizontal,
  Calendar,
  Copy,
  Check,
  Shield,
  Layers,
  ArrowUpRight
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
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
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

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ip':
      case 'ipv4':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'domain':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      case 'url':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'sha256':
      case 'md5':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Time Range Quick Filter Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        {/* Native Pure-React Time Range Quick Filter Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-white border border-slate-200 shadow-xs font-mono text-xs">
          <Calendar className="w-4 h-4 text-orange-600 ml-2 mr-1" />
          <button
            type="button"
            onClick={() => setTimeRange('all')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
              timeRange === 'all'
                ? 'bg-orange-500 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All Canonical IOCs
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('today')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold flex items-center gap-1.5 ${
              timeRange === 'today'
                ? 'bg-orange-500 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Today&apos;s New IOCs
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('24h')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
              timeRange === '24h'
                ? 'bg-orange-500 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Last 24 Hours
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('7d')}
            className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${
              timeRange === '7d'
                ? 'bg-orange-500 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Last 7 Days
          </button>
        </div>

        {onRequestIocOpen && (
          <button
            type="button"
            onClick={onRequestIocOpen}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-orange-500 hover:bg-orange-600 text-white font-semibold font-mono text-xs shadow-xs transition-all active:scale-95"
          >
            <Plus className="w-4 h-4" />
            <span>Fetch IOCs by CVE</span>
          </button>
        )}
      </div>

      {/* Advanced Search and Filter Bar */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search indicator by value, C2 host, IP, or hash..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* IOC Type filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 shadow-xs"
          >
            <option value="">All Types (IP / Domain / URL / Hash)</option>
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="url">URL</option>
            <option value="sha256">SHA-256 Hash</option>
            <option value="md5">MD5 Hash</option>
          </select>

          {/* Source Feed filter */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 shadow-xs"
          >
            <option value="">All Threat Feeds</option>
            <option value="Abuse.ch URLhaus">Abuse.ch URLhaus</option>
            <option value="ThreatFox">ThreatFox IOCs</option>
            <option value="AlienVault OTX">AlienVault OTX</option>
            <option value="OpenPhish">OpenPhish Feed</option>
            <option value="CISA KEV">CISA KEV Indicators</option>
          </select>

          {/* Min Confidence filter */}
          <div className="flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg">
            <SlidersHorizontal className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500 text-[11px]">Min Conf:</span>
            <input
              type="range"
              min="0"
              max="90"
              step="10"
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-16 h-1 bg-slate-300 rounded-lg appearance-none cursor-pointer accent-orange-500"
            />
            <span className="font-bold text-slate-800 w-7 text-right">{minConfidence}%</span>
          </div>

          <span className="text-xs text-slate-400 pl-2 border-l border-slate-200">
            {iocs.length} Indicators
          </span>
        </div>
      </div>

      {/* Main Canonical Table / Cards Container */}
      <div className="rounded-xl border border-slate-200/90 bg-white shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-700">
            <Database className="w-4 h-4 text-orange-600" />
            <span>Canonical Intelligence Indicator Database</span>
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Cross-feed automated deduplication enabled
          </div>
        </div>

        {loading ? (
          <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
            <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
            <span>Loading deduplicated indicators...</span>
          </div>
        ) : iocs.length === 0 ? (
          <div className="p-16 text-center text-xs font-mono text-slate-400">
            No indicators match the specified filters.
          </div>
        ) : (
          <div className="overflow-x-auto min-w-0">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50/80">
                  <th className="py-3 px-4 font-semibold">Type</th>
                  <th className="py-3 px-4 font-semibold">Canonical Value</th>
                  <th className="py-3 px-4 font-semibold text-center">Sightings</th>
                  <th className="py-3 px-4 font-semibold">Origin Feeds</th>
                  <th className="py-3 px-4 font-semibold text-right">Confidence</th>
                  <th className="py-3 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {iocs.map((ioc) => (
                  <tr
                    key={ioc.fingerprint}
                    className="hover:bg-slate-50/80 transition-colors group"
                  >
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] uppercase border ${getTypeColor(ioc.ioc_type)}`}>
                        {ioc.ioc_type}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2 max-w-lg min-w-0">
                        <span className="font-semibold text-slate-900 truncate select-all" title={ioc.ioc_value}>
                          {ioc.ioc_value}
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(ioc.ioc_value, ioc.fingerprint)}
                          title="Copy indicator value"
                          className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-slate-800 transition-opacity shrink-0"
                        >
                          {copiedKey === ioc.fingerprint ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-center">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${
                        ioc.sighting_count > 1
                          ? 'bg-orange-50 text-orange-700 border-orange-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {ioc.sighting_count}x
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {ioc.sources.map((src) => (
                          <span
                            key={src}
                            className="px-2 py-0.5 rounded text-[10px] bg-slate-100 text-slate-700 border border-slate-200 font-medium"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <div className="w-12 bg-slate-200 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="bg-emerald-500 h-full rounded-full"
                            style={{ width: `${ioc.overall_confidence}%` }}
                          />
                        </div>
                        <span className="font-bold text-slate-800 w-8">
                          {ioc.overall_confidence}%
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => openDetail(ioc.fingerprint)}
                        className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-orange-500 hover:text-white text-slate-700 transition-colors font-semibold text-[11px] border border-slate-200 shadow-2xs"
                      >
                        Inspect
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
      <Portal>
        <AnimatePresence>
          {selectedDetail && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
            >
              <motion.div
                initial={{ opacity: 0, scale: 0.96, y: 8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: 8 }}
                transition={{ duration: 0.18, ease: 'easeOut' }}
                className="w-full max-w-3xl max-h-[85vh] rounded-2xl border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl"
              >
            {/* Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50/80 shrink-0">
              <div className="min-w-0 pr-4">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className={`px-2 py-0.5 rounded font-mono text-xs uppercase font-bold border ${getTypeColor(selectedDetail.canonical_ioc.ioc_type)}`}>
                    {selectedDetail.canonical_ioc.ioc_type}
                  </span>
                  <h3 className="text-lg font-bold font-mono text-slate-900 break-all select-all">
                    {selectedDetail.canonical_ioc.ioc_value}
                  </h3>
                </div>
                <div className="text-[11px] font-mono text-slate-500 mt-1 flex items-center gap-3">
                  <span>Fingerprint: <strong className="text-slate-800 font-normal">{selectedDetail.canonical_ioc.fingerprint}</strong></span>
                  <span>Confidence: <strong className="text-emerald-700">{selectedDetail.canonical_ioc.overall_confidence}%</strong></span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedDetail(null)}
                className="p-1.5 rounded-lg bg-slate-200/80 text-slate-600 hover:text-slate-900 transition-colors shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Deduplication Statistics Banner */}
            <div className="p-4 bg-orange-50/60 border-b border-orange-100 flex items-center justify-between text-xs font-mono text-orange-950 shrink-0">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-orange-600" />
                <span>
                  <strong>{selectedDetail.sightings.length} Raw Telemetry Sightings</strong> consolidated into this single record
                </span>
              </div>
              <span className="font-bold text-orange-700 bg-orange-100 px-2 py-0.5 rounded border border-orange-200">
                {selectedDetail.sightings.length > 1 ? `${selectedDetail.sightings.length - 1} Duplicates Prevented` : 'Single Feed Sight'}
              </span>
            </div>

            {/* Sighting Timeline */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs font-mono flex-1">
              <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Telemetry Sightings Timeline ({selectedDetail.sightings.length})
              </h4>
              <div className="space-y-3">
                {selectedDetail.sightings.map((s: any, idx: number) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-bold text-slate-900">{s.source}</span>
                      <span className="text-slate-400">{s.observed_at ? new Date(s.observed_at).toLocaleString() : 'Recent'}</span>
                    </div>
                    {s.evidence_notes && (
                      <div className="text-slate-600 text-[11px] leading-relaxed">
                        {s.evidence_notes}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  </Portal>
</div>
);
};
