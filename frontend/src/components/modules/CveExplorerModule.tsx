import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Portal } from '../common/Portal';
import {
  Search,
  ExternalLink,
  Code2,
  Database,
  Users,
  X,
  Copy,
  Check,
  ShieldAlert,
  Flame,
  FileJson,
  Layers,
  ArrowRight
} from 'lucide-react';
import { CVE } from '../../types';
import { api } from '../../services/api';
import { copyToClipboard } from '../../utils/clipboard';

export const CveExplorerModule: React.FC = () => {
  const [cves, setCves] = useState<CVE[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [onlyPoc, setOnlyPoc] = useState<boolean>(false);
  const [selectedCveDetail, setSelectedCveDetail] = useState<any | null>(null);
  const [activeModalTab, setActiveModalTab] = useState<'dossier' | 'iocs' | 'pocs' | 'stix'>('dossier');
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchCves = async () => {
    try {
      setLoading(true);
      const res = await api.getCVEs({
        q: searchTerm || undefined,
        severity: selectedSeverity || undefined,
        has_poc: onlyPoc ? true : undefined,
      });
      setCves(res.items);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCves();
  }, [searchTerm, selectedSeverity, onlyPoc]);

  const openDetail = async (cveId: string) => {
    try {
      setActiveModalTab('dossier');
      const detail = await api.getCVEDetail(cveId);
      setSelectedCveDetail(detail);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCopy = async (text: string, label: string) => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedText(label);
      setTimeout(() => setCopiedText(null), 2000);
    }
  };

  const getSeverityBadge = (severity: string, score: number) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-50 text-rose-700 border-rose-200',
          dot: 'bg-rose-500',
          borderAccent: 'border-l-rose-500'
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-50 text-orange-700 border-orange-200',
          dot: 'bg-orange-500',
          borderAccent: 'border-l-orange-500'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-50 text-amber-700 border-amber-200',
          dot: 'bg-amber-500',
          borderAccent: 'border-l-amber-500'
        };
      default:
        return {
          bg: 'bg-sky-50 text-sky-700 border-sky-200',
          dot: 'bg-sky-500',
          borderAccent: 'border-l-sky-500'
        };
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Enterprise Filter & Search Toolbar */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[300px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search vulnerabilities by CVE ID (e.g. CVE-2024-3400) or software (e.g. VMware, PAN-OS, Log4j)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>

        <div className="flex items-center gap-3">
          {/* Severity selector */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 shadow-xs"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical Severity (9.0+)</option>
            <option value="HIGH">High Severity (7.0 - 8.9)</option>
            <option value="MEDIUM">Medium Severity (4.0 - 6.9)</option>
          </select>

          {/* Weaponized PoC toggle button */}
          <button
            type="button"
            onClick={() => setOnlyPoc(!onlyPoc)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border shadow-xs ${
              onlyPoc
                ? 'bg-orange-50 text-orange-700 border-orange-300 font-semibold'
                : 'bg-white text-slate-600 border-slate-200 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Code2 className="w-3.5 h-3.5 text-orange-600" />
            <span>Weaponized PoC</span>
          </button>

          <span className="text-xs font-mono text-slate-400 pl-1 border-l border-slate-200">
            {cves.length} CVEs
          </span>
        </div>
      </div>

      {/* CVE Full Width Card Grid */}
      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <span>Ingesting &amp; correlating vulnerabilities...</span>
        </div>
      ) : cves.length === 0 ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 bg-white rounded-xl border border-slate-200">
          No vulnerabilities match the current filter criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {cves.map((cve) => {
            const badge = getSeverityBadge(cve.severity, cve.cvss_score);
            return (
              <div
                key={cve.cve_id}
                onClick={() => openDetail(cve.cve_id)}
                className={`p-4 rounded-lg border border-slate-200/90 bg-white hover:border-orange-300/80 hover:shadow-sm cursor-pointer transition-all border-l-4 ${badge.borderAccent} flex flex-col justify-between gap-3 group`}
              >
                {/* Header row: ID, Badges, Dates */}
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-sm font-bold text-slate-900 group-hover:text-orange-600 transition-colors">
                      {cve.cve_id}
                    </span>

                    {/* Severity Pill */}
                    <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border flex items-center gap-1.5 ${badge.bg}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                      {cve.severity} {(cve.cvss_score ?? 0).toFixed(1)}
                    </span>

                    {/* Active In The Wild Badge */}
                    {cve.severity === 'CRITICAL' && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1 font-semibold">
                        <Flame className="w-3 h-3 text-rose-600" />
                        ACTIVELY EXPLOITED
                      </span>
                    )}

                    {/* PoC Badge */}
                    {cve.has_poc && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 flex items-center gap-1 font-semibold">
                        <Code2 className="w-3 h-3 text-amber-600" />
                        Weaponized PoC
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopy(cve.cve_id, cve.cve_id);
                      }}
                      title="Copy CVE ID"
                      className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                    >
                      {copiedText === cve.cve_id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                    <span className="text-xs font-mono text-slate-500 group-hover:text-orange-600 font-semibold flex items-center gap-1 transition-colors">
                      Dossier <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </span>
                  </div>
                </div>

                {/* Vulnerability Description (2-line clamp) */}
                <p className="text-xs text-slate-600 leading-relaxed line-clamp-2">
                  {cve.description}
                </p>

                {/* Bottom Metadata Badges */}
                <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-100 gap-2">
                  <div className="flex items-center gap-4 flex-wrap">
                    {cve.associated_ioc_count > 0 && (
                      <span className="flex items-center gap-1 text-slate-700 font-medium">
                        <Database className="w-3.5 h-3.5 text-orange-600" />
                        {cve.associated_ioc_count} Correlated Canonical IOCs
                      </span>
                    )}
                    {cve.cwe_ids && cve.cwe_ids.length > 0 && (
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px]">
                        {cve.cwe_ids.join(', ')}
                      </span>
                    )}
                  </div>

                  {cve.published_date && (
                    <span className="text-[10px] text-slate-400">
                      Disclosed: {new Date(cve.published_date).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Enterprise CVE Detailed Dossier Modal */}
      <Portal>
        <AnimatePresence>
          {selectedCveDetail && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[9999] bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto w-screen h-screen"
            >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: 8 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
              className="w-full max-w-4xl max-h-[90vh] rounded-lg border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl"
            >
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50/80 shrink-0">
              <div className="space-y-1.5 min-w-0 pr-4">
                <div className="flex items-center gap-3 flex-wrap">
                  <h3 className="text-xl font-bold font-mono text-slate-900 tracking-tight">
                    {selectedCveDetail.cve.cve_id}
                  </h3>
                  <span className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border ${getSeverityBadge(selectedCveDetail.cve?.severity || 'HIGH', selectedCveDetail.cve?.cvss_score ?? 0).bg}`}>
                    CVSS {(selectedCveDetail.cve?.cvss_score ?? 0).toFixed(1)} ({selectedCveDetail.cve?.severity || 'HIGH'})
                  </span>
                  {selectedCveDetail.cve.severity === 'CRITICAL' && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-200 font-bold flex items-center gap-1">
                      <Flame className="w-3 h-3 text-rose-600" />
                      CONFIRMED IN WILD
                    </span>
                  )}
                </div>
                {selectedCveDetail.cve.cvss_vector && (
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    Vector: <span className="text-slate-800 font-semibold">{selectedCveDetail.cve.cvss_vector}</span>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => setSelectedCveDetail(null)}
                className="p-1.5 rounded-lg bg-slate-200/80 text-slate-600 hover:text-slate-900 hover:bg-slate-300 transition-colors shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick KPI Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-slate-200 bg-white p-3 shrink-0 text-center text-xs font-mono divide-x divide-slate-100">
              <div className="p-1.5">
                <div className="text-[10px] text-slate-400 uppercase">CVSS Score</div>
                <div className="text-base font-bold text-slate-900 mt-0.5">
                  {(selectedCveDetail.cve?.cvss_score ?? 0).toFixed(1)} <span className="text-xs text-slate-400 font-normal">/ 10</span>
                </div>
              </div>
              <div className="p-1.5">
                <div className="text-[10px] text-slate-400 uppercase">Exploit PoCs</div>
                <div className="text-base font-bold text-amber-600 mt-0.5">
                  {selectedCveDetail.pocs.length}
                </div>
              </div>
              <div className="p-1.5">
                <div className="text-[10px] text-slate-400 uppercase">Threat Actors</div>
                <div className="text-base font-bold text-purple-600 mt-0.5">
                  {selectedCveDetail.exploiting_actors.length}
                </div>
              </div>
              <div className="p-1.5">
                <div className="text-[10px] text-slate-400 uppercase">Canonical IOCs</div>
                <div className="text-base font-bold text-orange-600 mt-0.5">
                  {selectedCveDetail.associated_iocs.length}
                </div>
              </div>
            </div>

            {/* Navigation Tabs inside modal */}
            <div className="flex border-b border-slate-200 px-6 gap-6 bg-slate-50/50 shrink-0 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveModalTab('dossier')}
                className={`py-3 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeModalTab === 'dossier'
                    ? 'border-orange-500 text-orange-600'
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Vulnerability Dossier</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveModalTab('iocs')}
                className={`py-3 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeModalTab === 'iocs'
                    ? 'border-orange-500 text-orange-600'
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                <span>Correlated IOCs ({selectedCveDetail.associated_iocs.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveModalTab('pocs')}
                className={`py-3 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeModalTab === 'pocs'
                    ? 'border-orange-500 text-orange-600'
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>PoCs &amp; Exploits ({selectedCveDetail.pocs.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveModalTab('stix')}
                className={`py-3 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeModalTab === 'stix'
                    ? 'border-orange-500 text-orange-600'
                    : 'border-transparent text-slate-500 hover:text-slate-900'
                }`}
              >
                <FileJson className="w-3.5 h-3.5" />
                <span>STIX 2.1 JSON</span>
              </button>
            </div>

            {/* Modal Body Content (Scrollable, Zero Overflow) */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs flex-1">
              {activeModalTab === 'dossier' && (
                <div className="space-y-6">
                  {/* Vulnerability Summary */}
                  <div>
                    <h4 className="font-semibold text-slate-900 uppercase tracking-wider font-mono text-[11px] mb-2">
                      Vulnerability Description &amp; Technical Analysis
                    </h4>
                    <p className="text-slate-700 leading-relaxed bg-slate-50 p-4 rounded-xl border border-slate-200 font-sans text-xs">
                      {selectedCveDetail.cve.description}
                    </p>
                  </div>

                  {/* Threat Actors */}
                  {selectedCveDetail.exploiting_actors.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-slate-900 uppercase tracking-wider font-mono text-[11px] mb-2 flex items-center gap-1.5">
                        <Users className="w-3.5 h-3.5 text-purple-600" />
                        Threat Actors Actively Exploiting ({selectedCveDetail.exploiting_actors.length})
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {selectedCveDetail.exploiting_actors.map((actor: string) => (
                          <span key={actor} className="px-3 py-1.5 rounded-lg bg-purple-50 text-purple-800 border border-purple-200 font-mono font-bold flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-purple-600" />
                            {actor}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* References & Advisories */}
                  {selectedCveDetail.cve.references && selectedCveDetail.cve.references.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-slate-900 uppercase tracking-wider font-mono text-[11px] mb-2 flex items-center gap-1.5">
                        <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
                        Official References &amp; Vendor Advisories
                      </h4>
                      <div className="space-y-1.5 font-mono">
                        {selectedCveDetail.cve.references.map((ref: string, idx: number) => (
                          <a
                            key={idx}
                            href={ref}
                            target="_blank"
                            rel="noreferrer"
                            className="p-2.5 rounded-lg bg-slate-50 hover:bg-orange-50 border border-slate-200 hover:border-orange-200 text-slate-700 hover:text-orange-700 flex items-center justify-between text-xs transition-colors"
                          >
                            <span className="truncate mr-4">{ref}</span>
                            <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeModalTab === 'iocs' && (
                <div>
                  {selectedCveDetail.associated_iocs.length === 0 ? (
                    <div className="p-8 rounded-xl bg-slate-50 border border-slate-200 text-center space-y-2">
                      <Database className="w-8 h-8 text-slate-300 mx-auto" />
                      <div className="text-xs font-mono font-semibold text-slate-700">
                        Zero Canonical IOCs In Observed Window
                      </div>
                      <div className="text-[11px] text-slate-500 max-w-md mx-auto">
                        Automated threat telemetry continues syncing from threat intelligence databases to index emerging C2 domains, hashes, and scanning IPs.
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2 font-mono">
                      {selectedCveDetail.associated_iocs.map((ioc: any) => (
                        <div key={ioc.fingerprint} className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-4">
                          <div className="flex items-center gap-3 min-w-0">
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-orange-100 text-orange-800 border border-orange-200 shrink-0">
                              {ioc.ioc_type.toUpperCase()}
                            </span>
                            <span className="text-slate-900 font-semibold truncate select-all">{ioc.ioc_value}</span>
                            <span className="text-slate-400 text-[10px] hidden sm:inline">
                              ({ioc.sources.join(', ')})
                            </span>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 text-[10px]">
                              {ioc.sighting_count} sightings
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopy(ioc.ioc_value, ioc.fingerprint)}
                              className="p-1 text-slate-400 hover:text-slate-800"
                              title="Copy indicator"
                            >
                              {copiedText === ioc.fingerprint ? (
                                <Check className="w-3.5 h-3.5 text-emerald-600" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeModalTab === 'pocs' && (
                <div>
                  {selectedCveDetail.pocs.length === 0 ? (
                    <div className="p-8 rounded-xl bg-slate-50 border border-slate-200 text-center space-y-2">
                      <Code2 className="w-8 h-8 text-slate-300 mx-auto" />
                      <div className="text-xs font-mono font-semibold text-slate-700">
                        No Public Exploit Scripts Cataloged
                      </div>
                      <div className="text-[11px] text-slate-500 max-w-md mx-auto">
                        No weaponized PoC code has been verified on GitHub, Exploit-DB, or PacketStorm for this vulnerability record.
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3 font-mono">
                      {selectedCveDetail.pocs.map((poc: any) => (
                        <div key={poc.poc_id} className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="min-w-0 space-y-1">
                            <div className="font-bold text-slate-900 text-xs truncate">{poc.title}</div>
                            <div className="text-[11px] text-slate-600">{poc.description}</div>
                            <div className="text-[10px] text-slate-400">
                              Source: <span className="text-slate-700 font-semibold">{poc.source}</span> · Author: <span className="text-slate-700 font-semibold">{poc.author}</span>
                            </div>
                          </div>
                          <a
                            href={poc.url}
                            target="_blank"
                            rel="noreferrer"
                            className="px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-bold text-xs flex items-center justify-center gap-1.5 shrink-0 transition-colors shadow-xs"
                          >
                            <span>Inspect Exploit</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeModalTab === 'stix' && (
                <div className="space-y-3 font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 text-[11px]">OASIS STIX 2.1 Vulnerability Object:</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(JSON.stringify(selectedCveDetail, null, 2), 'stix-json')}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold"
                    >
                      {copiedText === 'stix-json' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy STIX 2.1</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-900 text-slate-100 text-[11px] overflow-x-auto leading-relaxed border border-slate-800">
                    {JSON.stringify(
                      {
                        type: "vulnerability",
                        spec_version: "2.1",
                        id: `vulnerability--${selectedCveDetail.cve.cve_id.toLowerCase()}`,
                        name: selectedCveDetail.cve.cve_id,
                        description: selectedCveDetail.cve.description,
                        external_references: [
                          {
                            source_name: "cve",
                            external_id: selectedCveDetail.cve.cve_id
                          }
                        ],
                        x_cvss_score: selectedCveDetail.cve.cvss_score,
                        x_cvss_vector: selectedCveDetail.cve.cvss_vector,
                        x_exploiting_actors: selectedCveDetail.exploiting_actors,
                        x_correlated_iocs_count: selectedCveDetail.associated_iocs.length,
                        x_poc_count: selectedCveDetail.pocs.length
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  </Portal>
</div>
);
};
