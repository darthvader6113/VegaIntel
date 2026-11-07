import React, { useState, useEffect } from 'react';
import {
  Search,
  ExternalLink,
  Code2,
  Database,
  Users,
  X,
} from 'lucide-react';
import { CVE } from '../../types';
import { api } from '../../services/api';

export const CveExplorerModule: React.FC = () => {
  const [cves, setCves] = useState<CVE[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [onlyPoc, setOnlyPoc] = useState<boolean>(false);
  const [selectedCveDetail, setSelectedCveDetail] = useState<any | null>(null);
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
      const detail = await api.getCVEDetail(cveId);
      setSelectedCveDetail(detail);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search and Filters Bar */}
      <div className="cyber-card p-4 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search CVEs by ID (e.g. CVE-2021-44228) or keywords (e.g. Log4j, MOVEit)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-3">
          {/* Severity selector */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
          </select>

          {/* PoC toggle button */}
          <button
            onClick={() => setOnlyPoc(!onlyPoc)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border ${
              onlyPoc
                ? 'bg-orange-50 text-orange-700 border-orange-300 shadow-sm font-semibold'
                : 'bg-slate-100 text-slate-600 border-slate-200 hover:text-slate-900'
            }`}
          >
            <Code2 className="w-3.5 h-3.5 text-orange-600" />
            <span>Weaponized PoC</span>
          </button>
        </div>
      </div>

      {/* CVE Grid / List */}
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400">Loading vulnerabilities...</div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {cves.map((cve) => (
            <div
              key={cve.cve_id}
              onClick={() => openDetail(cve.cve_id)}
              className="cyber-card p-5 rounded-xl border border-slate-200 bg-white hover:border-orange-300 shadow-sm cursor-pointer transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="space-y-2 flex-1">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-mono text-sm font-bold text-slate-900 tracking-wide">
                    {cve.cve_id}
                  </span>
                  
                  {/* Severity badge */}
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                    cve.severity === 'CRITICAL'
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : 'bg-amber-50 text-amber-700 border-amber-200'
                  }`}>
                    {cve.severity} {cve.cvss_score.toFixed(1)}
                  </span>

                  {cve.has_poc && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200 flex items-center gap-1 font-semibold">
                      <Code2 className="w-3 h-3 text-orange-600" />
                      Exploit Available
                    </span>
                  )}

                  {cve.cwe_ids.map((cwe) => (
                    <span key={cwe} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                      {cwe}
                    </span>
                  ))}
                </div>

                <p className="text-xs text-slate-600 leading-relaxed line-clamp-2">
                  {cve.description}
                </p>
              </div>

              <div className="flex items-center gap-6 shrink-0 font-mono text-xs">
                <div className="text-right">
                  <div className="text-slate-500 text-[10px] uppercase font-semibold">Correlated IOCs</div>
                  <div className="text-orange-600 font-bold text-base flex items-center justify-end gap-1">
                    <Database className="w-3.5 h-3.5" />
                    {cve.associated_ioc_count}
                  </div>
                </div>

                <button className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-orange-500 hover:text-white text-slate-700 text-xs font-semibold border border-slate-200 shadow-sm transition-colors">
                  Inspect
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* CVE Detailed Modal */}
      {selectedCveDetail && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-3xl max-h-[85vh] rounded-2xl border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl">
            {/* Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50">
              <div>
                <div className="flex items-center gap-3">
                  <h3 className="text-xl font-bold font-mono text-slate-900">
                    {selectedCveDetail.cve.cve_id}
                  </h3>
                  <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">
                    CVSS {selectedCveDetail.cve.cvss_score} ({selectedCveDetail.cve.severity})
                  </span>
                </div>
                {selectedCveDetail.cve.cvss_vector && (
                  <div className="text-[11px] font-mono text-slate-500 mt-1">
                    Vector: {selectedCveDetail.cve.cvss_vector}
                  </div>
                )}
              </div>
              <button
                onClick={() => setSelectedCveDetail(null)}
                className="p-1 rounded-lg bg-slate-200 text-slate-600 hover:text-slate-900 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs">
              <div>
                <h4 className="font-semibold text-slate-800 uppercase tracking-wider font-mono text-[11px] mb-2">
                  Vulnerability Description
                </h4>
                <p className="text-slate-700 leading-relaxed bg-slate-50 p-3.5 rounded-lg border border-slate-200">
                  {selectedCveDetail.cve.description}
                </p>
              </div>

              {/* Mapped Threat Actors */}
              {selectedCveDetail.exploiting_actors.length > 0 && (
                <div>
                  <h4 className="font-semibold text-slate-800 uppercase tracking-wider font-mono text-[11px] mb-2 flex items-center gap-1.5">
                    <Users className="w-3.5 h-3.5 text-orange-600" />
                    Threat Actors Actively Exploiting
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedCveDetail.exploiting_actors.map((actor: string) => (
                      <span key={actor} className="px-2.5 py-1 rounded bg-orange-50 text-orange-700 border border-orange-200 font-mono font-semibold">
                        {actor}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Associated Canonical IOCs */}
              <div>
                <h4 className="font-semibold text-slate-800 uppercase tracking-wider font-mono text-[11px] mb-2 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-orange-600" />
                  Correlated Canonical IOCs ({selectedCveDetail.associated_iocs.length})
                </h4>
                {selectedCveDetail.associated_iocs.length === 0 ? (
                  <div className="text-slate-400 font-mono italic">No IOCs mapped yet.</div>
                ) : (
                  <div className="space-y-2 font-mono">
                    {selectedCveDetail.associated_iocs.map((ioc: any) => (
                      <div key={ioc.fingerprint} className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                        <div>
                          <span className="text-orange-600 font-semibold mr-2">[{ioc.ioc_type.toUpperCase()}]</span>
                          <span className="text-slate-900 font-medium">{ioc.ioc_value}</span>
                          <span className="text-slate-500 ml-2 text-[10px]">({ioc.sources.join(', ')})</span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 text-[10px]">
                          {ioc.sighting_count} sightings
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* PoC Exploit References */}
              <div>
                <h4 className="font-semibold text-slate-800 uppercase tracking-wider font-mono text-[11px] mb-2 flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5 text-amber-600" />
                  PoC &amp; Exploit References ({selectedCveDetail.pocs.length})
                </h4>
                <div className="space-y-2">
                  {selectedCveDetail.pocs.map((poc: any) => (
                    <div key={poc.poc_id} className="p-3 rounded bg-slate-50 border border-slate-200 flex items-start justify-between gap-4 font-mono">
                      <div>
                        <div className="font-semibold text-slate-900">{poc.title}</div>
                        <div className="text-[11px] text-slate-600 mt-1">{poc.description}</div>
                        <div className="text-[10px] text-slate-500 mt-1">Source: {poc.source} · Author: {poc.author}</div>
                      </div>
                      <a
                        href={poc.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 rounded bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-500 hover:text-white flex items-center gap-1 shrink-0 font-bold transition-colors"
                      >
                        Source <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
