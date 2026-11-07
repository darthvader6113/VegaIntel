import React, { useState, useEffect } from 'react';
import { AlertTriangle, ExternalLink, Code2, Search, ShieldCheck } from 'lucide-react';
import { PoCReference } from '../../types';
import { api } from '../../services/api';

export const PocLibraryModule: React.FC = () => {
  const [pocs, setPocs] = useState<PoCReference[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPocs = async () => {
      try {
        setLoading(true);
        const res = await api.getPoCs();
        setPocs(res.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchPocs();
  }, []);

  const filteredPocs = pocs.filter(
    (p) =>
      !searchTerm ||
      p.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.author.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.source.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="w-full space-y-6">
      {/* Search Header */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search PoC exploits by CVE ID (e.g. CVE-2021-44228), title, or author..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>
        <span className="text-xs font-mono text-slate-500 font-medium">
          Cataloged Exploit References ({filteredPocs.length})
        </span>
      </div>

      {/* Safety Advisory Banner */}
      <div className="p-4 rounded-xl border border-amber-200 bg-amber-50/60 flex items-start gap-3 shadow-xs">
        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="text-xs">
          <strong className="text-amber-900 font-mono block mb-1">
            DEFENSIVE RESEARCH ADVISORY (ENGINEERING MANDATE)
          </strong>
          <span className="text-amber-800 leading-relaxed font-sans">
            Exploit references are indexed exclusively for threat verification, IOC correlation, and patch prioritization. Scripts and source links are treated as untrusted metadata with strict sandbox isolation.
          </span>
        </div>
      </div>

      {/* PoC Reference Cards */}
      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading verified exploit references...</span>
        </div>
      ) : filteredPocs.length === 0 ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 bg-white rounded-xl border border-slate-200">
          No PoC references match the search query.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredPocs.map((poc) => (
            <div
              key={poc.poc_id}
              className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs space-y-3.5 hover:border-amber-300 hover:shadow-md transition-all"
            >
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="px-2.5 py-0.5 rounded-full bg-orange-50 text-orange-700 font-mono text-xs font-bold border border-orange-200">
                      {poc.cve_id}
                    </span>
                    <span className="text-sm font-bold text-slate-900 font-mono">
                      {poc.title}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] border border-slate-200 font-medium">
                      {poc.source}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    Author: <span className="text-slate-800 font-semibold">{poc.author}</span> · Reliability: <strong className="text-emerald-700">{poc.reliability}</strong>
                  </div>
                </div>

                <a
                  href={poc.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3.5 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-mono text-xs font-bold flex items-center justify-center gap-1.5 shrink-0 transition-colors shadow-xs active:scale-95"
                >
                  <span>Inspect Exploit</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>

              <p className="text-xs text-slate-700 leading-relaxed bg-slate-50/80 p-3.5 rounded-xl border border-slate-200 font-sans">
                {poc.description}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
