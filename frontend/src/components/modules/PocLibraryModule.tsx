import React, { useState, useEffect } from 'react';
import { AlertTriangle, ExternalLink } from 'lucide-react';
import { PoCReference } from '../../types';
import { api } from '../../services/api';

export const PocLibraryModule: React.FC = () => {
  const [pocs, setPocs] = useState<PoCReference[]>([]);
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

  return (
    <div className="space-y-6">
      {/* Strict Engineering Safety Advisory Banner */}
      <div className="cyber-card p-4 rounded-xl border border-amber-300 bg-amber-50 flex items-start gap-3 shadow-sm">
        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="text-xs">
          <strong className="text-amber-800 font-mono block mb-1">
            CRITICAL SAFETY ADVISORY (ENGINEERING RULE)
          </strong>
          <span className="text-amber-900 leading-relaxed font-sans">
            Exploits and PoCs are indexed purely as technical context and defensive references. VegaIntel treats all repository scripts as untrusted metadata and strictly prohibits automatic or headless execution.
          </span>
        </div>
      </div>

      {/* PoC Reference Cards */}
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400">Loading PoC library...</div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {pocs.map((poc) => (
            <div
              key={poc.poc_id}
              className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm space-y-3"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-orange-50 text-orange-700 font-mono text-xs font-bold border border-orange-200">
                      {poc.cve_id}
                    </span>
                    <span className="text-sm font-bold text-slate-900 font-mono">
                      {poc.title}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] border border-slate-200 font-medium">
                      {poc.source}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono mt-1">
                    Author: {poc.author} · Reliability: <strong className="text-emerald-700">{poc.reliability}</strong>
                  </div>
                </div>

                <a
                  href={poc.url}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-orange-500 hover:text-white text-slate-700 border border-slate-200 transition-colors text-xs font-semibold flex items-center gap-1.5 shrink-0 shadow-sm"
                >
                  Inspect Source <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>

              <p className="text-xs text-slate-700 leading-relaxed bg-slate-50 p-3 rounded-lg border border-slate-200 font-sans">
                {poc.description}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
