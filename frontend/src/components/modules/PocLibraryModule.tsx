import React, { useState, useEffect } from 'react';
import { ExternalLink, Code2, Search, ShieldCheck, FileCode, Check, Copy } from 'lucide-react';
import { PoCReference } from '../../types';
import { api } from '../../services/api';

export const PocLibraryModule: React.FC = () => {
  const [pocs, setPocs] = useState<PoCReference[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
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

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

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
      {/* Enterprise Filter Header */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search exploit PoCs by CVE ID (e.g. CVE-2024-3400), title, or author..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 flex items-center gap-1.5 font-semibold">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            Defensive Index · Sandbox Safe
          </span>
          <span className="text-xs font-mono text-slate-400 pl-1 border-l border-slate-200">
            {filteredPocs.length} Exploits
          </span>
        </div>
      </div>

      {/* PoC Exploit Cards Grid */}
      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <span>Indexing weaponized exploit references...</span>
        </div>
      ) : filteredPocs.length === 0 ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 bg-white rounded-xl border border-slate-200">
          No PoC references match your search query.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredPocs.map((poc) => (
            <div
              key={poc.poc_id}
              className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs space-y-3.5 hover:border-amber-300 hover:shadow-md transition-all flex flex-col justify-between group"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-0.5 rounded-full bg-orange-50 text-orange-700 font-mono text-xs font-bold border border-orange-200">
                        {poc.cve_id}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] border border-slate-200 font-medium">
                        {poc.source}
                      </span>
                      <span className="text-[10px] font-mono text-emerald-700 font-bold px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200">
                        {poc.reliability || 'VERIFIED'}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-slate-900 font-mono truncate group-hover:text-orange-600 transition-colors" title={poc.title}>
                      {poc.title}
                    </h3>
                  </div>

                  <a
                    href={poc.url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-mono text-xs font-bold flex items-center justify-center gap-1.5 shrink-0 transition-colors shadow-xs active:scale-95"
                  >
                    <span>Source</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed bg-slate-50/70 p-3 rounded-lg border border-slate-200/80 font-sans line-clamp-3">
                  {poc.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Author: <strong className="text-slate-700 font-normal">{poc.author}</strong></span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(poc.url, poc.poc_id)}
                  className="text-slate-500 hover:text-slate-800 flex items-center gap-1 transition-colors"
                >
                  {copiedKey === poc.poc_id ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-600" />
                      <span className="text-emerald-600 font-semibold">Copied URL</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Link</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
