import React, { useState } from 'react';
import {
  X,
  Search,
  CheckCircle2,
  AlertTriangle,
  Database,
  ShieldAlert,
  Sparkles,
  Layers,
  Copy,
  Check,
  Flame,
  ArrowRight,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import { api } from '../../services/api';

interface RequestIocModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const RequestIocModal: React.FC<RequestIocModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [cveInput, setCveInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const quickCveChips = [
    { id: 'CVE-2024-3400', label: 'Palo Alto GlobalProtect (10.0)', hot: true },
    { id: 'CVE-2021-44228', label: 'Log4Shell (10.0)', hot: true },
    { id: 'CVE-2023-34362', label: 'MOVEit SQLi (9.8)', hot: false },
    { id: 'CVE-2024-1709', label: 'ScreenConnect Bypass (10.0)', hot: true },
    { id: 'CVE-2023-23397', label: 'Outlook NTLM Leak (9.8)', hot: false },
  ];

  const handleSelectChip = (cveId: string) => {
    setCveInput(cveId);
    setErrorMsg(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setResult(null);

    const clean = cveInput.trim().toUpperCase();
    if (!clean) {
      setErrorMsg('Please enter a CVE identifier (e.g. CVE-2024-3400).');
      return;
    }

    if (!/^CVE-\d{4}-\d{4,8}$/i.test(clean)) {
      setErrorMsg(`Invalid CVE format '${clean}'. Expected format is CVE-YYYY-NNNN (e.g. CVE-2024-3400).`);
      return;
    }

    try {
      setLoading(true);
      setLoadingStep('Connecting to NIST NVD & CISA KEV feeds...');

      setTimeout(() => {
        setLoadingStep('Querying ThreatFox, AlienVault OTX & URLhaus for active C2 indicators...');
      }, 700);

      setTimeout(() => {
        setLoadingStep('Running deterministic deduplication & false positive prevention...');
      }, 1400);

      const res = await api.fetchIOCsByCVE(clean);

      setResult(res);
      onSuccess();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch IOCs for CVE');
    } finally {
      setLoading(false);
      setLoadingStep('');
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const resetModal = () => {
    setCveInput('');
    setLoading(false);
    setErrorMsg(null);
    setResult(null);
    onClose();
  };

  const getTypeColor = (type: string) => {
    switch ((type || '').toLowerCase()) {
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
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
      <div className="w-full max-w-2xl max-h-[90vh] rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-2xl flex flex-col animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50/80 shrink-0">
          <div className="space-y-1 min-w-0 pr-4">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-orange-100 border border-orange-200 flex items-center justify-center text-orange-700">
                <Database className="w-4 h-4" />
              </div>
              <h3 className="text-base font-bold font-mono text-slate-900 tracking-tight">
                CVE-Driven Threat Intelligence &amp; IOC Discovery
              </h3>
            </div>
            <p className="text-xs text-slate-500 font-sans leading-relaxed">
              Provide any CVE identifier (e.g. <strong className="text-slate-800 font-mono">CVE-2024-3400</strong>). VegaIntel queries NIST NVD, CISA KEV, ThreatFox, AlienVault OTX, and URLhaus to discover, deduplicate, and ingest all correlated C2 indicators.
            </p>
          </div>
          <button
            type="button"
            onClick={resetModal}
            className="p-1.5 rounded-lg bg-slate-200/80 hover:bg-slate-300 text-slate-600 transition-colors shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Input Form */}
          {!result && (
            <form onSubmit={handleSubmit} className="space-y-5">
              {errorMsg && (
                <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 flex items-start gap-2.5 font-mono">
                  <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <strong className="block text-rose-800 font-bold">Input Error</strong>
                    <span>{errorMsg}</span>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <label className="block text-xs font-mono font-bold text-slate-800 uppercase tracking-wider">
                  Vulnerability Identifier (CVE ID)
                </label>
                <div className="relative">
                  <ShieldAlert className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Enter CVE ID (e.g. CVE-2024-3400, CVE-2021-44228)..."
                    value={cveInput}
                    onChange={(e) => {
                      setCveInput(e.target.value);
                      setErrorMsg(null);
                    }}
                    disabled={loading}
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-300 rounded-xl font-mono text-sm font-bold text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 transition-all uppercase"
                  />
                </div>
              </div>

              {/* Quick Suggestion Chips */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  Suggested High-Impact CVEs:
                </span>
                <div className="flex flex-wrap gap-2">
                  {quickCveChips.map((chip) => (
                    <button
                      key={chip.id}
                      type="button"
                      onClick={() => handleSelectChip(chip.id)}
                      disabled={loading}
                      className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono transition-all flex items-center gap-1.5 ${
                        cveInput.toUpperCase() === chip.id
                          ? 'bg-orange-50 text-orange-700 border-orange-300 font-bold shadow-xs'
                          : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                      }`}
                    >
                      {chip.hot && <Flame className="w-3 h-3 text-orange-500" />}
                      <span className="font-bold">{chip.id}</span>
                      <span className="text-slate-400 text-[10px]">({chip.label.split(' ')[1] || 'KEV'})</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Progress Stepper when loading */}
              {loading && (
                <div className="p-5 rounded-xl bg-orange-50/70 border border-orange-200 space-y-2 animate-in fade-in">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-orange-900">
                    <RefreshCw className="w-4 h-4 text-orange-600 animate-spin" />
                    <span>Automated Ingestion Pipeline Active...</span>
                  </div>
                  <div className="text-[11px] font-mono text-orange-700 pl-6">
                    {loadingStep}
                  </div>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className={`w-full py-2.5 px-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 shadow-xs ${
                  loading
                    ? 'bg-orange-200 text-orange-800 cursor-wait'
                    : 'bg-orange-500 hover:bg-orange-600 active:scale-98 text-white shadow-sm'
                }`}
              >
                <Search className="w-4 h-4" />
                <span>{loading ? 'Discovering & Ingesting IOCs...' : 'Fetch & Ingest All Correlated IOCs'}</span>
              </button>
            </form>
          )}

          {/* Results Display */}
          {result && (
            <div className="space-y-6 animate-in fade-in">
              {/* Success Banner */}
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="font-bold font-mono text-sm text-emerald-900">
                    Successfully Ingested {result.summary.total_iocs_found} Canonical Indicators
                  </h4>
                  <p className="text-xs text-emerald-800 font-sans">
                    All indicators for <strong className="font-mono">{result.cve_id}</strong> have been normalized, checked for false positives, deduplicated, and persisted into the database.
                  </p>
                </div>
              </div>

              {/* CVE Metadata Pill Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs text-center">
                <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                  <span className="text-[10px] text-slate-400 block uppercase">CVSS Score</span>
                  <span className="text-sm font-bold text-slate-900 mt-0.5 block">
                    {(result.cve_details?.cvss_score ?? 0).toFixed(1)} ({result.cve_details?.severity || 'HIGH'})
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-orange-50 border border-orange-200">
                  <span className="text-[10px] text-orange-600 block uppercase">Total Discovered</span>
                  <span className="text-sm font-bold text-orange-700 mt-0.5 block">
                    {result.summary.total_iocs_found} IOCs
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200">
                  <span className="text-[10px] text-emerald-600 block uppercase">Duplicates Merged</span>
                  <span className="text-sm font-bold text-emerald-700 mt-0.5 block">
                    {result.summary.duplicates_prevented} Prevented
                  </span>
                </div>
                <div className="p-2.5 rounded-xl bg-purple-50 border border-purple-200">
                  <span className="text-[10px] text-purple-600 block uppercase">Linked Actors</span>
                  <span className="text-sm font-bold text-purple-700 mt-0.5 block">
                    {result.summary.attributed_threat_actors.length} APTs
                  </span>
                </div>
              </div>

              {/* Attributed Threat Actors if any */}
              {result.summary.attributed_threat_actors.length > 0 && (
                <div className="space-y-1.5 font-mono">
                  <span className="text-[11px] text-slate-500 font-semibold uppercase">
                    Attributed Threat Groups:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {result.summary.attributed_threat_actors.map((actor: string) => (
                      <span key={actor} className="px-2.5 py-1 rounded-lg bg-purple-50 text-purple-800 border border-purple-200 font-bold text-xs">
                        {actor}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted IOCs List */}
              <div className="space-y-2 font-mono">
                <span className="text-[11px] text-slate-500 font-semibold uppercase">
                  Ingested Canonical IOCs ({result.iocs.length}):
                </span>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {result.iocs.map((ioc: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 group">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border shrink-0 ${getTypeColor(ioc.ioc_type)}`}>
                          {ioc.ioc_type}
                        </span>
                        <span className="font-semibold text-slate-900 truncate select-all">{ioc.ioc_value}</span>
                        <span className="text-slate-400 text-[10px] hidden sm:inline">
                          ({ioc.sources.join(', ')})
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] font-bold text-slate-500">
                          {ioc.sighting_count}x
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(ioc.ioc_value, `ioc-${idx}`)}
                          className="p-1 text-slate-400 hover:text-slate-800"
                          title="Copy IOC"
                        >
                          {copiedKey === `ioc-${idx}` ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action buttons */}
              <div className="pt-3 border-t border-slate-200 flex items-center justify-between font-mono">
                <button
                  type="button"
                  onClick={() => {
                    setResult(null);
                    setCveInput('');
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors"
                >
                  Discover Another CVE
                </button>
                <button
                  type="button"
                  onClick={resetModal}
                  className="px-4 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white text-xs font-bold transition-colors shadow-xs"
                >
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
