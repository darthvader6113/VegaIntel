import React, { useState } from 'react';
import { X, Send, CheckCircle2, AlertTriangle, Database } from 'lucide-react';
import { api } from '../../services/api';

interface RequestIocModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const RequestIocModal: React.FC<RequestIocModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [iocValue, setIocValue] = useState('');
  const [iocType, setIocType] = useState('');
  const [targetCve, setTargetCve] = useState('');
  const [tags, setTags] = useState('');
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successResult, setSuccessResult] = useState<any | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessResult(null);

    if (!iocValue.trim()) {
      setErrorMsg('Please provide an IOC value.');
      return;
    }

    try {
      setLoading(true);
      const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean);
      const res = await api.requestIOC({
        ioc: iocValue.trim(),
        ioc_type: iocType || undefined,
        target_cve: targetCve.trim() || undefined,
        tags: tagList,
        notes: notes.trim() || undefined,
      });

      setSuccessResult(res);
      setTimeout(() => {
        onSuccess();
      }, 1500);
    } catch (err: any) {
      setErrorMsg(err.message || 'Submission failed');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setIocValue('');
    setIocType('');
    setTargetCve('');
    setTags('');
    setNotes('');
    setErrorMsg(null);
    setSuccessResult(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-xl rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50">
          <div>
            <h3 className="text-lg font-bold font-mono text-slate-900 flex items-center gap-2">
              <Database className="w-5 h-5 text-orange-600" />
              On-Demand IOC Request &amp; Enrichment
            </h3>
            <p className="text-xs text-slate-500 font-mono mt-1">
              Validates through False Positive Engine, generates canonical fingerprint, and correlates with threat graph.
            </p>
          </div>
          <button
            onClick={resetForm}
            className="p-1 rounded-lg bg-slate-200 hover:bg-slate-300 text-slate-600 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 font-mono text-xs">
          {errorMsg && (
            <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-700 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <div>
                <strong className="block text-red-700 font-bold mb-0.5">Validation Alert</strong>
                <span>{errorMsg}</span>
              </div>
            </div>
          )}

          {successResult && (
            <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <strong className="block text-emerald-800 font-bold mb-0.5">IOC Accepted &amp; Deduplicated</strong>
                <span>
                  Fingerprint: <code className="text-slate-900 bg-slate-100 px-1 py-0.5 rounded font-bold">{successResult.fingerprint}</code> (Sightings: {successResult.total_sightings})
                </span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-slate-700 text-[11px] font-semibold uppercase mb-1">
              Indicator Value (IP, Domain, URL, or Hash) *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. 194.38.20.41, mal-c2.net, or SHA-256 hash"
              value={iocValue}
              onChange={(e) => setIocValue(e.target.value)}
              className="w-full px-3.5 py-2.5 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-colors"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-700 text-[11px] font-semibold uppercase mb-1">
                Indicator Type
              </label>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
              >
                <option value="">Auto-Detect from Syntax</option>
                <option value="ip">IPv4 / IPv6 Address</option>
                <option value="domain">Domain Name</option>
                <option value="url">URL Address</option>
                <option value="sha256">SHA-256 Hash</option>
                <option value="md5">MD5 Hash</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-700 text-[11px] font-semibold uppercase mb-1">
                Target Vulnerability (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. CVE-2021-44228"
                value={targetCve}
                onChange={(e) => setTargetCve(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-700 text-[11px] font-semibold uppercase mb-1">
              Threat Tags (Comma-Separated)
            </label>
            <input
              type="text"
              placeholder="e.g. cobalt-strike, c2, suspicious-beacon"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
            />
          </div>

          <div>
            <label className="block text-slate-700 text-[11px] font-semibold uppercase mb-1">
              Analyst Investigation Notes
            </label>
            <textarea
              rows={3}
              placeholder="Provide contextual rationale or telemetry details..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 resize-none font-sans"
            />
          </div>

          <div className="pt-3 border-t border-slate-200 flex items-center justify-between">
            <span className="text-[10px] text-slate-500">
              Filtered against 10k apex whitelist &amp; RFC1918.
            </span>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-bold shadow-md transition-all active:scale-95"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{loading ? 'Processing...' : 'Request & Ingest'}</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
