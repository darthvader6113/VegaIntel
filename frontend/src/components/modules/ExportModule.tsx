import React, { useState } from 'react';
import { Download, FileJson, FileSpreadsheet, Code2, Copy, Check, ShieldAlert, Cpu, ArrowUpRight } from 'lucide-react';
import { copyToClipboard } from '../../utils/clipboard';

export const ExportModule: React.FC = () => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const curlSnippets = [
    {
      title: 'Fetch STIX 2.1 Bundle (Direct SIEM/MISP Ingestion)',
      cmd: 'curl -X GET "http://localhost:8000/api/export/stix?min_confidence=75" -H "Accept: application/json" -o stix21_intel.json'
    },
    {
      title: 'Query Canonical IOCs with High Sightings',
      cmd: 'curl -X GET "http://localhost:8000/api/iocs/?min_sightings=2&min_confidence=80" -H "Accept: application/json"'
    },
    {
      title: 'Trigger Automated Threat Feed Collection',
      cmd: 'curl -X POST "http://localhost:8000/api/feeds/sync"'
    },
    {
      title: 'Export Deduplicated IOCs as CSV',
      cmd: 'curl -X GET "http://localhost:8000/api/export/csv" -o vegaintel_iocs.csv'
    }
  ];

  const handleCopy = async (text: string, idx: number) => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedIndex(idx);
      setTimeout(() => setCopiedIndex(null), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Enterprise SIEM Connector Banner (Coming Soon) */}
      <div className="cyber-card p-5 rounded-lg border border-amber-200 bg-amber-50/50 shadow-xs flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800 border border-amber-300">
              COMING SOON
            </span>
            <h3 className="text-sm font-bold text-slate-900 font-mono">
              Direct SIEM &amp; SOAR Connectors (Splunk, Microsoft Sentinel, IBM QRadar, Chronicle)
            </h3>
          </div>
          <p className="text-xs text-slate-600 font-sans max-w-3xl">
            Automated bidirectional live streaming connector pushing verified high-confidence canonical indicators (C2 IPs, domains, SHA256 hashes) directly into your enterprise detection rules with automated STIX 2.1 taxonomy mapping.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="px-3 py-1.5 rounded-md bg-white border border-amber-300 text-amber-900 text-xs font-mono font-semibold shadow-xs">
            v2.4 Roadmap
          </span>
        </div>
      </div>

      {/* Export Options Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* STIX 2.1 */}
        <div className="cyber-card p-5 rounded-lg border border-orange-200 bg-white shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileJson className="w-4 h-4 text-orange-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">OASIS STIX 2.1 Bundle</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              OASIS Cyber Threat Intelligence standard format. Includes Indicators, Vulnerabilities, Intrusion Sets, Malware, and Sightings.
            </p>
          </div>
          <a
            href="/api/export/stix"
            download="vegaintel_threat_bundle_stix21.json"
            className="w-full py-2 px-3 rounded-md bg-orange-500 hover:bg-orange-600 text-white font-mono font-bold text-xs flex items-center justify-center gap-2 shadow-xs transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Download STIX 2.1 JSON
          </a>
        </div>

        {/* CSV Export */}
        <div className="cyber-card p-5 rounded-lg border border-slate-200 bg-white shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">Canonical IOCs (CSV)</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              Spreadsheet format for SOC analysts. Contains normalized values, sighting counts, originating feeds, and confidence scores.
            </p>
          </div>
          <a
            href="/api/export/csv"
            download="vegaintel_canonical_iocs.csv"
            className="w-full py-2 px-3 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono font-bold text-xs flex items-center justify-center gap-2 border border-slate-300 shadow-xs transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Download CSV Export
          </a>
        </div>

        {/* JSON Export */}
        <div className="cyber-card p-5 rounded-lg border border-slate-200 bg-white shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Code2 className="w-4 h-4 text-blue-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">Raw JSON Repository</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              Complete raw JSON dump of canonical threat entities for script-based processing and data pipeline integration.
            </p>
          </div>
          <a
            href="/api/export/json"
            download="vegaintel_raw_dump.json"
            className="w-full py-2 px-3 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono font-bold text-xs flex items-center justify-center gap-2 border border-slate-300 shadow-xs transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Download Raw JSON
          </a>
        </div>
      </div>

      {/* REST API cURL Explorer */}
      <div className="cyber-card p-5 rounded-lg border border-slate-200 bg-white shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-orange-600" />
            <h3 className="text-sm font-semibold text-slate-900 font-mono">
              SIEM &amp; SOAR Integration API Snippets
            </h3>
          </div>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="text-xs font-mono text-orange-600 hover:text-orange-700 underline font-semibold flex items-center gap-1"
          >
            Interactive Swagger / OpenAPI Docs <ArrowUpRight className="w-3 h-3" />
          </a>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {curlSnippets.map((item, idx) => (
            <div key={idx} className="p-3 rounded-md bg-slate-50 border border-slate-200 space-y-1.5">
              <div className="flex items-center justify-between text-slate-600 font-semibold text-[11px]">
                <span>{item.title}</span>
                <button
                  type="button"
                  onClick={() => handleCopy(item.cmd, idx)}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 transition-colors"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-600" />
                      <span className="text-emerald-600 font-bold">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy cURL</span>
                    </>
                  )}
                </button>
              </div>
              <div className="p-2 rounded bg-slate-900 text-slate-100 overflow-x-auto text-[11px] selection:bg-orange-500">
                <code>{item.cmd}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
