import React, { useState } from 'react';
import { Download, FileJson, FileSpreadsheet, Code2, Copy, Check } from 'lucide-react';

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

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Export Options Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* STIX 2.1 */}
        <div className="cyber-card p-6 rounded-xl border border-orange-200 bg-white shadow-sm flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileJson className="w-5 h-5 text-orange-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">OASIS STIX 2.1 Bundle</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              OASIS Cyber Threat Intelligence standard format. Includes Indicators, Vulnerabilities, Intrusion Sets, Malware, and Sightings.
            </p>
          </div>
          <a
            href="/api/export/stix"
            download="vegaintel_threat_bundle_stix21.json"
            className="w-full py-2.5 px-4 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-mono font-bold text-xs flex items-center justify-center gap-2 shadow-sm transition-all"
          >
            <Download className="w-4 h-4" />
            Download STIX 2.1 JSON
          </a>
        </div>

        {/* CSV Export */}
        <div className="cyber-card p-6 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileSpreadsheet className="w-5 h-5 text-emerald-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">Canonical IOCs (CSV)</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              Spreadsheet format for SOC analysts. Contains normalized values, sighting counts, originating feeds, and confidence scores.
            </p>
          </div>
          <a
            href="/api/export/csv"
            download="vegaintel_canonical_iocs.csv"
            className="w-full py-2.5 px-4 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono font-bold text-xs flex items-center justify-center gap-2 border border-slate-300 shadow-sm transition-all"
          >
            <Download className="w-4 h-4" />
            Download CSV Export
          </a>
        </div>

        {/* JSON Export */}
        <div className="cyber-card p-6 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Code2 className="w-5 h-5 text-blue-600" />
              <h3 className="font-bold text-slate-900 font-mono text-sm">Raw JSON Repository</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed font-sans">
              Complete raw JSON dump of canonical threat entities for script-based processing and data pipeline integration.
            </p>
          </div>
          <a
            href="/api/export/json"
            download="vegaintel_raw_dump.json"
            className="w-full py-2.5 px-4 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono font-bold text-xs flex items-center justify-center gap-2 border border-slate-300 shadow-sm transition-all"
          >
            <Download className="w-4 h-4" />
            Download Raw JSON
          </a>
        </div>
      </div>

      {/* REST API cURL Explorer */}
      <div className="cyber-card p-6 rounded-xl border border-slate-200 bg-white shadow-sm space-y-4">
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
            className="text-xs font-mono text-orange-600 hover:text-orange-700 underline font-semibold"
          >
            Interactive Swagger / OpenAPI Docs &rarr;
          </a>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {curlSnippets.map((item, idx) => (
            <div key={idx} className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center justify-between text-slate-600 text-[11px]">
                <span className="font-semibold text-slate-800">{item.title}</span>
                <button
                  onClick={() => copyToClipboard(item.cmd, idx)}
                  className="flex items-center gap-1 text-slate-600 hover:text-slate-900 px-2 py-0.5 rounded bg-white border border-slate-200 shadow-sm transition-colors"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-600" />
                      <span className="text-emerald-700 text-[10px] font-bold">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span className="text-[10px]">Copy cURL</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="text-orange-400 bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto text-[11px]">
                {item.cmd}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
