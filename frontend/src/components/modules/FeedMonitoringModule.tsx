import React, { useState, useEffect } from 'react';
import { Activity, RefreshCw, Server, CheckCircle2, Clock, ShieldCheck } from 'lucide-react';
import { FeedStatus, IngestionJob } from '../../types';
import { api } from '../../services/api';

export const FeedMonitoringModule: React.FC = () => {
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [jobs, setJobs] = useState<IngestionJob[]>([]);
  const [isSyncing, setIsSyncing] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [fRes, jRes] = await Promise.all([
        api.getFeedStatuses(),
        api.getIngestionJobs(),
      ]);
      setFeeds(fRes.feeds);
      setJobs(jRes.jobs);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const triggerSync = async () => {
    try {
      setIsSyncing(true);
      await api.triggerSync();
      setTimeout(() => {
        loadData();
        setIsSyncing(false);
      }, 2000);
    } catch (e) {
      console.error(e);
      setIsSyncing(false);
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Top Banner with Trigger Button */}
      <div className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-900 font-mono flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-600" />
            OSINT Ingestion Health &amp; Pipeline Telemetry
          </h3>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Synchronizing live feeds: CISA KEV, AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, and Emerging Threats.
          </p>
        </div>

        <button
          type="button"
          onClick={triggerSync}
          disabled={isSyncing}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold uppercase tracking-wider font-mono transition-all shadow-xs ${
            isSyncing
              ? 'bg-orange-100 text-orange-700 border border-orange-200 cursor-wait'
              : 'bg-orange-500 hover:bg-orange-600 active:scale-98 text-white font-bold'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
          <span>{isSyncing ? 'Synchronizing...' : 'Run Ingestion Cycle'}</span>
        </button>
      </div>

      {/* Feed Status Cards */}
      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <span>Polling feed connector statuses...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {feeds.map((feed) => (
            <div
              key={feed.feed_name}
              className="p-5 rounded-xl border border-slate-200/90 bg-white shadow-xs space-y-3 flex flex-col justify-between hover:border-slate-300 transition-all"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 font-mono">{feed.feed_name}</h4>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5 uppercase tracking-wider">{feed.category}</div>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                  feed.status === 'HEALTHY'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : feed.status === 'SYNCING'
                    ? 'bg-amber-50 text-amber-800 border-amber-200 animate-pulse'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  {feed.status}
                </span>
              </div>

              <div className="space-y-1.5 font-mono text-xs pt-2 border-t border-slate-100">
                <div className="flex justify-between text-slate-500">
                  <span>Total Ingested:</span>
                  <span className="text-slate-900 font-bold">{feed.total_records_ingested.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Unique Canonical:</span>
                  <span className="text-orange-600 font-bold">{feed.unique_iocs_contributed.toLocaleString()}</span>
                </div>
                {feed.last_successful_sync && (
                  <div className="flex justify-between text-slate-400 text-[10px] pt-1 border-t border-slate-50">
                    <span>Last Checked:</span>
                    <span>{new Date(feed.last_successful_sync).toLocaleTimeString()}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Ingestion Jobs History Table */}
      <div className="rounded-xl border border-slate-200/90 bg-white shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-100 bg-slate-50/50 flex items-center justify-between">
          <h4 className="text-xs font-bold text-slate-900 font-mono uppercase tracking-wider">
            Ingestion Audit Trail &amp; Deduplication Log
          </h4>
          <span className="text-xs font-mono text-slate-400">{jobs.length} Recent Runs</span>
        </div>

        <div className="overflow-x-auto min-w-0">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50/80">
                <th className="py-3 px-4 font-semibold">Job ID</th>
                <th className="py-3 px-4 font-semibold">Feed Source</th>
                <th className="py-3 px-4 font-semibold">Processed</th>
                <th className="py-3 px-4 font-semibold">New Canonical</th>
                <th className="py-3 px-4 font-semibold">Sightings</th>
                <th className="py-3 px-4 font-semibold text-emerald-700">Duplicates Avoided</th>
                <th className="py-3 px-4 font-semibold text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {jobs.map((job) => (
                <tr key={job.job_id} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-2.5 px-4 text-slate-400 font-mono">{job.job_id.slice(0, 8)}...</td>
                  <td className="py-2.5 px-4 font-bold text-slate-900">{job.source}</td>
                  <td className="py-2.5 px-4 text-slate-700">{job.records_processed.toLocaleString()}</td>
                  <td className="py-2.5 px-4 text-orange-600 font-bold">{job.new_iocs_created.toLocaleString()}</td>
                  <td className="py-2.5 px-4 text-slate-700">{job.sightings_added.toLocaleString()}</td>
                  <td className="py-2.5 px-4 text-emerald-700 font-bold">{job.duplicates_prevented.toLocaleString()}</td>
                  <td className="py-2.5 px-4 text-right">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      job.status === 'SUCCESS'
                        ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                        : 'bg-amber-50 text-amber-800 border border-amber-200'
                    }`}>
                      {job.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
