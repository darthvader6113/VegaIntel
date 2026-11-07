import React, { useState, useEffect } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
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
    <div className="space-y-6">
      {/* Top Banner with Trigger Button */}
      <div className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-600" />
            Automated OSINT Pipeline Health
          </h3>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Synchronizing 5 core open-source threat feeds + NVD &amp; MITRE ATT&amp;CK
          </p>
        </div>

        <button
          onClick={triggerSync}
          disabled={isSyncing}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider font-mono transition-all ${
            isSyncing
              ? 'bg-orange-100 text-orange-700 border border-orange-300 cursor-wait'
              : 'bg-orange-500 hover:bg-orange-600 text-white font-bold shadow-sm'
          }`}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
          <span>{isSyncing ? 'Syncing...' : 'Run Ingestion Cycle'}</span>
        </button>
      </div>

      {/* Feed Status Cards */}
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400">Loading feed statuses...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {feeds.map((feed) => (
            <div
              key={feed.feed_name}
              className="cyber-card p-5 rounded-xl border border-slate-200 bg-white shadow-sm space-y-3"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 font-mono">{feed.feed_name}</h4>
                  <div className="text-[10px] text-slate-400 font-mono mt-0.5">{feed.category}</div>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                  feed.status === 'HEALTHY'
                    ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                    : feed.status === 'SYNCING'
                    ? 'bg-amber-100 text-amber-800 border-amber-200 animate-pulse'
                    : 'bg-red-100 text-red-800 border-red-200'
                }`}>
                  {feed.status}
                </span>
              </div>

              <div className="space-y-1 font-mono text-xs">
                <div className="flex justify-between text-slate-500">
                  <span>Total Ingested:</span>
                  <span className="text-slate-900 font-semibold">{feed.total_records_ingested}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Unique Canonical:</span>
                  <span className="text-orange-600 font-semibold">{feed.unique_iocs_contributed}</span>
                </div>
                {feed.last_successful_sync && (
                  <div className="flex justify-between text-slate-500 text-[11px] pt-1 border-t border-slate-100">
                    <span>Last Sync:</span>
                    <span className="text-slate-700">{new Date(feed.last_successful_sync).toLocaleTimeString()}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Ingestion Jobs History Table */}
      <div className="cyber-card rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <h4 className="text-sm font-semibold text-slate-900 font-mono">
            Ingestion Jobs &amp; Deduplication Audit Trail
          </h4>
          <span className="text-xs font-mono text-slate-500">{jobs.length} Recent Runs</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[11px] bg-slate-50">
                <th className="py-3 px-4">Job ID</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Processed</th>
                <th className="py-3 px-4">New IOCs</th>
                <th className="py-3 px-4">Sightings</th>
                <th className="py-3 px-4 text-emerald-700">Duplicates Saved</th>
                <th className="py-3 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {jobs.map((job) => (
                <tr key={job.job_id} className="hover:bg-slate-50">
                  <td className="py-3 px-4 text-slate-400">{job.job_id.slice(0, 8)}...</td>
                  <td className="py-3 px-4 font-bold text-slate-900">{job.source}</td>
                  <td className="py-3 px-4 text-slate-700">{job.records_processed}</td>
                  <td className="py-3 px-4 text-orange-600 font-semibold">{job.new_iocs_created}</td>
                  <td className="py-3 px-4 text-slate-700">{job.sightings_added}</td>
                  <td className="py-3 px-4 text-emerald-700 font-bold">{job.duplicates_prevented}</td>
                  <td className="py-3 px-4 text-right">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      job.status === 'SUCCESS'
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        : 'bg-amber-100 text-amber-800 border border-amber-200'
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
