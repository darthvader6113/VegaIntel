import React, { useState, useEffect } from 'react';
import { Users, Globe, Target, Terminal, X, Database } from 'lucide-react';
import { APTGroup } from '../../types';
import { api } from '../../services/api';

export const AptGroupsModule: React.FC = () => {
  const [groups, setGroups] = useState<APTGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<any | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchGroups = async () => {
      try {
        setLoading(true);
        const res = await api.getAPTGroups({ q: searchTerm || undefined });
        setGroups(res.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchGroups();
  }, [searchTerm]);

  const openGroup = async (groupId: string) => {
    try {
      const data = await api.getAPTDetail(groupId);
      setSelectedGroup(data);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="cyber-card p-4 rounded-xl border border-slate-200 bg-white shadow-sm flex items-center justify-between">
        <input
          type="text"
          placeholder="Search APT groups (e.g. Lazarus, Cozy Bear, Volt Typhoon)..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full max-w-md px-4 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
        />
        <span className="text-xs font-mono text-slate-500 font-medium">
          MITRE ATT&amp;CK Threat Actors ({groups.length})
        </span>
      </div>

      {/* Grid of APT Groups */}
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-slate-400">Loading threat actors...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {groups.map((apt) => (
            <div
              key={apt.group_id}
              onClick={() => openGroup(apt.group_id)}
              className="cyber-card p-5 rounded-xl border border-slate-200 bg-white hover:border-orange-300 shadow-sm cursor-pointer transition-all space-y-4"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-mono">{apt.name}</h3>
                    {apt.origin_country && (
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-mono border border-slate-200 flex items-center gap-1">
                        <Globe className="w-3 h-3 text-orange-600" />
                        {apt.origin_country}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono mt-1">
                    Aliases: {apt.aliases.join(', ')}
                  </div>
                </div>
                <span className="px-2 py-1 rounded bg-orange-50 text-orange-700 font-mono text-xs font-bold border border-orange-200">
                  {apt.associated_malware.length} Payloads
                </span>
              </div>

              <p className="text-xs text-slate-600 line-clamp-2 leading-relaxed">
                {apt.description}
              </p>

              {/* Target Sectors & Techniques */}
              <div className="space-y-2 pt-2 border-t border-slate-100 text-xs font-mono">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-slate-500 text-[11px] flex items-center gap-1 font-semibold">
                    <Target className="w-3 h-3 text-red-500" /> Targets:
                  </span>
                  {apt.target_sectors.slice(0, 3).map((sec) => (
                    <span key={sec} className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] border border-slate-200">
                      {sec}
                    </span>
                  ))}
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-slate-500 text-[11px] flex items-center gap-1 font-semibold">
                    <Terminal className="w-3 h-3 text-orange-600" /> Techniques:
                  </span>
                  {apt.techniques.slice(0, 2).map((tech) => (
                    <span key={tech} className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] border border-slate-200">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* APT Detail Modal */}
      {selectedGroup && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl">
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50">
              <div>
                <h3 className="text-xl font-bold font-mono text-slate-900 flex items-center gap-2">
                  <Users className="w-5 h-5 text-orange-600" />
                  {selectedGroup.group.name}
                </h3>
                <div className="text-xs text-slate-500 font-mono mt-1">
                  Origin: {selectedGroup.group.origin_country || 'Unknown'} · Aliases: {selectedGroup.group.aliases.join(', ')}
                </div>
              </div>
              <button
                onClick={() => setSelectedGroup(null)}
                className="p-1 rounded-lg bg-slate-200 text-slate-600 hover:text-slate-900 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 text-xs font-mono">
              <div>
                <h4 className="text-slate-700 uppercase text-[11px] font-semibold mb-2">Profile Overview</h4>
                <p className="text-slate-700 bg-slate-50 p-3 rounded-lg border border-slate-200 leading-relaxed font-sans text-xs">
                  {selectedGroup.group.description}
                </p>
              </div>

              <div>
                <h4 className="text-slate-700 uppercase text-[11px] font-semibold mb-2">Associated Malware Tools</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedGroup.group.associated_malware.map((m: string) => (
                    <span key={m} className="px-2.5 py-1 rounded bg-amber-50 text-amber-800 border border-amber-200 font-semibold">
                      {m}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-slate-700 uppercase text-[11px] font-semibold mb-2">Targeted Vulnerabilities</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedGroup.group.associated_cves.map((c: string) => (
                    <span key={c} className="px-2.5 py-1 rounded bg-orange-50 text-orange-700 border border-orange-200 font-semibold">
                      {c}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-slate-700 uppercase text-[11px] font-semibold mb-2 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-orange-600" />
                  Correlated Infrastructure IOCs ({selectedGroup.associated_infrastructure.length})
                </h4>
                {selectedGroup.associated_infrastructure.length === 0 ? (
                  <div className="text-slate-400 italic">No specific C2 infrastructure attributed yet.</div>
                ) : (
                  <div className="space-y-2">
                    {selectedGroup.associated_infrastructure.map((ioc: any) => (
                      <div key={ioc.fingerprint} className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-center justify-between text-slate-900">
                        <span className="font-medium">{ioc.ioc_value}</span>
                        <span className="text-slate-500 text-[10px]">({ioc.sources.join(', ')})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
