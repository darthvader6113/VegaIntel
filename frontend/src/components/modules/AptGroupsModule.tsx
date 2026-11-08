import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Users, Globe, Target, Terminal, X, Database, ShieldAlert, Binary, Search, Copy, Check, ArrowRight } from 'lucide-react';
import { Portal } from '../common/Portal';
import { APTGroup } from '../../types';
import { api } from '../../services/api';

export const AptGroupsModule: React.FC = () => {
  const [groups, setGroups] = useState<APTGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<any | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
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

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="w-full space-y-6">
      {/* Search Header */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search APT groups by name or alias (e.g. Lazarus, Cozy Bear, Volt Typhoon, APT29)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
          />
        </div>
        <span className="text-xs font-mono text-slate-500 font-medium">
          MITRE ATT&amp;CK Threat Actors ({groups.length})
        </span>
      </div>

      {/* Grid of APT Groups */}
      {loading ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 flex flex-col items-center justify-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading nation-state threat actors...</span>
        </div>
      ) : groups.length === 0 ? (
        <div className="p-16 text-center text-xs font-mono text-slate-400 bg-white rounded-xl border border-slate-200">
          No threat actor groups match the search criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {groups.map((apt) => (
            <div
              key={apt.group_id}
              onClick={() => openGroup(apt.group_id)}
              className="p-5 rounded-xl border border-slate-200/90 bg-white hover:border-purple-300 hover:shadow-md cursor-pointer transition-all space-y-3.5 flex flex-col justify-between group"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-base font-bold text-slate-900 font-mono group-hover:text-purple-700 transition-colors">
                        {apt.name}
                      </h3>
                      {apt.origin_country && (
                        <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-[10px] font-mono border border-slate-200 flex items-center gap-1 font-semibold">
                          <Globe className="w-3 h-3 text-purple-600" />
                          {apt.origin_country}
                        </span>
                      )}
                    </div>
                    {apt.aliases && apt.aliases.length > 0 && (
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                        Aliases: {apt.aliases.join(', ')}
                      </div>
                    )}
                  </div>
                  <span className="text-slate-400 group-hover:text-purple-600 group-hover:translate-x-0.5 transition-all">
                    <ArrowRight className="w-4 h-4" />
                  </span>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed line-clamp-3">
                  {apt.description}
                </p>
              </div>

              <div className="space-y-2 pt-2 border-t border-slate-100 text-[11px] font-mono">
                {/* Target Sectors */}
                {apt.target_sectors && apt.target_sectors.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <Target className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span className="text-slate-500">Targets:</span>
                    <span className="text-slate-700 font-semibold truncate max-w-[220px]">
                      {apt.target_sectors.slice(0, 3).join(', ')}
                      {apt.target_sectors.length > 3 ? ` +${apt.target_sectors.length - 3}` : ''}
                    </span>
                  </div>
                )}

                {/* Associated Tools & Exploits */}
                <div className="flex items-center justify-between text-slate-500 pt-1 border-t border-slate-50">
                  <span className="flex items-center gap-1 text-purple-700 font-medium">
                    <Binary className="w-3.5 h-3.5" />
                    {apt.associated_malware.length} Malware
                  </span>
                  <span className="flex items-center gap-1 text-orange-600 font-medium">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    {apt.associated_cves.length} CVEs
                  </span>
                  <span className="flex items-center gap-1 text-slate-600">
                    <Database className="w-3.5 h-3.5" />
                    {apt.infrastructure_count} C2 IOCs
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Enterprise Dossier Modal Mounted via Portal */}
      <Portal>
        <AnimatePresence>
          {selectedGroup && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
            >
              <motion.div
                initial={{ opacity: 0, scale: 0.96, y: 8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96, y: 8 }}
                transition={{ duration: 0.18, ease: 'easeOut' }}
                className="w-full max-w-3xl max-h-[85vh] rounded-2xl border border-slate-200 bg-white overflow-hidden flex flex-col shadow-2xl"
              >
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-200 flex items-start justify-between bg-slate-50/80 shrink-0">
              <div className="space-y-1 min-w-0 pr-4">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <div className="w-8 h-8 rounded-lg bg-purple-100 border border-purple-200 flex items-center justify-center text-purple-700">
                    <Users className="w-4 h-4" />
                  </div>
                  <h3 className="text-xl font-bold font-mono text-slate-900 tracking-tight">
                    {selectedGroup.group.name}
                  </h3>
                  {selectedGroup.group.origin_country && (
                    <span className="px-2.5 py-0.5 rounded-full bg-purple-50 text-purple-800 text-xs font-mono font-bold border border-purple-200">
                      Origin: {selectedGroup.group.origin_country}
                    </span>
                  )}
                </div>
                {selectedGroup.group.aliases && selectedGroup.group.aliases.length > 0 && (
                  <div className="text-xs text-slate-500 font-mono">
                    Tracked Aliases: <span className="text-slate-800 font-medium">{selectedGroup.group.aliases.join(', ')}</span>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => setSelectedGroup(null)}
                className="p-1.5 rounded-lg bg-slate-200/80 text-slate-600 hover:text-slate-900 transition-colors shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs font-mono flex-1">
              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-2">
                  Threat Actor Intelligence Profile
                </h4>
                <p className="text-slate-700 bg-slate-50 p-4 rounded-xl border border-slate-200 leading-relaxed font-sans text-xs">
                  {selectedGroup.group.description}
                </p>
              </div>

              {/* Target Sectors */}
              {selectedGroup.group.target_sectors && selectedGroup.group.target_sectors.length > 0 && (
                <div>
                  <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-purple-600" />
                    Targeted Industry Sectors
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedGroup.group.target_sectors.map((sector: string) => (
                      <span key={sector} className="px-2.5 py-1 rounded-lg bg-slate-100 text-slate-800 border border-slate-200 text-xs font-medium">
                        {sector}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Associated Malware Tools */}
              {selectedGroup.group.associated_malware && selectedGroup.group.associated_malware.length > 0 && (
                <div>
                  <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                    <Binary className="w-3.5 h-3.5 text-rose-600" />
                    Weaponized Toolkits &amp; Malware
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedGroup.group.associated_malware.map((m: string) => (
                      <span key={m} className="px-2.5 py-1 rounded-lg bg-rose-50 text-rose-800 border border-rose-200 font-bold">
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Targeted Vulnerabilities */}
              {selectedGroup.group.associated_cves && selectedGroup.group.associated_cves.length > 0 && (
                <div>
                  <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-orange-600" />
                    Targeted Exploits &amp; CVEs
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedGroup.group.associated_cves.map((c: string) => (
                      <span key={c} className="px-2.5 py-1 rounded-lg bg-orange-50 text-orange-800 border border-orange-200 font-bold">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Correlated Infrastructure IOCs */}
              <div>
                <h4 className="font-semibold text-slate-900 uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-orange-600" />
                  Correlated C2 Infrastructure IOCs ({selectedGroup.associated_infrastructure.length})
                </h4>
                {selectedGroup.associated_infrastructure.length === 0 ? (
                  <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-slate-400 italic text-center">
                    No active network infrastructure attributed in current observation window.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {selectedGroup.associated_infrastructure.map((ioc: any) => (
                      <div key={ioc.fingerprint} className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between text-slate-900">
                        <div className="flex items-center gap-2 truncate mr-2">
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-orange-100 text-orange-800 border border-orange-200">
                            {ioc.ioc_type.toUpperCase()}
                          </span>
                          <span className="font-semibold select-all truncate">{ioc.ioc_value}</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(ioc.ioc_value, ioc.fingerprint)}
                          className="p-1 text-slate-400 hover:text-slate-800 shrink-0"
                          title="Copy IOC"
                        >
                          {copiedKey === ioc.fingerprint ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  </Portal>
</div>
);
};
