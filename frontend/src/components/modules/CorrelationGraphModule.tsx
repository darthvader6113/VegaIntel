import React, { useState, useEffect } from 'react';
import { Share2, RefreshCw, Info, Database, ShieldAlert, Users, Binary, ArrowRight } from 'lucide-react';
import { api } from '../../services/api';

export const CorrelationGraphModule: React.FC = () => {
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [loading, setLoading] = useState(true);

  const fetchGraph = async () => {
    try {
      setLoading(true);
      const res = await api.getCorrelationGraph();
      setGraphData(res);
      if (res.nodes.length > 0 && !selectedNode) {
        setSelectedNode(res.nodes[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  const filteredNodes = graphData.nodes.filter((n) => {
    if (filterType === 'all') return true;
    return n.type === filterType;
  });

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'cve':
        return 'border-rose-200 bg-rose-50/60 text-rose-800 hover:border-rose-300';
      case 'ioc':
        return 'border-orange-200 bg-orange-50/60 text-orange-800 hover:border-orange-300';
      case 'apt_group':
        return 'border-purple-200 bg-purple-50/60 text-purple-800 hover:border-purple-300';
      case 'malware':
        return 'border-amber-200 bg-amber-50/60 text-amber-800 hover:border-amber-300';
      default:
        return 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300';
    }
  };

  const getEntityIcon = (type: string) => {
    switch (type) {
      case 'cve':
        return <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />;
      case 'ioc':
        return <Database className="w-3.5 h-3.5 text-orange-600" />;
      case 'apt_group':
        return <Users className="w-3.5 h-3.5 text-purple-600" />;
      case 'malware':
        return <Binary className="w-3.5 h-3.5 text-amber-600" />;
      default:
        return <Share2 className="w-3.5 h-3.5 text-slate-500" />;
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Controls Header */}
      <div className="p-4 rounded-xl border border-slate-200/90 bg-white shadow-xs flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-orange-100 border border-orange-200 flex items-center justify-center text-orange-700">
            <Share2 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-slate-900 font-mono text-sm">
              Threat Correlation Topology Visualizer
            </h3>
            <span className="text-xs font-mono text-slate-400">
              {graphData.nodes.length} Threat Entities · {graphData.edges.length} Cross-Entity Relationships
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 shadow-xs"
          >
            <option value="all">All Entity Types</option>
            <option value="cve">Vulnerabilities (CVE)</option>
            <option value="ioc">Canonical IOCs</option>
            <option value="apt_group">Threat Actors (APT)</option>
            <option value="malware">Malware Strains</option>
          </select>

          <button
            type="button"
            onClick={fetchGraph}
            className="p-2 rounded-lg bg-white hover:bg-slate-50 text-slate-600 border border-slate-200 shadow-xs transition-colors"
            title="Refresh graph"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Graph Grid / Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Nodes Canvas Panel */}
        <div className="lg:col-span-2 p-6 rounded-xl border border-slate-200/90 bg-white shadow-xs min-h-[520px] flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider font-bold">
                Cataloged Threat Nodes
              </span>
              <div className="flex items-center gap-3 text-[11px] font-mono font-bold">
                <span className="flex items-center gap-1.5 text-rose-600">
                  <span className="w-2 h-2 rounded-full bg-rose-500" /> CVE
                </span>
                <span className="flex items-center gap-1.5 text-orange-600">
                  <span className="w-2 h-2 rounded-full bg-orange-500" /> IOC
                </span>
                <span className="flex items-center gap-1.5 text-purple-600">
                  <span className="w-2 h-2 rounded-full bg-purple-500" /> APT
                </span>
                <span className="flex items-center gap-1.5 text-amber-600">
                  <span className="w-2 h-2 rounded-full bg-amber-500" /> Malware
                </span>
              </div>
            </div>

            {loading ? (
              <div className="py-24 text-center font-mono text-xs text-slate-400 flex flex-col items-center justify-center gap-2">
                <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
                <span>Constructing threat graph topology...</span>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[440px] overflow-y-auto pr-1">
                {filteredNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id;
                  return (
                    <div
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition-all font-mono text-xs ${getNodeColor(
                        n.type
                      )} ${
                        isSelected
                          ? 'ring-2 ring-orange-500 shadow-sm border-transparent'
                          : 'shadow-2xs'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="flex items-center gap-1 uppercase text-[10px] font-bold tracking-wider">
                          {getEntityIcon(n.type)}
                          {n.type}
                        </span>
                        {n.data.cvss_score && (
                          <span className="text-[10px] font-bold text-rose-700">
                            CVSS {n.data.cvss_score}
                          </span>
                        )}
                        {n.data.sighting_count && (
                          <span className="text-[10px] font-bold text-orange-700">
                            {n.data.sighting_count}x sightings
                          </span>
                        )}
                      </div>
                      <div className="font-bold truncate text-xs text-slate-900">
                        {n.label}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="text-[11px] font-mono text-slate-400 pt-3 border-t border-slate-100 flex items-center justify-between">
            <span>Click any node to inspect correlated intelligence.</span>
            <span>Triadic Correlation Engine</span>
          </div>
        </div>

        {/* Selected Node Details Inspector */}
        <div className="p-6 rounded-xl border border-slate-200/90 bg-white shadow-xs flex flex-col justify-between font-mono text-xs space-y-4">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <span className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-2">
                <Info className="w-4 h-4 text-orange-600" />
                Entity Inspector
              </span>
              {selectedNode && (
                <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                  {selectedNode.type}
                </span>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-3.5">
                <div className="p-3.5 rounded-xl bg-slate-50/80 border border-slate-200 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Canonical ID / Value</span>
                  <div className="text-slate-900 font-extrabold text-sm break-all select-all">
                    {selectedNode.label}
                  </div>
                </div>

                {selectedNode.data.description && (
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Description</span>
                    <p className="text-slate-600 leading-relaxed bg-slate-50/60 p-3 rounded-lg border border-slate-200/80 font-sans text-xs">
                      {selectedNode.data.description}
                    </p>
                  </div>
                )}

                {selectedNode.data.cvss_score && (
                  <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 flex items-center justify-between">
                    <span className="text-rose-700 font-bold">CVSS Base Score:</span>
                    <span className="text-rose-900 font-extrabold text-sm">{selectedNode.data.cvss_score} / 10.0</span>
                  </div>
                )}

                {selectedNode.data.sighting_count && (
                  <div className="p-3 rounded-xl bg-orange-50 border border-orange-200 flex items-center justify-between">
                    <span className="text-orange-700 font-bold">Consolidated Sightings:</span>
                    <span className="text-orange-900 font-extrabold text-sm">{selectedNode.data.sighting_count} Observations</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-24 text-center text-slate-400 italic">
                Select an entity from the graph to inspect correlated telemetry.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-100 text-[10px] text-slate-400">
            Decoupled Graph Architecture • STIX 2.1 Mapped
          </div>
        </div>
      </div>
    </div>
  );
};
