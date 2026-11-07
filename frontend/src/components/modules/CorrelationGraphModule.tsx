import React, { useState, useEffect } from 'react';
import { Share2, RefreshCw, Info } from 'lucide-react';
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
        return 'border-red-200 bg-red-50 text-red-700 hover:border-red-300';
      case 'ioc':
        return 'border-orange-200 bg-orange-50 text-orange-800 hover:border-orange-300';
      case 'apt_group':
        return 'border-purple-200 bg-purple-50 text-purple-700 hover:border-purple-300';
      case 'malware':
        return 'border-amber-200 bg-amber-50 text-amber-800 hover:border-amber-300';
      case 'poc':
        return 'border-blue-200 bg-blue-50 text-blue-700 hover:border-blue-300';
      default:
        return 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="cyber-card p-4 rounded-xl border border-slate-200 bg-white shadow-sm flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Share2 className="w-5 h-5 text-orange-600" />
          <h3 className="font-bold text-slate-900 font-mono text-sm">
            Decoupled Graph Correlation Visualizer
          </h3>
          <span className="text-xs font-mono text-slate-500">
            ({graphData.nodes.length} Nodes · {graphData.edges.length} Relationships)
          </span>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
          >
            <option value="all">Show All Entity Types</option>
            <option value="cve">Vulnerabilities (CVE)</option>
            <option value="ioc">Canonical IOCs</option>
            <option value="apt_group">APT Groups</option>
            <option value="malware">Malware</option>
          </select>

          <button
            onClick={fetchGraph}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 transition-colors border border-slate-200 shadow-sm"
            title="Refresh graph"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Graph Grid / Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Nodes Canvas Panel */}
        <div className="lg:col-span-2 cyber-card p-6 rounded-xl border border-slate-200 bg-white shadow-sm min-h-[500px] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-200">
              <span className="text-xs font-mono text-slate-500 uppercase tracking-wider font-semibold">
                Graph Entities
              </span>
              <div className="flex items-center gap-3 text-[11px] font-mono font-medium">
                <span className="flex items-center gap-1 text-red-600">
                  <span className="w-2 h-2 rounded-full bg-red-500" /> CVE
                </span>
                <span className="flex items-center gap-1 text-orange-600">
                  <span className="w-2 h-2 rounded-full bg-orange-500" /> IOC
                </span>
                <span className="flex items-center gap-1 text-purple-600">
                  <span className="w-2 h-2 rounded-full bg-purple-500" /> APT
                </span>
                <span className="flex items-center gap-1 text-amber-600">
                  <span className="w-2 h-2 rounded-full bg-amber-500" /> Malware
                </span>
              </div>
            </div>

            {loading ? (
              <div className="py-20 text-center font-mono text-xs text-slate-400">
                Constructing graph relationships...
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[420px] overflow-y-auto pr-2">
                {filteredNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id;
                  return (
                    <div
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      className={`p-3 rounded-lg border cursor-pointer transition-all font-mono text-xs shadow-sm ${getNodeColor(
                        n.type
                      )} ${
                        isSelected
                          ? 'ring-2 ring-orange-500 shadow-md scale-[1.02]'
                          : 'hover:shadow'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="uppercase text-[9px] font-extrabold tracking-wider">
                          {n.type}
                        </span>
                        {n.data.cvss_score && (
                          <span className="text-[10px] font-bold text-red-600">
                            CVSS {n.data.cvss_score}
                          </span>
                        )}
                        {n.data.sighting_count && (
                          <span className="text-[10px] font-bold text-orange-600">
                            {n.data.sighting_count}x sightings
                          </span>
                        )}
                      </div>
                      <div className="font-bold truncate text-[12px] text-slate-900">
                        {n.label}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-200 text-[11px] font-mono text-slate-500 flex items-center justify-between">
            <span>Click any node to inspect incident telemetry</span>
            <span>Relationships dynamically decoupled</span>
          </div>
        </div>

        {/* Selected Node Details & Connected Edges */}
        <div className="cyber-card p-6 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between">
          <div>
            <h4 className="text-sm font-semibold text-slate-900 font-mono mb-4 flex items-center gap-2">
              <Info className="w-4 h-4 text-orange-600" />
              Node Threat Inspector
            </h4>

            {selectedNode ? (
              <div className="space-y-4 font-mono text-xs">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Entity ID</div>
                  <div className="text-slate-900 font-bold break-all mt-0.5">{selectedNode.id}</div>
                  <div className="text-[10px] text-orange-700 uppercase mt-2 font-semibold">Type: {selectedNode.type}</div>
                </div>

                {/* Connected Edges */}
                <div>
                  <div className="text-slate-700 uppercase text-[11px] font-semibold mb-2">
                    Active Correlations ({
                      graphData.edges.filter(
                        (e) => e.source === selectedNode.id || e.target === selectedNode.id
                      ).length
                    })
                  </div>
                  <div className="space-y-2 max-h-[220px] overflow-y-auto">
                    {graphData.edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((edge) => {
                        const isOutgoing = edge.source === selectedNode.id;
                        const counterpart = isOutgoing ? edge.target : edge.source;
                        return (
                          <div
                            key={edge.id}
                            className="p-2.5 rounded bg-slate-50 border border-slate-200 text-[11px]"
                          >
                            <div className="flex items-center justify-between text-slate-500 mb-1">
                              <span className="text-orange-700 font-bold uppercase text-[10px]">
                                {edge.label.replace('_', ' ')}
                              </span>
                              <span className="text-[10px] text-emerald-700 font-bold">
                                {edge.confidence}% conf
                              </span>
                            </div>
                            <div className="text-slate-900 font-semibold truncate">
                              {counterpart}
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-slate-400 font-mono text-xs italic py-10 text-center">
                Select a node to inspect relationships.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
