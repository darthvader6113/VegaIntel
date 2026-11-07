import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Tabs } from '@ark-ui/react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Database,
  ShieldAlert,
  Users,
  Binary,
  Plus,
  RefreshCw,
  Activity
} from 'lucide-react';
import { api } from '../../services/api';

// Custom Node for Canonical IOC
const IocNodeComponent = ({ data }: { data: any }) => (
  <div className="px-4 py-3 rounded-xl bg-white border-2 border-orange-500 shadow-md min-w-[200px] text-xs font-mono">
    <Handle type="target" position={Position.Top} className="!bg-orange-500" />
    <div className="flex items-center justify-between text-[10px] text-orange-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <Database className="w-3 h-3 text-orange-600" />
        {data.type || 'IOC'}
      </span>
      <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-800 border border-orange-200 font-semibold">
        {data.sightingCount || 1}x sightings
      </span>
    </div>
    <div className="font-bold text-slate-900 text-[11px] truncate" title={data.value}>
      {data.value}
    </div>
    <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-slate-100 text-[10px] text-slate-500">
      <span>Confidence:</span>
      <span className="text-emerald-700 font-bold">{data.confidence || 85}%</span>
    </div>
    <Handle type="source" position={Position.Bottom} className="!bg-orange-500" />
  </div>
);

// Custom Node for Vulnerability (CVE)
const CveNodeComponent = ({ data }: { data: any }) => (
  <div className="px-4 py-3 rounded-xl bg-white border-2 border-red-500 shadow-md min-w-[190px] text-xs font-mono">
    <Handle type="target" position={Position.Top} className="!bg-red-500" />
    <div className="flex items-center justify-between text-[10px] text-red-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <ShieldAlert className="w-3 h-3 text-red-600" />
        VULNERABILITY
      </span>
      <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-bold">
        {data.severity || 'CRITICAL'}
      </span>
    </div>
    <div className="font-bold text-slate-900 text-[12px]">{data.label}</div>
    <div className="text-[10px] text-slate-500 mt-1 truncate">
      CVSS Score: <strong className="text-red-600">{data.score || 9.8}</strong>
    </div>
    <Handle type="source" position={Position.Bottom} className="!bg-red-500" />
  </div>
);

// Custom Node for Threat Actor / APT
const AptNodeComponent = ({ data }: { data: any }) => (
  <div className="px-4 py-3 rounded-xl bg-white border-2 border-purple-500 shadow-md min-w-[180px] text-xs font-mono">
    <Handle type="target" position={Position.Top} className="!bg-purple-500" />
    <div className="flex items-center justify-between text-[10px] text-purple-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <Users className="w-3 h-3 text-purple-600" />
        THREAT ACTOR
      </span>
      <span className="font-semibold text-slate-600">{data.country || 'APT'}</span>
    </div>
    <div className="font-bold text-slate-900 text-[12px]">{data.label}</div>
    <div className="text-[10px] text-slate-500 mt-1 truncate">
      {data.techniques ? `${data.techniques.length} Techniques` : 'MITRE ATT&CK'}
    </div>
    <Handle type="source" position={Position.Bottom} className="!bg-purple-500" />
  </div>
);

// Custom Node for Malware Payload
const MalwareNodeComponent = ({ data }: { data: any }) => (
  <div className="px-4 py-3 rounded-xl bg-white border-2 border-amber-500 shadow-md min-w-[180px] text-xs font-mono">
    <Handle type="target" position={Position.Top} className="!bg-amber-500" />
    <div className="flex items-center justify-between text-[10px] text-amber-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <Binary className="w-3 h-3 text-amber-600" />
        PAYLOAD
      </span>
      <span className="font-semibold text-slate-600">{data.malwareType || 'C2'}</span>
    </div>
    <div className="font-bold text-slate-900 text-[12px]">{data.label}</div>
    <Handle type="source" position={Position.Bottom} className="!bg-amber-500" />
  </div>
);

interface ReactFlowDetectionsModuleProps {
  onRequestIocOpen: () => void;
}

export const ReactFlowDetectionsModule: React.FC<ReactFlowDetectionsModuleProps> = ({ onRequestIocOpen }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [timeRange, setTimeRange] = useState<'today' | '24h' | 'all'>('today');
  const [loading, setLoading] = useState(true);

  const nodeTypes = useMemo(
    () => ({
      iocNode: IocNodeComponent,
      cveNode: CveNodeComponent,
      aptNode: AptNodeComponent,
      malwareNode: MalwareNodeComponent,
    }),
    []
  );

  const loadDetectionsGraph = async () => {
    try {
      setLoading(true);
      const [iocRes, graphRes] = await Promise.all([
        api.getIOCs({ time_range: timeRange, limit: 30 }),
        api.getCorrelationGraph(),
      ]);

      const flowNodes: Node[] = [];
      const flowEdges: Edge[] = [];

      // Layout coordinates calculation
      let iocX = 50;
      let iocY = 180;
      let cveX = 420;
      let cveY = 80;
      let aptX = 800;
      let aptY = 60;
      let malX = 800;
      let malY = 320;

      const registeredNodeIds = new Set<string>();

      // 1. Add Canonical IOC Nodes from filtered detections
      iocRes.items.forEach((ioc, i) => {
        const id = `node_ioc_${ioc.fingerprint}`;
        flowNodes.push({
          id,
          type: 'iocNode',
          position: { x: iocX, y: iocY + i * 110 },
          data: {
            label: ioc.ioc_value,
            value: ioc.ioc_value,
            type: ioc.ioc_type,
            sightingCount: ioc.sighting_count,
            sources: ioc.sources,
            confidence: ioc.overall_confidence,
            tags: ioc.tags,
            firstSeen: ioc.first_seen,
            lastSeen: ioc.last_seen,
          },
        });
        registeredNodeIds.add(ioc.fingerprint);
      });

      // 2. Correlate with CVEs, APTs, and Malware from Graph
      const relatedCveIds = new Set<string>();
      const relatedMalwareIds = new Set<string>();

      const allMalwareNodeIds = new Set(graphRes.nodes.filter((n: any) => n.type === 'malware').map((n: any) => n.id));

      graphRes.edges.forEach((edge: any) => {
        const isFromIoc = registeredNodeIds.has(edge.source);
        const isToIoc = registeredNodeIds.has(edge.target);

        if (isFromIoc || isToIoc) {
          const counterpart = isFromIoc ? edge.target : edge.source;
          const iocId = isFromIoc ? edge.source : edge.target;

          // If counterpart is a CVE
          if (counterpart.startsWith('CVE-')) {
            relatedCveIds.add(counterpart);
            flowEdges.push({
              id: `edge_${iocId}_${counterpart}`,
              source: `node_ioc_${iocId}`,
              target: `node_cve_${counterpart}`,
              animated: true,
              style: { stroke: '#ea580c', strokeWidth: 2 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#ea580c' },
            });
          }
          // If counterpart is Malware
          else if (allMalwareNodeIds.has(counterpart)) {
            relatedMalwareIds.add(counterpart);
            flowEdges.push({
              id: `edge_${iocId}_${counterpart}`,
              source: `node_ioc_${iocId}`,
              target: `node_mal_${counterpart}`,
              animated: true,
              style: { stroke: '#d97706', strokeWidth: 2 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#d97706' },
            });
          }
        }
      });

      // Place CVE Nodes
      Array.from(relatedCveIds).forEach((cveId, i) => {
        const cveData = graphRes.nodes.find((n: any) => n.id === cveId)?.data || {};
        flowNodes.push({
          id: `node_cve_${cveId}`,
          type: 'cveNode',
          position: { x: cveX, y: cveY + i * 140 },
          data: {
            label: cveId,
            score: cveData.cvss_score || 9.8,
            severity: cveData.severity || 'CRITICAL',
            desc: cveData.description,
          },
        });
      });

      // Place Malware Nodes
      Array.from(relatedMalwareIds).forEach((malName, i) => {
        const malObj = graphRes.nodes.find((n: any) => n.id === malName)?.data || {};
        flowNodes.push({
          id: `node_mal_${malName}`,
          type: 'malwareNode',
          position: { x: malX, y: malY + i * 130 },
          data: {
            label: malName,
            malwareType: malObj.malware_type || 'Malware',
          },
        });
      });

      // Place Real APT Actors from Live Graph
      const realAptNodes = graphRes.nodes.filter((n: any) => n.type === 'apt_group');
      realAptNodes.forEach((aptNode: any, i: number) => {
        const aptId = `node_apt_${aptNode.id}`;
        flowNodes.push({
          id: aptId,
          type: 'aptNode',
          position: { x: aptX, y: aptY + i * 130 },
          data: {
            label: aptNode.data.name || aptNode.id,
            country: aptNode.data.origin_country || 'Adversary',
            techniques: aptNode.data.techniques || [],
          },
        });
      });

      setNodes(flowNodes);
      setEdges(flowEdges);
      if (flowNodes.length > 0) {
        setSelectedNode(flowNodes[0].data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetectionsGraph();
  }, [timeRange]);

  const onNodeClick = useCallback((event: any, node: Node) => {
    setSelectedNode(node.data);
  }, []);

  return (
    <div className="space-y-4 h-[calc(100vh-140px)] flex flex-col">
      {/* Top Filter and Actions Toolbar */}
      <div className="cyber-card p-4 rounded-xl border border-slate-200 bg-white shadow-sm flex items-center justify-between flex-wrap gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-orange-600 animate-pulse" />
          <div>
            <h3 className="font-bold text-slate-900 font-mono text-sm flex items-center gap-2">
              React Flow: Live Threat Detection Graph
              <span className="text-[10px] px-2 py-0.5 rounded bg-orange-50 text-orange-700 font-semibold border border-orange-200">
                ACTIVE PIPELINE
              </span>
            </h3>
            <p className="text-xs text-slate-500 font-mono">
              Dynamic multi-feed visual correlation: IOCs &rarr; CVEs &rarr; Adversaries &rarr; Malware
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          {/* Ark UI Time Filter ("From the day get new ioc") */}
          <Tabs.Root
            value={timeRange}
            onValueChange={(details) => setTimeRange(details.value as 'today' | '24h' | 'all')}
          >
            <Tabs.List className="flex rounded-lg bg-slate-100 border border-slate-200 p-0.5">
              <Tabs.Trigger
                value="today"
                className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold ${
                  timeRange === 'today'
                    ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Today&apos;s Detections
              </Tabs.Trigger>
              <Tabs.Trigger
                value="24h"
                className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold ${
                  timeRange === '24h'
                    ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Last 24 Hours
              </Tabs.Trigger>
              <Tabs.Trigger
                value="all"
                className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold ${
                  timeRange === 'all'
                    ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All Detections
              </Tabs.Trigger>
            </Tabs.List>
          </Tabs.Root>

          {/* Fetch IOCs by CVE Trigger Button */}
          <button
            onClick={onRequestIocOpen}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-bold shadow-xs transition-all active:scale-95"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Fetch by CVE</span>
          </button>

          <button
            onClick={loadDetectionsGraph}
            className="p-2 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 transition-colors shadow-sm"
            title="Refresh graph"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Flow Canvas and Node Details */}
      <div className="flex-1 flex gap-4 min-h-0">
        {/* React Flow Visual Canvas */}
        <div className="flex-1 rounded-xl border border-slate-200 relative overflow-hidden bg-slate-50 shadow-sm">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={2.0}
            className="bg-transparent"
          >
            <Background color="#cbd5e1" gap={20} size={1} />
            <Controls className="!bg-white !border-slate-200 !text-slate-800 !fill-slate-800 shadow-sm" />
            <MiniMap
              nodeColor={(n) => {
                if (n.type === 'iocNode') return '#ea580c';
                if (n.type === 'cveNode') return '#dc2626';
                if (n.type === 'aptNode') return '#9333ea';
                return '#d97706';
              }}
              className="!bg-white !border !border-slate-200 shadow-sm"
            />
          </ReactFlow>
        </div>

        {/* Selected Node Details Inspector */}
        <div className="w-80 p-5 rounded-xl border border-slate-200 bg-white shadow-sm flex flex-col justify-between shrink-0 font-mono text-xs overflow-y-auto">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 mb-3">
              <span className="font-bold text-slate-900 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-orange-600" />
                Detection Inspector
              </span>
              <span className="text-[10px] text-slate-500">Click node to inspect</span>
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase font-bold">Indicator / Entity</div>
                  <div className="text-slate-900 font-extrabold text-sm break-all">
                    {selectedNode.value || selectedNode.label}
                  </div>
                  {selectedNode.type && (
                    <div className="text-[10px] text-orange-700 uppercase font-semibold">
                      Type: {selectedNode.type}
                    </div>
                  )}
                </div>

                {selectedNode.sources && (
                  <div>
                    <div className="text-slate-500 text-[10px] uppercase font-bold mb-1.5">Reporting Feeds</div>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.sources.map((s: string) => (
                        <span key={s} className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-[10px]">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedNode.confidence !== undefined && (
                  <div className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <span className="text-slate-600">Composite Confidence:</span>
                    <span className="text-emerald-700 font-bold text-sm">{selectedNode.confidence}%</span>
                  </div>
                )}

                {selectedNode.tags && selectedNode.tags.length > 0 && (
                  <div>
                    <div className="text-slate-500 text-[10px] uppercase font-bold mb-1.5">Threat Tags</div>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.tags.map((t: string) => (
                        <span key={t} className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] border border-slate-200">
                          #{t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedNode.desc && (
                  <div>
                    <div className="text-slate-500 text-[10px] uppercase font-bold mb-1">Vulnerability Context</div>
                    <p className="text-slate-700 text-[11px] bg-slate-50 p-2.5 rounded border border-slate-200 leading-relaxed font-sans">
                      {selectedNode.desc}
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-slate-400 italic py-12 text-center text-xs">
                Select any node on the canvas to inspect real-time detection telemetry.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-200 text-[10px] text-slate-500">
            Powered by React Flow &amp; VegaIntel Deduplication Engine.
          </div>
        </div>
      </div>
    </div>
  );
};
