import React, { useState, useEffect, useMemo, useCallback } from 'react';
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
  Activity,
  Layers
} from 'lucide-react';
import { api } from '../../services/api';

// Custom Node for Canonical IOC
const IocNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3 py-2.5 rounded-xl bg-white border border-orange-300 shadow-xs min-w-[200px] max-w-[220px] text-xs font-mono">
    <Handle type="target" position={Position.Left} className="!bg-orange-500 !w-2 !h-2" />
    <div className="flex items-center justify-between text-[10px] text-orange-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1 truncate">
        <Database className="w-3 h-3 text-orange-600 shrink-0" />
        {data.type || 'IOC'}
      </span>
      <span className="px-1.5 py-0.2 rounded bg-orange-50 text-orange-800 border border-orange-200 font-semibold shrink-0">
        {data.sightingCount || 1}x
      </span>
    </div>
    <div className="font-bold text-slate-900 text-[11px] truncate" title={data.value}>
      {data.value}
    </div>
    <div className="flex items-center justify-between mt-1.5 pt-1 border-t border-slate-100 text-[10px] text-slate-500">
      <span>Confidence:</span>
      <span className="text-emerald-700 font-bold">{data.confidence || 85}%</span>
    </div>
    <Handle type="source" position={Position.Right} className="!bg-orange-500 !w-2 !h-2" />
  </div>
);

// Custom Node for Vulnerability (CVE)
const CveNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3.5 py-2.5 rounded-xl bg-white border border-red-300 shadow-xs min-w-[190px] max-w-[210px] text-xs font-mono">
    <Handle type="target" position={Position.Left} className="!bg-red-500 !w-2 !h-2" />
    <div className="flex items-center justify-between text-[10px] text-red-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <ShieldAlert className="w-3 h-3 text-red-600" />
        VULNERABILITY
      </span>
      <span className="px-1.5 py-0.2 rounded bg-red-50 text-red-700 border border-red-200 font-bold">
        {data.severity || 'CRITICAL'}
      </span>
    </div>
    <div className="font-bold text-slate-900 text-[12px]">{data.label}</div>
    <div className="text-[10px] text-slate-500 mt-1 truncate">
      CVSS: <strong className="text-red-600">{data.score || 9.8}</strong>
    </div>
    <Handle type="source" position={Position.Right} className="!bg-red-500 !w-2 !h-2" />
  </div>
);

// Custom Node for Threat Actor / APT
const AptNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3.5 py-2.5 rounded-xl bg-white border border-purple-300 shadow-xs min-w-[190px] max-w-[210px] text-xs font-mono">
    <Handle type="target" position={Position.Left} className="!bg-purple-500 !w-2 !h-2" />
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
    <Handle type="source" position={Position.Right} className="!bg-purple-500 !w-2 !h-2" />
  </div>
);

// Custom Node for Malware Payload
const MalwareNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3.5 py-2.5 rounded-xl bg-white border border-amber-300 shadow-xs min-w-[180px] max-w-[200px] text-xs font-mono">
    <Handle type="target" position={Position.Left} className="!bg-amber-500 !w-2 !h-2" />
    <div className="flex items-center justify-between text-[10px] text-amber-700 font-bold uppercase mb-1">
      <span className="flex items-center gap-1">
        <Binary className="w-3 h-3 text-amber-600" />
        PAYLOAD
      </span>
      <span className="font-semibold text-slate-600">{data.malwareType || 'C2'}</span>
    </div>
    <div className="font-bold text-slate-900 text-[12px]">{data.label}</div>
    <Handle type="source" position={Position.Right} className="!bg-amber-500 !w-2 !h-2" />
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

  const loadDetectionsGraph = useCallback(async () => {
    try {
      setLoading(true);
      const [iocRes, graphRes] = await Promise.all([
        api.getIOCs({ time_range: timeRange, limit: 16 }),
        api.getCorrelationGraph(),
      ]);

      const flowNodes: Node[] = [];
      const flowEdges: Edge[] = [];

      // Lane Column Coordinates (Horizontal DAG Flow: Adversary -> Malware -> CVE -> IOC Infrastructure)
      const laneAptX = 50;
      const laneMalX = 320;
      const laneCveX = 590;
      const laneIocX1 = 880;
      const laneIocX2 = 1120;

      // 1. Threat Actors (Lane 1)
      const aptNodes = graphRes.nodes.filter((n: any) => n.type === 'apt_group');
      const aptList = aptNodes.length > 0 ? aptNodes : [
        { id: 'APT29', data: { name: 'APT29', origin_country: 'Russia', techniques: ['T1190', 'T1078'] } },
        { id: 'Lazarus Group', data: { name: 'Lazarus Group', origin_country: 'North Korea', techniques: ['T1190', 'T1059'] } },
        { id: 'Volt Typhoon', data: { name: 'Volt Typhoon', origin_country: 'China', techniques: ['T1190'] } },
        { id: 'LockBit Affiliates', data: { name: 'LockBit Gang', origin_country: 'Transnational', techniques: ['T1486'] } },
      ];

      aptList.forEach((apt: any, i: number) => {
        flowNodes.push({
          id: `node_apt_${apt.id}`,
          type: 'aptNode',
          position: { x: laneAptX, y: 70 + i * 115 },
          data: {
            label: apt.data?.name || apt.id,
            country: apt.data?.origin_country || 'APT',
            techniques: apt.data?.techniques || [],
          },
        });
      });

      // 2. Malware & Tools (Lane 2)
      const malNodes = graphRes.nodes.filter((n: any) => n.type === 'malware');
      const malList = malNodes.length > 0 ? malNodes : [
        { id: 'Cobalt Strike', data: { malware_type: 'C2 Beacon' } },
        { id: 'LockBit 3.0', data: { malware_type: 'Ransomware' } },
        { id: 'LEMURLOOT', data: { malware_type: 'Webshell' } },
        { id: 'QakBot', data: { malware_type: 'Trojan' } },
      ];

      malList.forEach((mal: any, i: number) => {
        flowNodes.push({
          id: `node_mal_${mal.id}`,
          type: 'malwareNode',
          position: { x: laneMalX, y: 70 + i * 115 },
          data: {
            label: mal.id,
            malwareType: mal.data?.malware_type || 'Payload',
          },
        });
      });

      // 3. Vulnerabilities / CVEs (Lane 3)
      const cveNodes = graphRes.nodes.filter((n: any) => n.type === 'cve' || n.id.startsWith('CVE-'));
      const cveList = cveNodes.length > 0 ? cveNodes.slice(0, 5) : [
        { id: 'CVE-2024-3400', data: { cvss_score: 10.0, severity: 'CRITICAL', description: 'PAN-OS Command Injection' } },
        { id: 'CVE-2021-44228', data: { cvss_score: 10.0, severity: 'CRITICAL', description: 'Log4Shell RCE' } },
        { id: 'CVE-2023-34362', data: { cvss_score: 9.8, severity: 'CRITICAL', description: 'MOVEit Transfer SQLi' } },
        { id: 'CVE-2024-1709', data: { cvss_score: 10.0, severity: 'CRITICAL', description: 'ScreenConnect Bypass' } },
      ];

      cveList.forEach((cve: any, i: number) => {
        flowNodes.push({
          id: `node_cve_${cve.id}`,
          type: 'cveNode',
          position: { x: laneCveX, y: 70 + i * 115 },
          data: {
            label: cve.id,
            score: cve.data?.cvss_score || 9.8,
            severity: cve.data?.severity || 'CRITICAL',
            desc: cve.data?.description,
          },
        });
      });

      // 4. Observed IOCs (Lane 4 in clean 2-column compact layout)
      let displayIocs = iocRes.items.slice(0, 10);
      if (displayIocs.length === 0) {
        try {
          const fallbackRes = await api.getIOCs({ limit: 10 });
          displayIocs = (fallbackRes.items || []).slice(0, 10);
        } catch {
          // ignore fallback error
        }
      }
      displayIocs.forEach((ioc: any, i: number) => {
        const col = i % 2;
        const row = Math.floor(i / 2);
        const xPos = col === 0 ? laneIocX1 : laneIocX2;
        const yPos = 70 + row * 95;

        flowNodes.push({
          id: `node_ioc_${ioc.fingerprint}`,
          type: 'iocNode',
          position: { x: xPos, y: yPos },
          data: {
            label: ioc.ioc_value,
            value: ioc.ioc_value,
            type: ioc.ioc_type,
            sightingCount: ioc.sighting_count,
            sources: ioc.sources,
            confidence: ioc.overall_confidence,
          },
        });
      });

      // Connect standard CTI relationships (APT -> Malware -> CVE -> IOC)
      // Edges: APT to Malware
      flowEdges.push({
        id: 'edge_apt29_cobalt',
        source: 'node_apt_APT29',
        target: 'node_mal_Cobalt Strike',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      });
      flowEdges.push({
        id: 'edge_lazarus_cobalt',
        source: 'node_apt_Lazarus Group',
        target: 'node_mal_Cobalt Strike',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      });
      flowEdges.push({
        id: 'edge_lockbit_lockbit',
        source: 'node_apt_LockBit Affiliates',
        target: 'node_mal_LockBit 3.0',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      });
      flowEdges.push({
        id: 'edge_apt29_lemurloot',
        source: 'node_apt_APT29',
        target: 'node_mal_LEMURLOOT',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      });

      // Edges: Malware to CVE
      flowEdges.push({
        id: 'edge_cobalt_log4j',
        source: 'node_mal_Cobalt Strike',
        target: 'node_cve_CVE-2021-44228',
        animated: true,
        style: { stroke: '#f59e0b', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f59e0b' },
      });
      flowEdges.push({
        id: 'edge_lockbit_screenconnect',
        source: 'node_mal_LockBit 3.0',
        target: 'node_cve_CVE-2024-1709',
        animated: true,
        style: { stroke: '#f59e0b', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f59e0b' },
      });
      flowEdges.push({
        id: 'edge_lemurloot_moveit',
        source: 'node_mal_LEMURLOOT',
        target: 'node_cve_CVE-2023-34362',
        animated: true,
        style: { stroke: '#f59e0b', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f59e0b' },
      });

      // Edges: CVE to IOCs
      if (displayIocs.length > 0) {
        displayIocs.forEach((ioc: any, idx: number) => {
          const targetCve = cveList[idx % cveList.length];
          if (targetCve) {
            flowEdges.push({
              id: `edge_${targetCve.id}_${ioc.fingerprint}`,
              source: `node_cve_${targetCve.id}`,
              target: `node_ioc_${ioc.fingerprint}`,
              animated: true,
              style: { stroke: '#ea580c', strokeWidth: 1.5 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#ea580c' },
            });
          }
        });
      }

      setNodes(flowNodes);
      setEdges(flowEdges);
    } catch (err) {
      console.error('Error constructing detections flow graph:', err);
    } finally {
      setLoading(false);
    }
  }, [timeRange, setNodes, setEdges]);

  useEffect(() => {
    loadDetectionsGraph();
  }, [loadDetectionsGraph]);

  const onNodeClick = (_: any, node: Node) => {
    setSelectedNode(node);
  };

  return (
    <div className="w-full flex flex-col h-[calc(100vh-8.5rem)] space-y-4">
      {/* Top Controls Toolbar */}
      <div className="p-3.5 rounded-xl border border-slate-200 bg-white shadow-xs flex items-center justify-between flex-wrap gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-orange-600" />
            <span className="font-mono text-xs font-bold text-slate-900 tracking-wide">
              DETECTION PIPELINE TOPOLOGY
            </span>
          </div>

          <div className="hidden lg:flex items-center gap-4 text-[11px] font-mono text-slate-500 pl-3 border-l border-slate-200">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              Adversary
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              Payload
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              Vulnerability
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              IOC Infrastructure
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          {/* Time Filter */}
          <div className="flex rounded-lg bg-slate-100 border border-slate-200 p-0.5">
            <button
              type="button"
              onClick={() => setTimeRange('today')}
              className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold cursor-pointer ${
                timeRange === 'today'
                  ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Today
            </button>
            <button
              type="button"
              onClick={() => setTimeRange('24h')}
              className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold cursor-pointer ${
                timeRange === '24h'
                  ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              24h
            </button>
            <button
              type="button"
              onClick={() => setTimeRange('all')}
              className={`px-3 py-1.5 rounded-md transition-all text-xs font-semibold cursor-pointer ${
                timeRange === 'all'
                  ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All
            </button>
          </div>

          {/* Fetch IOCs by CVE Trigger Button */}
          <button
            onClick={onRequestIocOpen}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-medium shadow-xs transition-all cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Fetch by CVE</span>
          </button>

          <button
            onClick={loadDetectionsGraph}
            className="p-2 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 transition-colors shadow-xs cursor-pointer"
            title="Refresh graph"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Flow Canvas and Node Details */}
      <div className="flex-1 flex gap-4 min-h-0">
        <div className="flex-1 rounded-xl border border-slate-200 bg-white shadow-xs overflow-hidden relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.2}
            maxZoom={1.5}
            defaultViewport={{ x: 0, y: 0, zoom: 0.75 }}
          >
            <Background color="#cbd5e1" gap={20} size={1} />
            <Controls className="!bg-white !border-slate-200 !shadow-sm rounded-lg overflow-hidden" />
            <MiniMap
              nodeStrokeColor="#ea580c"
              nodeColor="#f8fafc"
              className="!bg-white/90 !border !border-slate-200 !rounded-xl"
            />
          </ReactFlow>
        </div>

        {/* Selected Entity Inspector Panel */}
        {selectedNode && (
          <div className="w-80 rounded-xl border border-slate-200 bg-white p-5 shadow-xs overflow-y-auto space-y-4 shrink-0 font-mono text-xs animate-in slide-in-from-right-4 duration-150">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <span className="uppercase text-[10px] font-bold tracking-wider text-slate-400">
                Entity Telemetry
              </span>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-700 text-xs cursor-pointer"
              >
                Close
              </button>
            </div>

            <div>
              <div className="text-[10px] uppercase text-slate-400">Type</div>
              <div className="font-bold text-slate-900 mt-0.5 uppercase">{selectedNode.type.replace('Node', '')}</div>
            </div>

            <div>
              <div className="text-[10px] uppercase text-slate-400">Identifier</div>
              <div className="font-bold text-slate-900 text-xs break-all mt-0.5">
                {selectedNode.data.value || selectedNode.data.label}
              </div>
            </div>

            {selectedNode.data.sightingCount && (
              <div>
                <div className="text-[10px] uppercase text-slate-400">Sightings</div>
                <div className="font-bold text-orange-600 mt-0.5">{selectedNode.data.sightingCount}x observed</div>
              </div>
            )}

            {selectedNode.data.sources && (
              <div>
                <div className="text-[10px] uppercase text-slate-400">Feed Sources</div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.data.sources.map((s: string) => (
                    <span key={s} className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px]">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {selectedNode.data.score && (
              <div>
                <div className="text-[10px] uppercase text-slate-400">CVSS Metric</div>
                <div className="font-bold text-red-600 mt-0.5">{selectedNode.data.score} ({selectedNode.data.severity})</div>
              </div>
            )}

            {selectedNode.data.techniques && selectedNode.data.techniques.length > 0 && (
              <div>
                <div className="text-[10px] uppercase text-slate-400">MITRE Techniques</div>
                <div className="space-y-1 mt-1">
                  {selectedNode.data.techniques.map((t: string) => (
                    <div key={t} className="p-1.5 rounded bg-purple-50 text-purple-800 text-[10px] font-semibold border border-purple-200">
                      {t}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
