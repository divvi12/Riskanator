import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Tile, Tag, Toggle, Tooltip, Modal } from '@carbon/react';
import {
  Application,
  DataBase,
  Cloud,
  Security,
  WarningAlt,
  CheckmarkFilled,
  Information,
  Help,
  Locked,
  Unlocked,
  ArrowRight,
  Certificate,
  Password,
  SettingsCheck,
  Document,
  Code
} from '@carbon/icons-react';
import { useAppContext } from '../App';
import { TopologyNode, TopologyEdge, Exposure } from '../types';
import { demoExposures, demoExtendedScanResult } from '../data/demoData';

// Node type icons and colors
const NODE_CONFIG: Record<string, { icon: typeof Application; color: string; label: string }> = {
  application: { icon: Application, color: '#4589FF', label: 'Application' },
  gateway: { icon: Cloud, color: '#0f62fe', label: 'Gateway' },
  service: { icon: Application, color: '#6929c4', label: 'Service' },
  database: { icon: DataBase, color: '#009d9a', label: 'Database' },
  cache: { icon: DataBase, color: '#1192e8', label: 'Cache' },
  queue: { icon: Cloud, color: '#a56eff', label: 'Queue' },
  external: { icon: Cloud, color: '#8a3ffc', label: 'External' },
  storage: { icon: DataBase, color: '#007d79', label: 'Storage' },
  container: { icon: Application, color: '#0072c3', label: 'Container' }
};

// Risk level colors
const RISK_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  critical: { bg: '#FA4D56', border: '#da1e28', text: '#fff' },
  high: { bg: '#FF832B', border: '#eb6200', text: '#fff' },
  medium: { bg: '#F1C21B', border: '#d2a106', text: '#161616' },
  low: { bg: '#42BE65', border: '#24a148', text: '#fff' },
  healthy: { bg: '#198038', border: '#0e6027', text: '#fff' }
};

// Calculate node positions in a layered layout based on node type
function calculateNodePositions(nodes: TopologyNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  // If nodes have pre-calculated positions from backend, use them
  const hasBackendPositions = nodes.some(n => n.x !== undefined && n.y !== undefined);
  if (hasBackendPositions) {
    nodes.forEach(node => {
      if (node.x !== undefined && node.y !== undefined) {
        positions.set(node.id, { x: node.x, y: node.y });
      }
    });
    return positions;
  }

  // Layer mapping based on node TYPE (not id)
  // Matches the visual labels: Frontend(0), Gateway(1), Services(2), Data Layer(3), External(4), Infrastructure(5)
  const typeToLayer: Record<string, number> = {
    'application': 0,  // Frontend
    'gateway': 1,      // Gateway
    'service': 2,      // Services
    'database': 3,     // Data Layer
    'cache': 3,        // Data Layer
    'queue': 3,        // Data Layer
    'external': 4,     // External
    'storage': 5,      // Infrastructure
    'container': 5     // Infrastructure
  };

  // Fixed y positions for each layer (matching the static labels)
  const layerYPositions: Record<number, number> = {
    0: 85,   // Frontend
    1: 185,  // Gateway
    2: 285,  // Services
    3: 385,  // Data Layer
    4: 485,  // External
    5: 585   // Infrastructure
  };

  // Group nodes by layer
  const nodesByLayer: Map<number, TopologyNode[]> = new Map();
  nodes.forEach(node => {
    const layer = typeToLayer[node.type] ?? 2;
    if (!nodesByLayer.has(layer)) {
      nodesByLayer.set(layer, []);
    }
    nodesByLayer.get(layer)!.push(node);
  });

  // Position nodes using fixed y positions
  const width = 900;

  nodesByLayer.forEach((layerNodes, layer) => {
    const nodeWidth = width / (layerNodes.length + 1);
    const yPos = layerYPositions[layer] ?? 285; // Default to Services layer
    layerNodes.forEach((node, index) => {
      positions.set(node.id, {
        x: nodeWidth * (index + 1),
        y: yPos
      });
    });
  });

  return positions;
}

// Topology Node Component
function TopologyNodeComponent({
  node,
  position,
  isSelected,
  onClick,
  showLabels
}: {
  node: TopologyNode;
  position: { x: number; y: number };
  isSelected: boolean;
  onClick: () => void;
  showLabels: boolean;
}) {
  const config = NODE_CONFIG[node.type] || NODE_CONFIG.service;
  const riskColor = RISK_COLORS[node.riskLevel] || RISK_COLORS.medium;
  const Icon = config.icon;

  return (
    <g
      transform={`translate(${position.x - 40}, ${position.y - 30})`}
      onClick={onClick}
      style={{ cursor: 'pointer' }}
    >
      {/* Node background */}
      <rect
        x={0}
        y={0}
        width={80}
        height={60}
        rx={8}
        fill={isSelected ? riskColor.bg : '#262626'}
        stroke={riskColor.border}
        strokeWidth={isSelected ? 3 : 2}
        opacity={isSelected ? 1 : 0.9}
      />

      {/* Risk indicator dot */}
      <circle
        cx={70}
        cy={10}
        r={6}
        fill={riskColor.bg}
      />

      {/* Icon */}
      <foreignObject x={28} y={8} width={24} height={24}>
        <Icon size={24} />
      </foreignObject>

      {/* Node name (always visible) */}
      <text
        x={40}
        y={45}
        textAnchor="middle"
        fill="#f4f4f4"
        fontSize={10}
        fontWeight={500}
      >
        {node.name.length > 12 ? node.name.substring(0, 11) + '…' : node.name}
      </text>

      {/* CVE/Exposure count badge */}
      {(node.cveCount > 0 || node.exposureCount > 0) && (
        <g transform="translate(60, 45)">
          <rect
            x={0}
            y={0}
            width={20}
            height={14}
            rx={7}
            fill={node.cveCount > 10 ? '#FA4D56' : node.cveCount > 0 ? '#FF832B' : '#42BE65'}
          />
          <text x={10} y={10} textAnchor="middle" fill="#fff" fontSize={8} fontWeight={600}>
            {node.cveCount + node.exposureCount}
          </text>
        </g>
      )}

      {/* Extended label on hover/selection */}
      {showLabels && (
        <g transform="translate(-20, 65)">
          <rect
            x={0}
            y={0}
            width={120}
            height={40}
            rx={4}
            fill="#393939"
            stroke="#525252"
          />
          <text x={60} y={14} textAnchor="middle" fill="#c6c6c6" fontSize={9}>
            {node.technology}
          </text>
          <text x={60} y={28} textAnchor="middle" fill="#f4f4f4" fontSize={10}>
            {node.cveCount} CVEs • {node.exposureCount} Issues
          </text>
        </g>
      )}
    </g>
  );
}

// Edge Component
function EdgeComponent({
  edge,
  sourcePos,
  targetPos,
  showSecurity
}: {
  edge: TopologyEdge;
  sourcePos: { x: number; y: number };
  targetPos: { x: number; y: number };
  showSecurity: boolean;
}) {
  const midX = (sourcePos.x + targetPos.x) / 2;
  const midY = (sourcePos.y + targetPos.y) / 2;

  // Calculate control point for curved lines
  const dx = targetPos.x - sourcePos.x;
  const dy = targetPos.y - sourcePos.y;
  const controlX = midX + dy * 0.1;
  const controlY = midY - dx * 0.1;

  const pathD = `M ${sourcePos.x} ${sourcePos.y} Q ${controlX} ${controlY} ${targetPos.x} ${targetPos.y}`;

  return (
    <g>
      <path
        d={pathD}
        fill="none"
        stroke={edge.encrypted ? '#42BE65' : showSecurity ? '#FA4D56' : '#525252'}
        strokeWidth={showSecurity && !edge.encrypted ? 2 : 1.5}
        strokeDasharray={edge.encrypted ? undefined : '4,4'}
        opacity={0.7}
        markerEnd="url(#arrowhead)"
      />

      {/* Connection label */}
      <g transform={`translate(${midX - 20}, ${midY - 8})`}>
        <rect
          x={0}
          y={0}
          width={40}
          height={16}
          rx={3}
          fill="#262626"
          stroke="#525252"
        />
        <text x={20} y={11} textAnchor="middle" fill="#c6c6c6" fontSize={8}>
          {edge.label}
        </text>
        {showSecurity && (
          <foreignObject x={32} y={2} width={12} height={12}>
            {edge.encrypted ? (
              <Locked size={12} style={{ color: '#42BE65' }} />
            ) : (
              <Unlocked size={12} style={{ color: '#FA4D56' }} />
            )}
          </foreignObject>
        )}
      </g>
    </g>
  );
}

// Exposure type colors and icons for unified exposures
const EXPOSURE_TYPE_CONFIG: Record<string, { icon: typeof Security; color: string; label: string }> = {
  cve: { icon: Security, color: '#FA4D56', label: 'CVEs' },
  certificate: { icon: Certificate, color: '#8A3FFC', label: 'Certificates' },
  secret: { icon: Password, color: '#FF832B', label: 'Secrets' },
  misconfiguration: { icon: SettingsCheck, color: '#1192E8', label: 'Misconfigurations' },
  license: { icon: Document, color: '#009D9A', label: 'Licenses' },
  'code-security': { icon: Code, color: '#6929C4', label: 'Code Security' }
};

// Main Arena View Component
export default function ArenaView() {
  const { currentScan, isDemoMode } = useAppContext();
  const navigate = useNavigate();

  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [showSecurityOverlay, setShowSecurityOverlay] = useState(true);
  const [showLabels, setShowLabels] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [selectedExposureType, setSelectedExposureType] = useState<string | null>(null);

  const topology = isDemoMode ? demoExtendedScanResult.topology : currentScan?.topology;
  const exposures: Exposure[] = isDemoMode ? demoExposures : (currentScan?.exposures as Exposure[] || []);

  // Calculate node positions
  const nodePositions = useMemo(() => {
    if (!topology) return new Map();
    return calculateNodePositions(topology.nodes);
  }, [topology]);

  // Get exposures for selected node
  const selectedNodeExposures = useMemo(() => {
    if (!selectedNode) return [];
    // Filter exposures that might relate to this node (simplified matching)
    return exposures.filter(e =>
      e.location.toLowerCase().includes(selectedNode.id.toLowerCase()) ||
      e.location.toLowerCase().includes(selectedNode.technology?.toLowerCase() || '')
    );
  }, [selectedNode, exposures]);

  // Filter exposures by type
  const filteredExposures = useMemo(() => {
    if (!selectedExposureType) return exposures;
    return exposures.filter(e => e.type === selectedExposureType);
  }, [exposures, selectedExposureType]);

  // Exposure counts by type
  const exposureCountsByType = useMemo(() => {
    const counts: Record<string, number> = {};
    exposures.forEach(e => {
      counts[e.type] = (counts[e.type] || 0) + 1;
    });
    return counts;
  }, [exposures]);

  if (!topology) {
    return (
      <div className="empty-state">
        <WarningAlt size={64} />
        <h3>No Topology Data Available</h3>
        <p>Run a scan or enable demo mode to see your application architecture and security posture.</p>
        <Button kind="primary" onClick={() => navigate('/app/scan')}>
          Start New Scan
        </Button>
      </div>
    );
  }

  // Summary stats
  const criticalNodes = topology.nodes.filter(n => n.riskLevel === 'critical').length;
  const highRiskNodes = topology.nodes.filter(n => n.riskLevel === 'high').length;
  const unencryptedConnections = topology.edges.filter(e => !e.encrypted).length;
  const totalExposures = exposures.length;
  const criticalExposures = exposures.filter(e => e.severity === 'critical').length;

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-4">
        <div>
          <h1 style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>Arena View</h1>
          <p style={{ color: 'var(--cve-text-secondary)' }}>
            Application topology and security posture visualization
          </p>
        </div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <Toggle
            id="security-overlay"
            labelText="Security Overlay"
            toggled={showSecurityOverlay}
            onToggle={setShowSecurityOverlay}
            size="sm"
          />
          <Toggle
            id="show-labels"
            labelText="Show Details"
            toggled={showLabels}
            onToggle={setShowLabels}
            size="sm"
          />
        </div>
      </div>

      {/* Help Section */}
      <Tile style={{ marginBottom: '1.5rem', padding: '1rem', backgroundColor: 'var(--cve-background-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
          <Help size={20} style={{ color: 'var(--cve-interactive)', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h4 style={{ marginBottom: '0.5rem', fontSize: '0.875rem' }}>Understanding the Arena View</h4>
            <p style={{ color: 'var(--cve-text-secondary)', fontSize: '0.8125rem', lineHeight: 1.6, margin: 0 }}>
              This diagram shows your application's components and how they connect. <strong>Node colors</strong> indicate risk level (red = critical, orange = high).
              <strong> Dashed lines</strong> show unencrypted connections. Click any component to see details. Use <strong>Security Overlay</strong> to highlight security issues.
            </p>
          </div>
        </div>
      </Tile>

      {/* Summary Cards */}
      <div className="dashboard-grid" style={{ marginBottom: '1.5rem' }}>
        <Tile className="metric-card">
          <div className="metric-label">Total Components</div>
          <div className="metric-value">{topology.nodes.length}</div>
          <div className="metric-subtext">Services, databases, and infrastructure</div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label" style={{ color: '#FA4D56' }}>Critical Risk Components</div>
          <div className="metric-value text-critical">{criticalNodes}</div>
          <div className="metric-subtext">{highRiskNodes} high risk components</div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label">Unencrypted Connections</div>
          <div className="metric-value" style={{ color: unencryptedConnections > 0 ? '#FF832B' : '#42BE65' }}>
            {unencryptedConnections}
          </div>
          <div className="metric-subtext">of {topology.edges.length} total connections</div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label">All Exposures</div>
          <div className="metric-value">{totalExposures}</div>
          <div className="metric-subtext">{criticalExposures} critical across 6 types</div>
        </Tile>
      </div>

      {/* Topology Diagram */}
      <Tile className="cve-card" style={{ padding: '1rem', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', marginBottom: '1rem' }}>Application Topology</h3>
        <div style={{ width: '100%', height: '650px', overflow: 'auto', backgroundColor: '#161616', borderRadius: '4px' }}>
          <svg width="900" height="700" style={{ display: 'block', margin: '0 auto' }}>
            {/* Definitions */}
            <defs>
              <marker
                id="arrowhead"
                markerWidth="10"
                markerHeight="7"
                refX="9"
                refY="3.5"
                orient="auto"
              >
                <polygon points="0 0, 10 3.5, 0 7" fill="#525252" />
              </marker>
            </defs>

            {/* Layer labels */}
            <text x={30} y={85} fill="#6f6f6f" fontSize={11}>Frontend</text>
            <text x={30} y={185} fill="#6f6f6f" fontSize={11}>Gateway</text>
            <text x={30} y={285} fill="#6f6f6f" fontSize={11}>Services</text>
            <text x={30} y={385} fill="#6f6f6f" fontSize={11}>Data Layer</text>
            <text x={30} y={485} fill="#6f6f6f" fontSize={11}>External</text>
            <text x={30} y={585} fill="#6f6f6f" fontSize={11}>Infrastructure</text>

            {/* Edges (render first so they're behind nodes) */}
            {topology.edges.map((edge, index) => {
              const sourcePos = nodePositions.get(edge.source);
              const targetPos = nodePositions.get(edge.target);
              if (!sourcePos || !targetPos) return null;
              return (
                <EdgeComponent
                  key={index}
                  edge={edge}
                  sourcePos={sourcePos}
                  targetPos={targetPos}
                  showSecurity={showSecurityOverlay}
                />
              );
            })}

            {/* Nodes */}
            {topology.nodes.map(node => {
              const pos = nodePositions.get(node.id);
              if (!pos) return null;
              return (
                <TopologyNodeComponent
                  key={node.id}
                  node={node}
                  position={pos}
                  isSelected={selectedNode?.id === node.id}
                  onClick={() => {
                    setSelectedNode(node);
                    setDetailModalOpen(true);
                  }}
                  showLabels={showLabels || selectedNode?.id === node.id}
                />
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', gap: '2rem', marginTop: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#c6c6c6' }}>Risk Level:</span>
            {Object.entries(RISK_COLORS).map(([level, colors]) => (
              <div key={level} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <div style={{ width: 12, height: 12, borderRadius: '50%', backgroundColor: colors.bg }} />
                <span style={{ fontSize: '0.75rem', color: '#c6c6c6', textTransform: 'capitalize' }}>{level}</span>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#c6c6c6' }}>Connections:</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <div style={{ width: 20, height: 2, backgroundColor: '#42BE65' }} />
              <span style={{ fontSize: '0.75rem', color: '#c6c6c6' }}>Encrypted</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <div style={{ width: 20, height: 2, backgroundColor: '#FA4D56', borderStyle: 'dashed', borderWidth: '1px' }} />
              <span style={{ fontSize: '0.75rem', color: '#c6c6c6' }}>Unencrypted</span>
            </div>
          </div>
        </div>
      </Tile>

      {/* Unified Exposures Section - All 6 Types */}
      <Tile className="cve-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Security size={20} />
          <h3 style={{ fontSize: '1rem', margin: 0 }}>All Exposures</h3>
          <Tooltip label="All security exposures: CVEs, secrets, certificates, misconfigurations, licenses, and code security issues">
            <button type="button" style={{ background: 'none', border: 'none', padding: '2px', cursor: 'help' }}>
              <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
            </button>
          </Tooltip>
        </div>

        {/* Exposure type filter chips */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <Tag
            type={selectedExposureType === null ? 'blue' : 'gray'}
            size="sm"
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedExposureType(null)}
          >
            All ({exposures.length})
          </Tag>
          {Object.entries(EXPOSURE_TYPE_CONFIG).map(([type, config]) => {
            const count = exposureCountsByType[type] || 0;
            if (count === 0) return null;
            const Icon = config.icon;
            return (
              <Tag
                key={type}
                type={selectedExposureType === type ? 'blue' : 'gray'}
                size="sm"
                style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                onClick={() => setSelectedExposureType(selectedExposureType === type ? null : type)}
              >
                <Icon size={12} />
                {config.label}: {count}
              </Tag>
            );
          })}
        </div>

        {/* Exposure list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '400px', overflow: 'auto' }}>
          {filteredExposures
            .sort((a, b) => (b.riskScore?.concert || 0) - (a.riskScore?.concert || 0))
            .slice(0, 50)
            .map(exposure => {
              const typeConfig = EXPOSURE_TYPE_CONFIG[exposure.type];
              const TypeIcon = typeConfig?.icon || Security;
              return (
                <div
                  key={exposure.id}
                  style={{
                    padding: '0.75rem',
                    backgroundColor: 'var(--cve-background)',
                    borderRadius: '4px',
                    borderLeft: `3px solid ${typeConfig?.color || '#FA4D56'}`
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <div style={{
                        width: 24,
                        height: 24,
                        borderRadius: 4,
                        backgroundColor: `${typeConfig?.color || '#FA4D56'}30`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        <TypeIcon size={14} style={{ color: typeConfig?.color }} />
                      </div>
                      <Tag type={
                        exposure.severity === 'critical' ? 'red' :
                        exposure.severity === 'high' ? 'magenta' :
                        exposure.severity === 'medium' ? 'gray' : 'green'
                      } size="sm">
                        {exposure.severity}
                      </Tag>
                      <strong style={{ fontSize: '0.875rem' }}>{exposure.title}</strong>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                      {exposure.riskScore?.concert?.toFixed(1)}/10
                    </span>
                  </div>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', margin: '0.25rem 0' }}>
                    {exposure.description.substring(0, 150)}{exposure.description.length > 150 ? '...' : ''}
                  </p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem' }}>
                    <code style={{ fontSize: '0.75rem', color: '#78a9ff', backgroundColor: '#262626', padding: '0.125rem 0.375rem', borderRadius: '2px' }}>
                      {exposure.location}
                    </code>
                    <Tag type="outline" size="sm">{typeConfig?.label || exposure.type}</Tag>
                  </div>
                  {exposure.complianceImpact && exposure.complianceImpact.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                      {exposure.complianceImpact.slice(0, 2).map((impact, i) => (
                        <Tag key={i} type="purple" size="sm">{impact}</Tag>
                      ))}
                      {exposure.complianceImpact.length > 2 && (
                        <Tag type="outline" size="sm">+{exposure.complianceImpact.length - 2}</Tag>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          {filteredExposures.length > 50 && (
            <Button kind="ghost" size="sm" onClick={() => navigate('/app/exposures')}>
              View all {filteredExposures.length} exposures <ArrowRight size={16} />
            </Button>
          )}
        </div>
      </Tile>

      {/* Node Detail Modal */}
      <Modal
        open={detailModalOpen}
        onRequestClose={() => setDetailModalOpen(false)}
        modalHeading={selectedNode?.name || 'Component Details'}
        passiveModal
        size="md"
      >
        {selectedNode && (
          <div style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
              <Tag type={
                selectedNode.riskLevel === 'critical' ? 'red' :
                selectedNode.riskLevel === 'high' ? 'magenta' :
                selectedNode.riskLevel === 'medium' ? 'gray' : 'green'
              }>
                {selectedNode.riskLevel} risk
              </Tag>
              <Tag type="outline">{selectedNode.type}</Tag>
              {selectedNode.technology && <Tag type="blue">{selectedNode.technology}</Tag>}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
              <Tile style={{ padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>CVEs</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 600, color: selectedNode.cveCount > 10 ? '#FA4D56' : '#f4f4f4' }}>
                  {selectedNode.cveCount}
                </div>
              </Tile>
              <Tile style={{ padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Exposures</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 600, color: selectedNode.exposureCount > 3 ? '#FF832B' : '#f4f4f4' }}>
                  {selectedNode.exposureCount}
                </div>
              </Tile>
            </div>

            <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Connections</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginBottom: '1rem' }}>
              {topology.edges
                .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                .map((edge, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
                    {edge.encrypted ? (
                      <CheckmarkFilled size={16} style={{ color: '#42BE65' }} />
                    ) : (
                      <WarningAlt size={16} style={{ color: '#FA4D56' }} />
                    )}
                    <span>
                      {edge.source === selectedNode.id ? `→ ${edge.target}` : `← ${edge.source}`}
                    </span>
                    <span style={{ color: 'var(--cve-text-secondary)' }}>({edge.protocol})</span>
                    {!edge.encrypted && (
                      <Tag type="red" size="sm">Unencrypted</Tag>
                    )}
                  </div>
                ))}
            </div>

            {selectedNodeExposures.length > 0 && (
              <>
                <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Related Exposures</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {selectedNodeExposures.map(exp => (
                    <div key={exp.id} style={{ padding: '0.5rem', backgroundColor: '#262626', borderRadius: '4px', fontSize: '0.8125rem' }}>
                      <strong>{exp.title}</strong>
                      <p style={{ margin: '0.25rem 0 0', color: 'var(--cve-text-secondary)' }}>{exp.description}</p>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ marginTop: '1rem' }}>
              <Button
                kind="secondary"
                size="sm"
                onClick={() => {
                  setDetailModalOpen(false);
                  navigate('/app/cves');
                }}
              >
                View CVEs for this Component
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
