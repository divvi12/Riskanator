import { useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Button,
  Modal,
  Tag,
  Tile,
  Search,
  Tooltip
} from '@carbon/react';
import { Add, Warning, Information, Security, Certificate, Password, SettingsCheck, Document, Code, Help } from '@carbon/icons-react';
import { useAppContext } from '../App';
import {
  Exposure,
  CVEExposure,
  CertificateExposure,
  SecretExposure,
  MisconfigurationExposure,
  LicenseExposure,
  CodeSecurityExposure,
  ExposureType
} from '../types';
import { BarChart, Bar, XAxis, YAxis, Tooltip as ChartTooltip, ResponsiveContainer, Cell } from 'recharts';
import { demoExposures } from '../data/demoData';

// Exposure type colors
const EXPOSURE_COLORS: Record<string, string> = {
  cve: '#FA4D56',
  certificate: '#8A3FFC',
  secret: '#FF832B',
  misconfiguration: '#1192E8',
  license: '#009D9A',
  'code-security': '#6929C4'
};

const EXPOSURE_LABELS: Record<string, string> = {
  cve: 'CVEs',
  certificate: 'Certificates',
  secret: 'Secrets',
  misconfiguration: 'Misconfigurations',
  license: 'Licenses',
  'code-security': 'Code Security'
};

const EXPOSURE_ICONS: Record<string, typeof Security> = {
  cve: Security,
  certificate: Certificate,
  secret: Password,
  misconfiguration: SettingsCheck,
  license: Document,
  'code-security': Code
};

// Info about how each exposure type is collected
const EXPOSURE_COLLECTION_INFO: Record<string, string> = {
  cve: 'CVEs are detected using Software Composition Analysis (SCA). We scan package manifests (package.json, requirements.txt, go.mod) and use npm-audit, pip-audit, and Trivy to identify vulnerable dependencies. Results are enriched with CVSS scores, EPSS probabilities, and CISA KEV status from NVD.',
  certificate: 'Certificate exposures are detected by scanning configuration files, code, and infrastructure definitions for SSL/TLS certificates. We check for expired certificates, weak algorithms (SHA-1, MD5), short key lengths, self-signed certificates, and certificates expiring within 30 days.',
  secret: 'Secrets are detected using TruffleHog and pattern-based scanning. We identify API keys, passwords, tokens, private keys, and credentials in source code, config files, and git history. High-entropy strings are analyzed to reduce false positives. Verified secrets (confirmed active) are flagged as critical.',
  misconfiguration: 'Misconfigurations are detected using Checkov for Infrastructure-as-Code scanning. We analyze Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles for security issues like public S3 buckets, missing encryption, overly permissive IAM policies, and CIS benchmark violations.',
  license: 'License exposures are detected by scanning package dependencies for license compliance issues. We identify copyleft licenses (GPL, AGPL) that may conflict with proprietary code, unknown/missing licenses, and licenses that restrict commercial use or require attribution.',
  'code-security': 'Code security issues are detected using Semgrep for Static Application Security Testing (SAST). We scan source code for vulnerabilities like SQL injection, XSS, command injection, path traversal, weak cryptography, and insecure coding patterns across multiple languages.'
};

// Circular progress component
function CircularProgress({
  value,
  total,
  color = '#FA4D56',
  size = 44
}: {
  value: number;
  total: number;
  color?: string;
  size?: number;
}) {
  const percentage = total > 0 ? (value / total) * 100 : 0;
  const radius = (size - 4) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#393939" strokeWidth={4} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth={4}
        strokeDasharray={circumference}
        strokeDashoffset={strokeDashoffset}
        strokeLinecap="round"
      />
    </svg>
  );
}

// Progress bar for risk score
function RiskProgressBar({ value, max, color = '#FA4D56' }: { value: number; max: number; color?: string }) {
  const width = max > 0 ? (value / max) * 100 : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <span style={{ fontSize: '0.8125rem', minWidth: '40px' }}>{value.toFixed(1)}</span>
      <div style={{ width: '80px', height: '4px', backgroundColor: '#393939', borderRadius: '2px' }}>
        <div style={{ width: `${Math.min(width, 100)}%`, height: '100%', backgroundColor: color, borderRadius: '2px' }} />
      </div>
    </div>
  );
}

// Type filter chip
function TypeFilterChip({
  type,
  count,
  isSelected,
  onClick
}: {
  type: ExposureType | 'all';
  count: number;
  isSelected: boolean;
  onClick: () => void;
}) {
  const Icon = type !== 'all' ? EXPOSURE_ICONS[type] : Security;
  const color = type !== 'all' ? EXPOSURE_COLORS[type] : '#78a9ff';
  const label = type !== 'all' ? EXPOSURE_LABELS[type] : 'All';
  const collectionInfo = type !== 'all' ? EXPOSURE_COLLECTION_INFO[type] : null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        padding: '0.5rem 0.75rem',
        backgroundColor: isSelected ? '#262626' : '#161616',
        border: isSelected ? `1px solid ${color}` : '1px solid #393939',
        borderRadius: '4px',
        fontSize: '0.8125rem'
      }}
    >
      <div
        onClick={onClick}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          cursor: 'pointer'
        }}
      >
        <Icon size={16} style={{ color }} />
        <span>{label}</span>
        <Tag size="sm" type={isSelected ? 'blue' : 'gray'}>{count}</Tag>
      </div>
      {collectionInfo && (
        <Tooltip
          align="bottom"
          label={collectionInfo}
        >
          <button
            type="button"
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'none',
              border: 'none',
              padding: '2px',
              cursor: 'help',
              display: 'flex',
              alignItems: 'center',
              color: 'var(--cve-text-secondary)'
            }}
          >
            <Help size={14} />
          </button>
        </Tooltip>
      )}
    </div>
  );
}

// Stat card
function StatCard({
  value,
  total,
  label,
  color = '#FA4D56',
  isSelected = false,
  onClick
}: {
  value: number;
  total: number;
  label: string;
  color?: string;
  isSelected?: boolean;
  onClick?: () => void;
}) {
  const percentage = total > 0 ? Math.round((value / total) * 100) : 0;

  return (
    <div
      onClick={onClick}
      style={{
        padding: '1rem',
        backgroundColor: isSelected ? '#262626' : '#161616',
        border: isSelected ? '1px solid #525252' : '1px solid #393939',
        borderRadius: '4px',
        cursor: onClick ? 'pointer' : 'default',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem'
      }}
    >
      <CircularProgress value={value} total={total} color={color} />
      <div>
        <div style={{ fontSize: '1.125rem', fontWeight: 600 }}>
          {value} <span style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>({percentage}%)</span>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>{label}</div>
      </div>
    </div>
  );
}

function ExposuresList() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { currentScan, isDemoMode, fixedExposureIds } = useAppContext();

  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<ExposureType | 'all'>(
    (searchParams.get('type') as ExposureType) || 'all'
  );
  const [selectedSeverity, setSelectedSeverity] = useState<string>(
    searchParams.get('severity') || 'all'
  );
  const [selectedExposure, setSelectedExposure] = useState<Exposure | null>(null);

  // Get exposures from demo or scan, filtering out fixed ones
  const allExposures: Exposure[] = isDemoMode
    ? demoExposures
    : (currentScan?.exposures as Exposure[] || []);

  // Filter out exposures that have been marked as fixed
  const exposures = useMemo(() => {
    return allExposures.filter(e => !fixedExposureIds.has(e.id));
  }, [allExposures, fixedExposureIds]);

  // Count by type
  const countByType = useMemo(() => {
    const counts: Record<string, number> = {
      all: exposures.length,
      cve: 0,
      certificate: 0,
      secret: 0,
      misconfiguration: 0,
      license: 0,
      'code-security': 0
    };
    exposures.forEach(e => {
      counts[e.type] = (counts[e.type] || 0) + 1;
    });
    return counts;
  }, [exposures]);

  // Count by severity
  const countBySeverity = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    exposures.forEach(e => {
      counts[e.severity]++;
    });
    return counts;
  }, [exposures]);

  // Filter exposures
  const filteredExposures = useMemo(() => {
    return exposures.filter((exp) => {
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        if (!exp.title.toLowerCase().includes(term) && !exp.id.toLowerCase().includes(term)) {
          return false;
        }
      }
      if (selectedType !== 'all' && exp.type !== selectedType) return false;
      if (selectedSeverity !== 'all' && exp.severity !== selectedSeverity) return false;
      return true;
    });
  }, [exposures, searchTerm, selectedType, selectedSeverity]);

  // Chart data for exposure distribution
  const chartData = useMemo(() => {
    return Object.entries(EXPOSURE_LABELS).map(([key, label]) => ({
      name: label,
      value: countByType[key] || 0,
      fill: EXPOSURE_COLORS[key]
    })).filter(d => d.value > 0);
  }, [countByType]);

  if (!currentScan && !isDemoMode) {
    return (
      <div className="empty-state">
        <Warning size={64} />
        <h3>No Scan Data Available</h3>
        <p>Start a new scan or try demo mode to see exposures.</p>
        <Button kind="primary" renderIcon={Add} onClick={() => navigate('/app/scan')}>
          Start New Scan
        </Button>
      </div>
    );
  }

  return (
    <div>
      {/* Page Title */}
      <h1 style={{ fontSize: '1.75rem', marginBottom: '1.5rem' }}>Exposures</h1>

      {/* Summary Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '1rem', marginBottom: '1.5rem' }}>
        {/* Left: Total exposures */}
        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #525252' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
            Total Exposures
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 300 }}>
            {exposures.length}
          </div>
          <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginTop: '0.5rem' }}>
            Critical: <span style={{ color: '#FA4D56' }}>{countBySeverity.critical}</span> |
            High: <span style={{ color: '#FF832B' }}>{countBySeverity.high}</span> |
            Medium: <span style={{ color: '#F1C21B' }}>{countBySeverity.medium}</span> |
            Low: <span style={{ color: '#42BE65' }}>{countBySeverity.low}</span>
          </div>
        </Tile>

        {/* Right: Distribution chart */}
        <Tile style={{ padding: '1rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Exposure Distribution by Type</div>
          <div style={{ height: '100px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="horizontal">
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#c6c6c6', fontSize: 9 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#c6c6c6', fontSize: 9 }} width={25} />
                <ChartTooltip contentStyle={{ backgroundColor: '#262626', border: '1px solid #525252', borderRadius: '4px' }} />
                <Bar dataKey="value" radius={[2, 2, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Tile>
      </div>

      {/* Type filter chips */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <TypeFilterChip
          type="all"
          count={countByType.all}
          isSelected={selectedType === 'all'}
          onClick={() => setSelectedType('all')}
        />
        {(['cve', 'secret', 'certificate', 'misconfiguration', 'license', 'code-security'] as ExposureType[]).map(type => (
          <TypeFilterChip
            key={type}
            type={type}
            count={countByType[type] || 0}
            isSelected={selectedType === type}
            onClick={() => setSelectedType(selectedType === type ? 'all' : type)}
          />
        ))}
      </div>

      {/* Severity stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <StatCard
          value={countBySeverity.critical}
          total={exposures.length}
          label="Critical exposures"
          color="#FA4D56"
          isSelected={selectedSeverity === 'critical'}
          onClick={() => setSelectedSeverity(selectedSeverity === 'critical' ? 'all' : 'critical')}
        />
        <StatCard
          value={countBySeverity.high}
          total={exposures.length}
          label="High severity"
          color="#FF832B"
          isSelected={selectedSeverity === 'high'}
          onClick={() => setSelectedSeverity(selectedSeverity === 'high' ? 'all' : 'high')}
        />
        <StatCard
          value={countBySeverity.medium}
          total={exposures.length}
          label="Medium severity"
          color="#F1C21B"
          isSelected={selectedSeverity === 'medium'}
          onClick={() => setSelectedSeverity(selectedSeverity === 'medium' ? 'all' : 'medium')}
        />
        <StatCard
          value={countBySeverity.low}
          total={exposures.length}
          label="Low severity"
          color="#42BE65"
          isSelected={selectedSeverity === 'low'}
          onClick={() => setSelectedSeverity(selectedSeverity === 'low' ? 'all' : 'low')}
        />
      </div>

      {/* Search bar */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', alignItems: 'center' }}>
        <Search
          placeholder="Search exposures..."
          labelText=""
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ maxWidth: '400px' }}
        />
        {(selectedType !== 'all' || selectedSeverity !== 'all') && (
          <Button
            kind="ghost"
            size="sm"
            onClick={() => {
              setSelectedType('all');
              setSelectedSeverity('all');
            }}
          >
            Clear filters
          </Button>
        )}
        <div style={{ marginLeft: 'auto', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
          Showing {filteredExposures.length} of {exposures.length} exposures
        </div>
      </div>

      {/* Active filters */}
      {(selectedType !== 'all' || selectedSeverity !== 'all') && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <span style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>Filtered by:</span>
          {selectedType !== 'all' && (
            <Tag type="blue" filter onClose={() => setSelectedType('all')}>
              Type: {EXPOSURE_LABELS[selectedType]}
            </Tag>
          )}
          {selectedSeverity !== 'all' && (
            <Tag type="red" filter onClose={() => setSelectedSeverity('all')}>
              Severity: {selectedSeverity}
            </Tag>
          )}
        </div>
      )}

      {/* Exposures Table */}
      <Tile style={{ padding: 0, backgroundColor: '#161616', border: '1px solid #393939' }}>
        {/* Table Header */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '40px 200px 100px 120px 180px 1fr',
          padding: '0.75rem 1rem',
          borderBottom: '1px solid #393939',
          backgroundColor: '#262626',
          fontSize: '0.8125rem',
          fontWeight: 500
        }}>
          <div></div>
          <div>Exposure</div>
          <div>Severity</div>
          <div>Type</div>
          <div>Location</div>
          <div>Risk Score</div>
        </div>

        {/* Table Rows */}
        <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
          {filteredExposures.slice(0, 100).map((exposure) => {
            const Icon = EXPOSURE_ICONS[exposure.type] || Security;
            const color = EXPOSURE_COLORS[exposure.type] || '#78a9ff';

            return (
              <div
                key={exposure.id}
                onClick={() => setSelectedExposure(exposure)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '40px 200px 100px 120px 180px 1fr',
                  padding: '0.75rem 1rem',
                  borderBottom: '1px solid #262626',
                  cursor: 'pointer',
                  fontSize: '0.8125rem',
                  alignItems: 'center'
                }}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#262626'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <div>
                  <Icon size={16} style={{ color }} />
                </div>
                <div style={{ color: '#78a9ff' }}>
                  {exposure.title.length > 30 ? exposure.title.substring(0, 28) + '...' : exposure.title}
                </div>
                <div>
                  <Tag
                    type={
                      exposure.severity === 'critical' ? 'red' :
                      exposure.severity === 'high' ? 'magenta' :
                      exposure.severity === 'medium' ? 'warm-gray' : 'green'
                    }
                    size="sm"
                  >
                    {exposure.severity}
                  </Tag>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                  {EXPOSURE_LABELS[exposure.type]}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                  {exposure.location.length > 25 ? exposure.location.substring(0, 23) + '...' : exposure.location}
                </div>
                <RiskProgressBar
                  value={exposure.riskScore?.concert || 0}
                  max={10}
                  color={color}
                />
              </div>
            );
          })}
        </div>
      </Tile>

      {filteredExposures.length > 100 && (
        <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--cve-text-secondary)', fontSize: '0.8125rem' }}>
          Showing 100 of {filteredExposures.length} exposures
        </div>
      )}

      {/* Exposure Detail Modal */}
      <Modal
        open={!!selectedExposure}
        onRequestClose={() => setSelectedExposure(null)}
        modalHeading={selectedExposure?.title || ''}
        passiveModal
        size="lg"
      >
        {selectedExposure && <ExposureDetail exposure={selectedExposure} />}
      </Modal>
    </div>
  );
}

function ExposureDetail({ exposure }: { exposure: Exposure }) {
  const Icon = EXPOSURE_ICONS[exposure.type] || Security;
  const color = EXPOSURE_COLORS[exposure.type] || '#78a9ff';

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
        <Icon size={24} style={{ color }} />
        <Tag
          type={
            exposure.severity === 'critical' ? 'red' :
            exposure.severity === 'high' ? 'magenta' :
            exposure.severity === 'medium' ? 'warm-gray' : 'green'
          }
        >
          {exposure.severity}
        </Tag>
        <Tag type="blue">{EXPOSURE_LABELS[exposure.type]}</Tag>
        {exposure.slaStatus && (
          <Tag
            type={exposure.slaStatus === 'overdue' ? 'red' : exposure.slaStatus === 'due_soon' ? 'magenta' : 'green'}
          >
            {exposure.slaStatus === 'overdue' ? 'SLA Overdue' : exposure.slaStatus === 'due_soon' ? 'SLA Due Soon' : 'On Track'}
          </Tag>
        )}
      </div>

      {/* Description */}
      <div style={{ marginBottom: '1rem' }}>
        <h4 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Information size={16} />
          Description
        </h4>
        <p style={{ color: 'var(--cve-text-secondary)', lineHeight: 1.6 }}>{exposure.description}</p>
      </div>

      {/* Location */}
      <div style={{ marginBottom: '1rem' }}>
        <h4 style={{ marginBottom: '0.5rem' }}>Location</h4>
        <p style={{ fontFamily: 'monospace', backgroundColor: '#262626', padding: '0.5rem', borderRadius: '4px' }}>
          {exposure.location}
        </p>
      </div>

      {/* Risk Score */}
      <div style={{ marginBottom: '1rem' }}>
        <h4 style={{ marginBottom: '0.5rem' }}>Risk Score</h4>
        <div style={{ display: 'flex', gap: '2rem' }}>
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Concert:</span>
            <span style={{ marginLeft: '0.5rem', fontSize: '1.25rem', fontWeight: 600, color }}>
              {exposure.riskScore?.concert?.toFixed(1)}/10
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Comprehensive:</span>
            <span style={{ marginLeft: '0.5rem', fontSize: '1.25rem', fontWeight: 600 }}>
              {exposure.riskScore?.comprehensive?.toFixed(0)}
            </span>
          </div>
        </div>
      </div>

      {/* Type-specific details */}
      {exposure.type === 'cve' && <CVEDetails exposure={exposure as CVEExposure} />}
      {exposure.type === 'certificate' && <CertificateDetails exposure={exposure as CertificateExposure} />}
      {exposure.type === 'secret' && <SecretDetails exposure={exposure as SecretExposure} />}
      {exposure.type === 'misconfiguration' && <MisconfigDetails exposure={exposure as MisconfigurationExposure} />}
      {exposure.type === 'license' && <LicenseDetails exposure={exposure as LicenseExposure} />}
      {exposure.type === 'code-security' && <CodeSecurityDetails exposure={exposure as CodeSecurityExposure} />}

      {/* Compliance Impact */}
      {exposure.complianceImpact && exposure.complianceImpact.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <h4 style={{ marginBottom: '0.5rem' }}>Compliance Impact</h4>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {exposure.complianceImpact.map((impact, index) => (
              <Tag key={index} type="purple">{impact}</Tag>
            ))}
          </div>
        </div>
      )}

      {/* SLA */}
      {exposure.slaDeadline && (
        <div>
          <h4 style={{ marginBottom: '0.5rem' }}>SLA Deadline</h4>
          <p>
            <span className={exposure.slaStatus === 'overdue' ? 'text-critical' : exposure.slaStatus === 'due_soon' ? 'text-high' : 'text-low'}>
              {exposure.slaDeadline}
            </span>
            {exposure.daysRemaining !== undefined && (
              <span style={{ marginLeft: '0.5rem', color: 'var(--cve-text-secondary)' }}>
                ({exposure.daysRemaining > 0 ? `${exposure.daysRemaining} days remaining` : `${Math.abs(exposure.daysRemaining)} days overdue`})
              </span>
            )}
          </p>
        </div>
      )}
    </div>
  );
}

function CVEDetails({ exposure }: { exposure: CVEExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>CVE Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>CVE ID:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.cveId}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>CVSS:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.cvss?.toFixed(1)}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Component:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.component} v{exposure.version}</span>
        </div>
        {exposure.fixedVersion && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Fix Available:</span>
            <span style={{ marginLeft: '0.5rem', color: '#42BE65' }}>{exposure.fixedVersion}</span>
          </div>
        )}
        {exposure.epss !== undefined && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>EPSS:</span>
            <span style={{ marginLeft: '0.5rem' }}>{(exposure.epss * 100).toFixed(1)}%</span>
          </div>
        )}
        {exposure.cisaKEV && (
          <div>
            <Tag type="red">CISA KEV</Tag>
          </div>
        )}
      </div>
    </div>
  );
}

function CertificateDetails({ exposure }: { exposure: CertificateExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>Certificate Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Domain:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.domain}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Issuer:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.issuer}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Valid Until:</span>
          <span style={{ marginLeft: '0.5rem', color: exposure.isExpired ? '#FA4D56' : '#42BE65' }}>
            {exposure.validTo}
          </span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Days Until Expiration:</span>
          <span style={{ marginLeft: '0.5rem', color: exposure.daysUntilExpiration <= 30 ? '#FA4D56' : '#42BE65' }}>
            {exposure.daysUntilExpiration}
          </span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Algorithm:</span>
          <span style={{ marginLeft: '0.5rem', color: exposure.hasWeakAlgorithm ? '#FA4D56' : 'inherit' }}>
            {exposure.algorithm}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {exposure.isExpired && <Tag type="red">Expired</Tag>}
          {exposure.isSelfSigned && <Tag type="magenta">Self-Signed</Tag>}
          {exposure.hasWeakAlgorithm && <Tag type="red">Weak Algorithm</Tag>}
        </div>
      </div>
    </div>
  );
}

function SecretDetails({ exposure }: { exposure: SecretExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>Secret Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Secret Type:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.secretType}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Detector:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.detectorName}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Verified:</span>
          <span style={{ marginLeft: '0.5rem', color: exposure.verified ? '#FA4D56' : '#F1C21B' }}>
            {exposure.verified ? 'Yes (Active)' : 'Not Verified'}
          </span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>In Git History:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.inGitHistory ? 'Yes' : 'No'}</span>
        </div>
        {exposure.lineNumber && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Line Number:</span>
            <span style={{ marginLeft: '0.5rem' }}>{exposure.lineNumber}</span>
          </div>
        )}
      </div>
      {exposure.codeSnippet && (
        <div style={{ marginTop: '0.5rem' }}>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Code Snippet:</span>
          <pre style={{ backgroundColor: '#262626', padding: '0.5rem', borderRadius: '4px', fontSize: '0.75rem', overflow: 'auto' }}>
            {exposure.codeSnippet}
          </pre>
        </div>
      )}
    </div>
  );
}

function MisconfigDetails({ exposure }: { exposure: MisconfigurationExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>Misconfiguration Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Resource Type:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.resourceType}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Check ID:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.checkId}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Check Name:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.checkName}</span>
        </div>
        {exposure.framework && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Framework:</span>
            <span style={{ marginLeft: '0.5rem' }}>{exposure.framework}</span>
          </div>
        )}
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Publicly Accessible:</span>
          <span style={{ marginLeft: '0.5rem', color: exposure.isPubliclyAccessible ? '#FA4D56' : '#42BE65' }}>
            {exposure.isPubliclyAccessible ? 'Yes' : 'No'}
          </span>
        </div>
      </div>
      {exposure.guideline && (
        <div style={{ marginTop: '0.5rem' }}>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Guideline:</span>
          <p style={{ marginTop: '0.25rem' }}>{exposure.guideline}</p>
        </div>
      )}
    </div>
  );
}

function LicenseDetails({ exposure }: { exposure: LicenseExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>License Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Package:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.packageName} v{exposure.packageVersion}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>License:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.licenseName}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>License Type:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.licenseType}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {exposure.isCopyleft && <Tag type="red">Copyleft</Tag>}
          {exposure.isUnknown && <Tag type="magenta">Unknown License</Tag>}
          {exposure.requiresAttribution && <Tag type="blue">Requires Attribution</Tag>}
          {!exposure.commercialUseAllowed && <Tag type="red">No Commercial Use</Tag>}
        </div>
      </div>
    </div>
  );
}

function CodeSecurityDetails({ exposure }: { exposure: CodeSecurityExposure }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <h4 style={{ marginBottom: '0.5rem' }}>Code Security Details</h4>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Issue Type:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.issueType.replace(/_/g, ' ')}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Rule:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.ruleName}</span>
        </div>
        <div>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Line:</span>
          <span style={{ marginLeft: '0.5rem' }}>{exposure.lineNumber}{exposure.endLineNumber ? `-${exposure.endLineNumber}` : ''}</span>
        </div>
        {exposure.cwe && exposure.cwe.length > 0 && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>CWE:</span>
            <span style={{ marginLeft: '0.5rem' }}>{exposure.cwe.join(', ')}</span>
          </div>
        )}
        {exposure.owasp && exposure.owasp.length > 0 && (
          <div>
            <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>OWASP:</span>
            <span style={{ marginLeft: '0.5rem' }}>{exposure.owasp.join(', ')}</span>
          </div>
        )}
      </div>
      {exposure.codeSnippet && (
        <div style={{ marginTop: '0.5rem' }}>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Code:</span>
          <pre style={{ backgroundColor: '#262626', padding: '0.5rem', borderRadius: '4px', fontSize: '0.75rem', overflow: 'auto' }}>
            {exposure.codeSnippet}
          </pre>
        </div>
      )}
      {exposure.fixSuggestion && (
        <div style={{ marginTop: '0.5rem' }}>
          <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Fix Suggestion:</span>
          <p style={{ marginTop: '0.25rem', color: '#42BE65' }}>{exposure.fixSuggestion}</p>
        </div>
      )}
    </div>
  );
}

export default ExposuresList;
