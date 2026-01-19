import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Tile,
  Tag,
  Modal,
  Accordion,
  AccordionItem,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch
} from '@carbon/react';
import {
  WarningAlt,
  Add,
  Security,
  Certificate,
  Password,
  SettingsCheck,
  Document,
  Code,
  CheckmarkFilled,
  CloseFilled,
  ChevronRight,
  Report
} from '@carbon/icons-react';
import { useAppContext } from '../App';
import { Exposure } from '../types';
import { demoExposures } from '../data/demoData';

// Compliance framework definitions
const COMPLIANCE_FRAMEWORKS = {
  'PCI-DSS': {
    name: 'PCI-DSS',
    fullName: 'Payment Card Industry Data Security Standard',
    description: 'Requirements for handling payment card data securely',
    color: '#0f62fe',
    icon: '💳',
    categories: ['Data Protection', 'Access Control', 'Network Security', 'Vulnerability Management']
  },
  'HIPAA': {
    name: 'HIPAA',
    fullName: 'Health Insurance Portability and Accountability Act',
    description: 'Standards for protecting sensitive patient health information',
    color: '#24A148',
    icon: '🏥',
    categories: ['Privacy', 'Security', 'Administrative Safeguards']
  },
  'SOX': {
    name: 'SOX',
    fullName: 'Sarbanes-Oxley Act',
    description: 'Financial reporting and internal controls requirements',
    color: '#8A3FFC',
    icon: '📊',
    categories: ['Internal Controls', 'Financial Reporting', 'IT Controls']
  },
  'GDPR': {
    name: 'GDPR',
    fullName: 'General Data Protection Regulation',
    description: 'EU regulation on data protection and privacy',
    color: '#009D9A',
    icon: '🔒',
    categories: ['Data Protection', 'Privacy Rights', 'Security Measures']
  },
  'OWASP': {
    name: 'OWASP Top 10',
    fullName: 'OWASP Top 10 Web Application Security Risks',
    description: 'Standard awareness document for web application security',
    color: '#FA4D56',
    icon: '🌐',
    categories: ['Injection', 'Authentication', 'Cryptographic Failures']
  },
  'CIS': {
    name: 'CIS Controls',
    fullName: 'Center for Internet Security Controls',
    description: 'Prioritized set of actions for cyber defense',
    color: '#FF832B',
    icon: '🛡️',
    categories: ['Asset Management', 'Secure Configuration', 'Access Control']
  },
  'SOC2': {
    name: 'SOC 2',
    fullName: 'Service Organization Control 2',
    description: 'Trust service criteria for service organizations',
    color: '#6929C4',
    icon: '✅',
    categories: ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy']
  },
  'NIST': {
    name: 'NIST',
    fullName: 'NIST Cybersecurity Framework',
    description: 'Cybersecurity standards and guidelines',
    color: '#002D9C',
    icon: '📋',
    categories: ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
  }
};

// Exposure type icons
const EXPOSURE_ICONS: Record<string, typeof Security> = {
  cve: Security,
  certificate: Certificate,
  secret: Password,
  misconfiguration: SettingsCheck,
  license: Document,
  'code-security': Code
};

// Exposure type colors
const EXPOSURE_COLORS: Record<string, string> = {
  cve: '#FA4D56',
  certificate: '#8A3FFC',
  secret: '#FF832B',
  misconfiguration: '#1192E8',
  license: '#009D9A',
  'code-security': '#6929C4'
};

const SEVERITY_COLORS = {
  critical: '#FA4D56',
  high: '#FF832B',
  medium: '#F1C21B',
  low: '#42BE65'
};

// Parse compliance impact string to extract framework
function parseFramework(complianceImpact: string): string {
  if (complianceImpact.includes('PCI-DSS') || complianceImpact.includes('PCI')) return 'PCI-DSS';
  if (complianceImpact.includes('HIPAA')) return 'HIPAA';
  if (complianceImpact.includes('SOX')) return 'SOX';
  if (complianceImpact.includes('GDPR')) return 'GDPR';
  if (complianceImpact.includes('OWASP')) return 'OWASP';
  if (complianceImpact.includes('CIS')) return 'CIS';
  if (complianceImpact.includes('SOC2') || complianceImpact.includes('SOC 2')) return 'SOC2';
  if (complianceImpact.includes('NIST')) return 'NIST';
  return 'Other';
}

// Group exposures by framework
function groupByFramework(exposures: Exposure[]): Map<string, { exposures: Exposure[]; requirements: Set<string> }> {
  const frameworkMap = new Map<string, { exposures: Exposure[]; requirements: Set<string> }>();

  exposures.forEach(exposure => {
    if (!exposure.complianceImpact || exposure.complianceImpact.length === 0) return;

    exposure.complianceImpact.forEach(impact => {
      const framework = parseFramework(impact);

      if (!frameworkMap.has(framework)) {
        frameworkMap.set(framework, { exposures: [], requirements: new Set() });
      }

      const entry = frameworkMap.get(framework)!;
      // Avoid duplicate exposures in the same framework
      if (!entry.exposures.find(e => e.id === exposure.id)) {
        entry.exposures.push(exposure);
      }
      entry.requirements.add(impact);
    });
  });

  return frameworkMap;
}

function Compliance() {
  const navigate = useNavigate();
  const { isDemoMode, currentScan } = useAppContext();
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Get exposures from demo or real scan
  const exposures: Exposure[] = isDemoMode ? demoExposures : (currentScan?.exposures || []);

  // Group exposures by framework
  const frameworkGroups = useMemo(() => groupByFramework(exposures), [exposures]);

  // Calculate summary stats
  const totalNonCompliant = exposures.filter(e => e.complianceImpact && e.complianceImpact.length > 0).length;
  const frameworksAffected = frameworkGroups.size;
  const criticalNonCompliant = exposures.filter(
    e => e.complianceImpact && e.complianceImpact.length > 0 && e.severity === 'critical'
  ).length;

  // Get selected framework exposures
  const selectedFrameworkData = selectedFramework ? frameworkGroups.get(selectedFramework) : null;

  // Filter exposures based on search
  const filteredExposures = useMemo(() => {
    if (!selectedFrameworkData) return [];
    if (!searchTerm) return selectedFrameworkData.exposures;

    const term = searchTerm.toLowerCase();
    return selectedFrameworkData.exposures.filter(e =>
      e.title.toLowerCase().includes(term) ||
      e.description.toLowerCase().includes(term) ||
      e.location.toLowerCase().includes(term)
    );
  }, [selectedFrameworkData, searchTerm]);

  if (!isDemoMode && !currentScan) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <WarningAlt size={64} style={{ color: 'var(--cve-text-secondary)', marginBottom: '1rem' }} />
        <h2 style={{ marginBottom: '1rem' }}>No Scan Data Available</h2>
        <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '2rem' }}>
          Run a scan or enable demo mode to view compliance findings.
        </p>
        <Button kind="primary" onClick={() => navigate('/app/scan')}>
          <Add size={16} style={{ marginRight: '0.5rem' }} />
          Start New Scan
        </Button>
      </div>
    );
  }

  return (
    <div style={{ overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <Report size={28} style={{ color: '#0f62fe' }} />
          <h1 style={{ fontSize: '2rem', fontWeight: 300 }}>
            Compliance Dashboard
          </h1>
        </div>
        <p style={{ color: 'var(--cve-text-secondary)' }}>
          View non-compliant findings organized by regulatory framework
        </p>
      </div>

      {/* Summary Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Non-Compliant Findings
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: totalNonCompliant > 0 ? '#FA4D56' : '#42BE65' }}>
            {totalNonCompliant}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            exposures with compliance impact
          </div>
        </Tile>

        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Frameworks Affected
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600 }}>
            {frameworksAffected}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            regulatory frameworks
          </div>
        </Tile>

        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Critical Non-Compliant
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: criticalNonCompliant > 0 ? '#FA4D56' : '#42BE65' }}>
            {criticalNonCompliant}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            critical severity findings
          </div>
        </Tile>

        <Tile style={{
          padding: '1.25rem',
          backgroundColor: exposures.length === 0 ? '#161616' : (totalNonCompliant === 0 ? 'rgba(66, 190, 101, 0.1)' : 'rgba(250, 77, 86, 0.1)'),
          border: `1px solid ${exposures.length === 0 ? '#525252' : (totalNonCompliant === 0 ? '#42BE65' : '#FA4D56')}`
        }}>
          <div style={{ fontSize: '0.75rem', color: exposures.length === 0 ? 'var(--cve-text-secondary)' : (totalNonCompliant === 0 ? '#42BE65' : '#FA4D56'), marginBottom: '0.5rem' }}>
            Compliance Status
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {exposures.length === 0 ? (
              <>
                <WarningAlt size={24} style={{ color: '#F1C21B' }} />
                <span style={{ fontSize: '1.25rem', fontWeight: 600, color: '#F1C21B' }}>No Data</span>
              </>
            ) : totalNonCompliant === 0 ? (
              <>
                <CheckmarkFilled size={24} style={{ color: '#42BE65' }} />
                <span style={{ fontSize: '1.25rem', fontWeight: 600, color: '#42BE65' }}>Compliant</span>
              </>
            ) : (
              <>
                <CloseFilled size={24} style={{ color: '#FA4D56' }} />
                <span style={{ fontSize: '1.25rem', fontWeight: 600, color: '#FA4D56' }}>Issues Found</span>
              </>
            )}
          </div>
        </Tile>
      </div>

      {/* Frameworks Grid */}
      <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>Compliance Frameworks</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        {Object.entries(COMPLIANCE_FRAMEWORKS).map(([key, framework]) => {
          const frameworkData = frameworkGroups.get(key);
          const exposureCount = frameworkData?.exposures.length || 0;
          const requirements = frameworkData?.requirements || new Set();
          const hasCritical = frameworkData?.exposures.some(e => e.severity === 'critical');
          const hasHigh = frameworkData?.exposures.some(e => e.severity === 'high');

          return (
            <Tile
              key={key}
              style={{
                padding: '1.25rem',
                backgroundColor: '#161616',
                border: '1px solid #393939',
                cursor: exposureCount > 0 ? 'pointer' : 'default',
                opacity: exposureCount > 0 ? 1 : 0.6,
                transition: 'all 0.2s'
              }}
              onClick={() => exposureCount > 0 && setSelectedFramework(key)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '1.5rem' }}>{framework.icon}</span>
                  <div>
                    <div style={{ fontWeight: 600, color: framework.color }}>{framework.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                      {framework.fullName}
                    </div>
                  </div>
                </div>
                {exposureCount > 0 && (
                  <ChevronRight size={20} style={{ color: 'var(--cve-text-secondary)' }} />
                )}
              </div>

              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '2rem', fontWeight: 600, color: exposureCount > 0 ? '#FA4D56' : '#42BE65' }}>
                  {exposureCount}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                  non-compliant findings
                </div>
              </div>

              {exposureCount > 0 ? (
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {hasCritical && <Tag type="red" size="sm">Critical</Tag>}
                  {hasHigh && <Tag type="warm-gray" size="sm">High</Tag>}
                  <Tag type="outline" size="sm">{requirements.size} requirements</Tag>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <CheckmarkFilled size={16} style={{ color: '#42BE65' }} />
                  <span style={{ fontSize: '0.875rem', color: '#42BE65' }}>Compliant</span>
                </div>
              )}
            </Tile>
          );
        })}
      </div>

      {/* Non-Compliant Findings by Severity */}
      {totalNonCompliant > 0 && (
        <>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>All Non-Compliant Findings</h2>
          <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <Accordion>
              {['critical', 'high', 'medium', 'low'].map(severity => {
                const severityExposures = exposures.filter(
                  e => e.complianceImpact && e.complianceImpact.length > 0 && e.severity === severity
                );
                if (severityExposures.length === 0) return null;

                return (
                  <AccordionItem
                    key={severity}
                    title={
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Tag
                          type={severity === 'critical' ? 'red' : severity === 'high' ? 'warm-gray' : severity === 'medium' ? 'gray' : 'green'}
                          size="sm"
                        >
                          {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </Tag>
                        <span>{severityExposures.length} findings</span>
                      </div>
                    }
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '0.5rem 0' }}>
                      {severityExposures.slice(0, 10).map(exposure => {
                        const Icon = EXPOSURE_ICONS[exposure.type] || Security;
                        return (
                          <div
                            key={exposure.id}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '0.75rem',
                              padding: '0.75rem',
                              backgroundColor: '#262626',
                              borderRadius: '4px'
                            }}
                          >
                            <div style={{
                              width: 28,
                              height: 28,
                              borderRadius: 4,
                              backgroundColor: EXPOSURE_COLORS[exposure.type] || '#8A3FFC',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0
                            }}>
                              <Icon size={16} />
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontWeight: 500, marginBottom: '0.25rem' }}>{exposure.title}</div>
                              <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                                {exposure.location}
                              </div>
                              <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                                {exposure.complianceImpact?.map((impact, i) => (
                                  <Tag key={i} type="purple" size="sm">{impact}</Tag>
                                ))}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {severityExposures.length > 10 && (
                        <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.875rem', padding: '0.5rem' }}>
                          ...and {severityExposures.length - 10} more {severity} findings
                        </div>
                      )}
                    </div>
                  </AccordionItem>
                );
              })}
            </Accordion>
          </Tile>
        </>
      )}

      {/* Framework Detail Modal */}
      <Modal
        open={selectedFramework !== null}
        onRequestClose={() => {
          setSelectedFramework(null);
          setSearchTerm('');
        }}
        modalHeading={selectedFramework ? `${COMPLIANCE_FRAMEWORKS[selectedFramework as keyof typeof COMPLIANCE_FRAMEWORKS]?.name || selectedFramework} Non-Compliance` : ''}
        primaryButtonText="View in Exposures"
        secondaryButtonText="Close"
        onRequestSubmit={() => {
          navigate('/app/exposures');
          setSelectedFramework(null);
        }}
        size="lg"
      >
        {selectedFramework && selectedFrameworkData && (
          <div>
            <div style={{ marginBottom: '1.5rem' }}>
              <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
                {COMPLIANCE_FRAMEWORKS[selectedFramework as keyof typeof COMPLIANCE_FRAMEWORKS]?.description}
              </p>

              {/* Stats */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1rem' }}>
                <div style={{ padding: '0.75rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Total Findings</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>{selectedFrameworkData.exposures.length}</div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Critical</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600, color: '#FA4D56' }}>
                    {selectedFrameworkData.exposures.filter(e => e.severity === 'critical').length}
                  </div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>High</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600, color: '#FF832B' }}>
                    {selectedFrameworkData.exposures.filter(e => e.severity === 'high').length}
                  </div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Requirements</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>{selectedFrameworkData.requirements.size}</div>
                </div>
              </div>

              {/* Affected Requirements */}
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                  Affected Requirements
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {Array.from(selectedFrameworkData.requirements).map((req, i) => (
                    <Tag key={i} type="purple" size="sm">{req}</Tag>
                  ))}
                </div>
              </div>
            </div>

            {/* Search */}
            <div style={{ marginBottom: '1rem' }}>
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    placeholder="Search findings..."
                    onChange={(e: any) => setSearchTerm(e.target?.value || '')}
                  />
                </TableToolbarContent>
              </TableToolbar>
            </div>

            {/* Findings List */}
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {filteredExposures.map(exposure => {
                  const Icon = EXPOSURE_ICONS[exposure.type] || Security;
                  return (
                    <div
                      key={exposure.id}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '0.75rem',
                        padding: '0.75rem',
                        backgroundColor: '#262626',
                        borderRadius: '4px',
                        borderLeft: `3px solid ${SEVERITY_COLORS[exposure.severity]}`
                      }}
                    >
                      <div style={{
                        width: 28,
                        height: 28,
                        borderRadius: 4,
                        backgroundColor: EXPOSURE_COLORS[exposure.type] || '#8A3FFC',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0
                      }}>
                        <Icon size={16} />
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                          <Tag
                            type={exposure.severity === 'critical' ? 'red' : exposure.severity === 'high' ? 'warm-gray' : exposure.severity === 'medium' ? 'gray' : 'green'}
                            size="sm"
                          >
                            {exposure.severity}
                          </Tag>
                          <span style={{ fontWeight: 500 }}>{exposure.title}</span>
                        </div>
                        <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                          {exposure.location}
                        </div>
                        <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                          {exposure.description.slice(0, 150)}...
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

export default Compliance;
