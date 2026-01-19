import { useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Button,
  Modal,
  Tag,
  Tile,
  Search,
  ContentSwitcher,
  Switch
} from '@carbon/react';
import { Add, Warning, Information, Filter, ArrowRight, Upload, Renew } from '@carbon/icons-react';
import { useAppContext } from '../App';
import { CVE, NonCVEExposure } from '../types';
import { BarChart, Bar, XAxis, YAxis, Tooltip as ChartTooltip, ResponsiveContainer, Cell } from 'recharts';
import { demoNonCVEExposures } from '../data/demoData';

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

// Progress bar for findings
function FindingsProgressBar({ value, max, color = '#FA4D56' }: { value: number; max: number; color?: string }) {
  const width = max > 0 ? (value / max) * 100 : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <span style={{ fontSize: '0.8125rem', minWidth: '70px' }}>{value} findings</span>
      <div style={{ width: '100px', height: '4px', backgroundColor: '#393939', borderRadius: '2px' }}>
        <div style={{ width: `${width}%`, height: '100%', backgroundColor: color, borderRadius: '2px' }} />
      </div>
    </div>
  );
}

// Stat card matching Concert style
function StatCard({
  value,
  total,
  label,
  percentage,
  color = '#FA4D56',
  isSelected = false,
  onClick
}: {
  value: number;
  total: number;
  label: string;
  percentage: string;
  color?: string;
  isSelected?: boolean;
  onClick?: () => void;
}) {
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
        gap: '0.75rem',
        position: 'relative'
      }}
    >
      {isSelected && (
        <div style={{ position: 'absolute', top: '0.5rem', right: '0.5rem' }}>
          <div style={{ width: 12, height: 12, borderRadius: '50%', backgroundColor: color, border: '2px solid #fff' }} />
        </div>
      )}
      <CircularProgress value={value} total={total} color={color} />
      <div>
        <div style={{ fontSize: '1.125rem', fontWeight: 600 }}>
          {value} <span style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>({percentage})</span>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>{label}</div>
      </div>
    </div>
  );
}

function CVEList() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { currentScan, isDemoMode } = useAppContext();

  const [activeTab, setActiveTab] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<string>(searchParams.get('filter') || 'all');
  const [selectedCVE, setSelectedCVE] = useState<CVE | null>(null);

  const cves = currentScan?.cves || [];
  const exposures = isDemoMode ? demoNonCVEExposures : (currentScan?.nonCVEExposures || []);

  // Count stats
  const priority1Count = cves.filter(c => c.severity === 'critical' || c.severity === 'high').length;
  const kevCount = cves.filter(c => c.cisaKEV).length;
  const totalCVEs = cves.length;

  // Filter CVEs
  const filteredCVEs = useMemo(() => {
    return cves.filter((cve) => {
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        if (!cve.id.toLowerCase().includes(term) && !cve.component.toLowerCase().includes(term)) {
          return false;
        }
      }
      if (selectedFilter === 'critical') return cve.severity === 'critical' || cve.severity === 'high';
      if (selectedFilter === 'kev') return cve.cisaKEV;
      if (selectedFilter === 'sca') return cve.sourceType === 'sca';
      if (selectedFilter === 'sast') return cve.sourceType === 'sast';
      if (selectedFilter === 'container') return cve.sourceType === 'container';
      if (selectedFilter === 'iac') return cve.sourceType === 'iac';
      return true;
    });
  }, [cves, searchTerm, selectedFilter]);

  // Top CVEs for bar chart
  const topCVEsData = useMemo(() => {
    return cves
      .filter(c => c.severity === 'critical' || c.severity === 'high')
      .sort((a, b) => (b.riskScore?.concert || 0) - (a.riskScore?.concert || 0))
      .slice(0, 12)
      .map(cve => ({
        name: cve.id.length > 13 ? cve.id.substring(0, 11) + '...' : cve.id,
        findings: Math.floor((cve.riskScore?.concert || 5) * 8),
        priority: cve.severity === 'critical' ? 1 : 2
      }));
  }, [cves]);

  // Max findings for progress bar scaling
  const maxFindings = Math.max(...filteredCVEs.map(c => Math.floor((c.riskScore?.concert || 5) * 8)), 1);

  if (!currentScan) {
    return (
      <div className="empty-state">
        <Warning size={64} />
        <h3>No Scan Data Available</h3>
        <p>Start a new scan or try demo mode to see CVEs.</p>
        <Button kind="primary" renderIcon={Add} onClick={() => navigate('/app/scan')}>
          Start New Scan
        </Button>
      </div>
    );
  }

  return (
    <div>
      {/* Page Title */}
      <h1 style={{ fontSize: '1.75rem', marginBottom: '1.5rem' }}>Vulnerability</h1>

      {/* Tab Navigation */}
      <div style={{ marginBottom: '1.5rem' }}>
        <ContentSwitcher onChange={({ index }) => setActiveTab(index as number)} selectedIndex={activeTab} size="lg">
          <Switch name="cves" text={`CVEs ${totalCVEs}`} />
          <Switch name="exposures" text={`Exposures ${exposures.length}`} />
          <Switch name="auto-remediate" text="Auto-remediate" />
        </ContentSwitcher>
      </div>

      {activeTab === 0 && (
        <>
          {/* Main stats row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '1rem', marginBottom: '1.5rem' }}>
            {/* Left: Total CVEs card */}
            <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #525252' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
                Total unique CVEs
              </div>
              <div style={{ fontSize: '2.5rem', fontWeight: 300 }}>
                {totalCVEs} <span style={{ fontSize: '1rem', color: 'var(--cve-text-secondary)' }}>({totalCVEs * 4} findings)</span>
              </div>
            </Tile>

            {/* Right: Bar chart */}
            <Tile style={{ padding: '1rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.875rem' }}>CVEs with the highest priority findings</span>
                <Renew size={16} style={{ color: 'var(--cve-text-secondary)', cursor: 'pointer' }} />
              </div>
              <div style={{ height: '120px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topCVEsData} layout="horizontal">
                    <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#c6c6c6', fontSize: 8 }} angle={-45} textAnchor="end" height={50} />
                    <YAxis axisLine={false} tickLine={false} tick={{ fill: '#c6c6c6', fontSize: 9 }} width={30} />
                    <ChartTooltip contentStyle={{ backgroundColor: '#262626', border: '1px solid #525252', borderRadius: '4px' }} />
                    <Bar dataKey="findings" radius={[2, 2, 0, 0]}>
                      {topCVEsData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.priority === 1 ? '#FA4D56' : '#FF832B'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '0.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <div style={{ width: 8, height: 8, borderRadius: 1, backgroundColor: '#FA4D56' }} />
                  <span style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)' }}>Priority 1</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <div style={{ width: 8, height: 8, borderRadius: 1, backgroundColor: '#FF832B' }} />
                  <span style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)' }}>Priority 2</span>
                </div>
              </div>
            </Tile>
          </div>

          {/* Stats grid 2x2 */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '1.5rem' }}>
            <StatCard
              value={priority1Count}
              total={totalCVEs}
              percentage={`${totalCVEs > 0 ? Math.round((priority1Count / totalCVEs) * 100) : 0}%`}
              label="CVEs with priority 1 findings"
              color="#FA4D56"
              isSelected={selectedFilter === 'critical'}
              onClick={() => setSelectedFilter(selectedFilter === 'critical' ? 'all' : 'critical')}
            />
            <StatCard
              value={kevCount}
              total={totalCVEs}
              percentage={`${totalCVEs > 0 ? Math.round((kevCount / totalCVEs) * 100) : 0}%`}
              label="CISA KEV vulnerabilities"
              color="#FF832B"
              isSelected={selectedFilter === 'kev'}
              onClick={() => setSelectedFilter(selectedFilter === 'kev' ? 'all' : 'kev')}
            />
            <StatCard
              value={totalCVEs}
              total={totalCVEs}
              percentage="100%"
              label="CVEs with open findings"
              color="#FA4D56"
            />
            <StatCard
              value={cves.filter(c => c.slaStatus === 'overdue').length}
              total={totalCVEs}
              percentage={`${totalCVEs > 0 ? Math.round((cves.filter(c => c.slaStatus === 'overdue').length / totalCVEs) * 100) : 0}%`}
              label="CVEs with overdue SLA"
              color={cves.filter(c => c.slaStatus === 'overdue').length > 0 ? '#FA4D56' : '#42BE65'}
            />
          </div>

          {/* Search and filter bar */}
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', alignItems: 'center' }}>
            <Search
              placeholder="Find by CVE"
              labelText=""
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ maxWidth: '400px' }}
            />
            <Button kind="ghost" size="sm" hasIconOnly renderIcon={Filter} iconDescription="Filter" />
            <Button kind="ghost" size="sm" hasIconOnly renderIcon={Renew} iconDescription="Refresh" />
            <div style={{ marginLeft: 'auto' }}>
              <Button kind="primary" size="sm" renderIcon={Upload}>
                Upload a vulnerability scan
              </Button>
            </div>
          </div>

          {/* Active filters */}
          {selectedFilter !== 'all' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>Filtered by</span>
              <Tag type="blue" filter onClose={() => setSelectedFilter('all')}>
                {selectedFilter === 'critical' ? 'CVEs with priority 1 findings' :
                 selectedFilter === 'kev' ? 'CISA KEV' : selectedFilter.toUpperCase()}
              </Tag>
              <Button kind="ghost" size="sm" onClick={() => setSelectedFilter('all')}>Reset filters</Button>
            </div>
          )}

          {/* CVE Table */}
          <Tile style={{ padding: 0, backgroundColor: '#161616', border: '1px solid #393939' }}>
            {/* Table Header */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '180px 100px 180px 180px 1fr',
              padding: '0.75rem 1rem',
              borderBottom: '1px solid #393939',
              backgroundColor: '#262626',
              fontSize: '0.8125rem',
              fontWeight: 500
            }}>
              <div>CVE</div>
              <div>CVSS score</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                Highest-finding priority <ArrowRight size={12} style={{ transform: 'rotate(90deg)' }} />
              </div>
              <div>Highest risk score</div>
              <div>Open findings</div>
            </div>

            {/* Table Rows */}
            <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
              {filteredCVEs.slice(0, 50).map((cve) => (
                <div
                  key={cve.id}
                  onClick={() => setSelectedCVE(cve)}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '180px 100px 180px 180px 1fr',
                    padding: '0.75rem 1rem',
                    borderBottom: '1px solid #262626',
                    cursor: 'pointer',
                    fontSize: '0.8125rem',
                    alignItems: 'center'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#262626'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <div style={{ color: '#78a9ff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {cve.id}
                    {cve.cisaKEV && <span style={{ color: '#FA4D56', fontSize: '0.6875rem', fontWeight: 600 }}>KEV</span>}
                  </div>
                  <div>{cve.cvss?.toFixed(1)}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ color: cve.severity === 'critical' ? '#FA4D56' : '#FF832B' }}>⬆</span>
                    Priority {cve.severity === 'critical' ? '1' : cve.severity === 'high' ? '2' : '3'}
                  </div>
                  <div>{cve.riskScore?.concert?.toFixed(1) || '-'}</div>
                  <FindingsProgressBar
                    value={Math.floor((cve.riskScore?.concert || 5) * 8)}
                    max={maxFindings}
                    color={cve.severity === 'critical' ? '#FA4D56' : cve.severity === 'high' ? '#FF832B' : '#F1C21B'}
                  />
                </div>
              ))}
            </div>
          </Tile>

          {filteredCVEs.length > 50 && (
            <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--cve-text-secondary)', fontSize: '0.8125rem' }}>
              Showing 50 of {filteredCVEs.length} CVEs
            </div>
          )}
        </>
      )}

      {activeTab === 1 && <ExposuresTab exposures={exposures} />}

      {activeTab === 2 && (
        <div className="empty-state" style={{ padding: '3rem' }}>
          <h3>Auto-Remediate</h3>
          <p style={{ color: 'var(--cve-text-secondary)' }}>
            Automated remediation suggestions will appear here.
          </p>
          <Button kind="primary" onClick={() => navigate('/app/remediation')}>
            View Remediation Groups
          </Button>
        </div>
      )}

      {/* CVE Detail Modal */}
      <Modal
        open={!!selectedCVE}
        onRequestClose={() => setSelectedCVE(null)}
        modalHeading={selectedCVE?.id || ''}
        passiveModal
        size="lg"
      >
        {selectedCVE && <CVEDetail cve={selectedCVE} />}
      </Modal>
    </div>
  );
}

function ExposuresTab({ exposures }: { exposures: NonCVEExposure[] }) {
  const [selectedFilter, setSelectedFilter] = useState<string>('all');

  const priority1Exposures = exposures.filter(e => e.severity === 'critical');
  const publicAccessExposures = exposures.filter(e => e.category === 'Network Security' || e.category === 'Data Security');
  const withSolutions = exposures.filter(e => e.recommendation);

  const filteredExposures = selectedFilter === 'all' ? exposures :
    selectedFilter === 'priority1' ? priority1Exposures :
    selectedFilter === 'public' ? publicAccessExposures : exposures;

  return (
    <>
      {/* Total exposures card */}
      <Tile style={{ padding: '1.25rem', marginBottom: '1rem', backgroundColor: '#161616', border: '1px solid #525252' }}>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
          Total exposures
        </div>
        <div style={{ fontSize: '2.5rem', fontWeight: 300, marginBottom: '0.5rem' }}>
          {exposures.length}
        </div>
        <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
          Total blast radius: <span style={{ color: '#78a9ff' }}>{exposures.length}</span> applications,{' '}
          <span style={{ color: '#78a9ff' }}>1</span> environments,{' '}
          <span style={{ color: '#78a9ff' }}>{publicAccessExposures.length}</span> public access points
        </div>
      </Tile>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <StatCard
          value={priority1Exposures.length}
          total={exposures.length}
          percentage={`${exposures.length > 0 ? Math.round((priority1Exposures.length / exposures.length) * 100) : 0}%`}
          label="Priority 1 exposures"
          color="#FA4D56"
          isSelected={selectedFilter === 'priority1'}
          onClick={() => setSelectedFilter(selectedFilter === 'priority1' ? 'all' : 'priority1')}
        />
        <StatCard
          value={publicAccessExposures.length}
          total={exposures.length}
          percentage={`${exposures.length > 0 ? Math.round((publicAccessExposures.length / exposures.length) * 100) : 0}%`}
          label="Exposures impacting public access points"
          color="#FF832B"
          isSelected={selectedFilter === 'public'}
          onClick={() => setSelectedFilter(selectedFilter === 'public' ? 'all' : 'public')}
        />
        <StatCard
          value={0}
          total={exposures.length}
          percentage="0%"
          label="Exposures with open tickets"
          color="#42BE65"
        />
        <StatCard
          value={withSolutions.length}
          total={exposures.length}
          percentage={`${exposures.length > 0 ? Math.round((withSolutions.length / exposures.length) * 100) : 0}%`}
          label="Exposures with solutions"
          color="#42BE65"
        />
      </div>

      {/* Exposures table */}
      <Tile style={{ padding: 0, backgroundColor: '#161616', border: '1px solid #393939' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '250px 150px 150px 150px 1fr',
          padding: '0.75rem 1rem',
          borderBottom: '1px solid #393939',
          backgroundColor: '#262626',
          fontSize: '0.8125rem',
          fontWeight: 500
        }}>
          <div>Rule</div>
          <div>Highest-finding priority</div>
          <div>Scan type</div>
          <div>Found on</div>
          <div>Open findings</div>
        </div>

        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          {filteredExposures.map((exposure) => (
            <div
              key={exposure.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '250px 150px 150px 150px 1fr',
                padding: '0.75rem 1rem',
                borderBottom: '1px solid #262626',
                fontSize: '0.8125rem',
                alignItems: 'center'
              }}
            >
              <div style={{ color: '#78a9ff' }}>{exposure.title}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: exposure.severity === 'critical' ? '#FA4D56' : '#FF832B' }}>⬆</span>
                Priority {exposure.severity === 'critical' ? '1' : exposure.severity === 'high' ? '2' : '3'}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <span style={{ color: 'var(--cve-text-secondary)' }}>⟳</span>
                {exposure.type === 'misconfiguration' ? 'IaC scan' : 'SAST'}
              </div>
              <div style={{ color: 'var(--cve-text-secondary)' }}>
                {new Date().toLocaleDateString()}
              </div>
              <FindingsProgressBar
                value={Math.floor(exposure.riskScore * 2)}
                max={20}
                color={exposure.severity === 'critical' ? '#FA4D56' : '#FF832B'}
              />
            </div>
          ))}
        </div>
      </Tile>
    </>
  );
}

function CVEDetail({ cve }: { cve: CVE }) {
  return (
    <div>
      <div style={{ marginBottom: '1rem' }}>
        <Tag type={cve.severity === 'critical' ? 'red' : cve.severity === 'high' ? 'magenta' : 'gray'}>
          {cve.severity}
        </Tag>
        <span style={{ marginLeft: '0.5rem', color: 'var(--cve-text-secondary)' }}>
          CVSS: {cve.cvss?.toFixed(1)}
        </span>
      </div>

      {cve.cisaKEV && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.75rem',
          backgroundColor: 'rgba(250, 77, 86, 0.1)',
          border: '1px solid #FA4D56',
          borderRadius: '4px',
          marginBottom: '1rem'
        }}>
          <Warning size={20} style={{ color: '#FA4D56' }} />
          <span style={{ color: '#FA4D56', fontWeight: 600 }}>
            CISA Known Exploited Vulnerability
          </span>
        </div>
      )}

      <div style={{ marginBottom: '1rem' }}>
        <h4 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Information size={16} />
          Component
        </h4>
        <p>
          <strong>{cve.component}</strong> version {cve.version}
          {cve.fixedVersion && (
            <span style={{ color: '#42BE65', marginLeft: '1rem' }}>
              Fix available: {cve.fixedVersion}
            </span>
          )}
        </p>
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <h4 style={{ marginBottom: '0.5rem' }}>Description</h4>
        <p style={{ color: 'var(--cve-text-secondary)', lineHeight: 1.6 }}>{cve.description}</p>
      </div>

      {cve.complianceImpact && cve.complianceImpact.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <h4 style={{ marginBottom: '0.5rem' }}>Compliance Impact</h4>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {cve.complianceImpact.map((impact, index) => (
              <Tag key={index} type="purple">{impact}</Tag>
            ))}
          </div>
        </div>
      )}

      {cve.slaDeadline && (
        <div>
          <h4 style={{ marginBottom: '0.5rem' }}>SLA Deadline</h4>
          <p>
            <span className={cve.slaStatus === 'overdue' ? 'text-critical' : cve.slaStatus === 'due_soon' ? 'text-high' : 'text-low'}>
              {cve.slaDeadline}
            </span>
            {cve.daysRemaining !== undefined && (
              <span style={{ marginLeft: '0.5rem', color: 'var(--cve-text-secondary)' }}>
                ({cve.daysRemaining > 0 ? `${cve.daysRemaining} days remaining` : `${Math.abs(cve.daysRemaining)} days overdue`})
              </span>
            )}
          </p>
        </div>
      )}
    </div>
  );
}

export default CVEList;
