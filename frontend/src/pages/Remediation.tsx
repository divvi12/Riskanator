import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Tile,
  Tag,
  Accordion,
  AccordionItem,
  RadioButtonGroup,
  RadioButton,
  Dropdown
} from '@carbon/react';
import { Add, Warning, Time, Copy, ArrowRight } from '@carbon/icons-react';
import { useAppContext } from '../App';
import { RemediationGroup, ExtendedRemediationGroup } from '../types';

// Union type for remediation groups
type AnyRemediationGroup = RemediationGroup | ExtendedRemediationGroup;

// Helper to get exposure/CVE count from either type
function getExposureCount(group: AnyRemediationGroup): number {
  return 'cvesCount' in group ? group.cvesCount : group.exposuresCount;
}

// Helper to get exposure/CVE IDs from either type
function getExposureIds(group: AnyRemediationGroup): string[] {
  return 'cves' in group ? group.cves : group.exposures;
}

// Calculate score improvement for a group
function calculateScoreImprovement(
  currentScore: number,
  riskReduction: number,
  maxScore: number = 10
): { current: number; improved: number } {
  // riskReduction is in points (0-100 scale typically)
  // Convert to score scale (0-10)
  const improvement = (riskReduction / 100) * maxScore;
  const improved = Math.max(0, currentScore - improvement);
  return {
    current: Math.round(currentScore * 10) / 10,
    improved: Math.round(improved * 10) / 10
  };
}

function Remediation() {
  const navigate = useNavigate();
  const { currentScan, applicationContext } = useAppContext();

  const [groupBy, setGroupBy] = useState<'fixes' | 'impact' | 'component'>('fixes');
  const [sortBy, setSortBy] = useState<string>('risk');

  const remediationGroups = currentScan?.remediationGroups || [];

  // Sort groups
  const sortedGroups = [...remediationGroups].sort((a, b) => {
    switch (sortBy) {
      case 'risk':
        return b.riskReduction - a.riskReduction;
      case 'sla':
        const slaOrder = { overdue: 0, due_soon: 1, on_track: 2 };
        return slaOrder[a.slaStatus] - slaOrder[b.slaStatus];
      case 'effort':
        const effortOrder = { low: 0, medium: 1, high: 2 };
        return effortOrder[a.effort] - effortOrder[b.effort];
      default:
        return b.priority - a.priority;
    }
  });

  // Get current scores from scan summary
  const summary = currentScan?.summary;
  const currentExposureScore = (summary as any)?.riskScore?.concert || (summary as any)?.overallRiskScore || 5;
  const currentConcertScore = (summary as any)?.riskScore?.concert || 5;
  const selectedFormula = applicationContext?.formula || 'concert';

  // Calculate total potential improvement
  const totalRiskReduction = remediationGroups.reduce((sum, g) => sum + g.riskReduction, 0);
  const potentialImprovement = calculateScoreImprovement(currentExposureScore, totalRiskReduction);

  if (!currentScan) {
    return (
      <div className="empty-state">
        <Warning size={64} />
        <h3>No Scan Data Available</h3>
        <p>Start a new scan or try demo mode to see prioritized remediation.</p>
        <Button kind="primary" renderIcon={Add} onClick={() => navigate('/app/scan')}>
          Start New Scan
        </Button>
      </div>
    );
  }

  if (remediationGroups.length === 0) {
    return (
      <div className="empty-state">
        <Warning size={64} />
        <h3>No Prioritized Actions</h3>
        <p>No exposures found that can be grouped for remediation.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <div>
          <h1 style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>Prioritized Remediation</h1>
          <p style={{ color: 'var(--cve-text-secondary)' }}>
            {remediationGroups.length} action groups prioritized by impact
          </p>
        </div>
      </div>

      {/* Filters */}
      <div
        style={{
          display: 'flex',
          gap: '2rem',
          marginBottom: '1.5rem',
          alignItems: 'flex-end',
          flexWrap: 'wrap'
        }}
      >
        <RadioButtonGroup
          legendText="Group By"
          name="group-by"
          valueSelected={groupBy}
          onChange={(value) => setGroupBy(value as typeof groupBy)}
        >
          <RadioButton labelText="Fixes" value="fixes" />
          <RadioButton labelText="Impact" value="impact" />
          <RadioButton labelText="Component" value="component" />
        </RadioButtonGroup>

        <Dropdown
          id="sort-by"
          titleText="Sort By"
          label="Score Impact"
          items={[
            { id: 'risk', text: 'Score Impact' },
            { id: 'sla', text: 'SLA Status' },
            { id: 'effort', text: 'Effort (Low First)' }
          ]}
          itemToString={(item) => item?.text || ''}
          selectedItem={{ id: sortBy, text: 'Score Impact' }}
          onChange={({ selectedItem }) => setSortBy(selectedItem?.id || 'risk')}
        />
      </div>

      {/* Summary Stats */}
      <div className="dashboard-grid" style={{ marginBottom: '1.5rem' }}>
        <Tile className="metric-card">
          <div className="metric-label">Total Exposures Covered</div>
          <div className="metric-value">
            {remediationGroups.reduce((sum, g) => sum + getExposureCount(g), 0)}
          </div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label">Exposure Score Improvement</div>
          <div className="metric-value" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ color: 'var(--cve-text-secondary)' }}>{potentialImprovement.current}</span>
            <ArrowRight size={16} style={{ color: '#42BE65' }} />
            <span style={{ color: '#42BE65' }}>{potentialImprovement.improved}</span>
          </div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label">Estimated Effort</div>
          <div className="metric-value">
            {remediationGroups.reduce((sum, g) => sum + g.effortHours, 0)}h
          </div>
        </Tile>
        <Tile className="metric-card">
          <div className="metric-label">Groups with Overdue SLA</div>
          <div className="metric-value" style={{ color: remediationGroups.some(g => g.slaStatus === 'overdue') ? '#FA4D56' : '#42BE65' }}>
            {remediationGroups.filter(g => g.slaStatus === 'overdue').length}
          </div>
        </Tile>
      </div>

      {/* Remediation Groups */}
      <div className="cve-grid">
        {sortedGroups.map((group) => (
          <RemediationCard
            key={group.id}
            group={group}
            currentExposureScore={currentExposureScore}
            currentConcertScore={currentConcertScore}
            showConcertScore={selectedFormula === 'concert'}
          />
        ))}
      </div>
    </div>
  );
}

function RemediationCard({
  group,
  currentExposureScore
}: {
  group: AnyRemediationGroup;
  currentExposureScore: number;
  currentConcertScore: number;
  showConcertScore: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  const handleCopyCommand = () => {
    if (group.fixCommand) {
      navigator.clipboard.writeText(group.fixCommand);
    }
  };

  // Calculate score improvements for this group
  const exposureImprovement = calculateScoreImprovement(currentExposureScore, group.riskReduction);
  const scoreReduction = Math.round((exposureImprovement.current - exposureImprovement.improved) * 10) / 10;

  return (
    <Tile className="cve-card" style={{ padding: 0 }}>
      <div style={{ display: 'flex' }}>
        {/* Main Content */}
        <div style={{ flex: 1, padding: '1rem' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>{group.title}</h3>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <Tag type={getEffortTagType(group.effort)}>{group.effort} effort</Tag>
                <Tag type="gray">{getExposureCount(group)} exposures</Tag>
                {'targetVersion' in group && group.targetVersion && <Tag type="blue">Target: {group.targetVersion}</Tag>}
              </div>
            </div>
            <SLABadge status={group.slaStatus} overdueCount={group.overdueCount} dueSoonCount={group.dueSoonCount} />
          </div>

          {/* Score Details */}
          <div style={{ display: 'flex', gap: '2rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Score After Fix</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '1.125rem', fontWeight: 600 }}>
                <span style={{ color: 'var(--cve-text-secondary)', textDecoration: 'line-through' }}>{exposureImprovement.current}</span>
                <ArrowRight size={14} style={{ color: '#42BE65' }} />
                <span style={{ color: '#42BE65' }}>{exposureImprovement.improved}</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Effort</div>
              <div style={{ fontSize: '1.125rem', fontWeight: 600 }}>{group.effortHours}h</div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Priority</div>
              <div style={{ fontSize: '1.125rem', fontWeight: 600 }}>#{group.priority}</div>
            </div>
          </div>

        {/* Compliance Impact */}
        {group.complianceImpact.length > 0 && (
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
              Compliance Impact
            </div>
            <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
              {group.complianceImpact.map((impact, index) => (
                <Tag key={index} type="purple" size="sm">
                  {impact}
                </Tag>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Button kind="primary" size="sm" disabled>
            Get AI Plan
          </Button>
          <Button kind="secondary" size="sm" disabled>
            Create Incident
          </Button>
          {group.fixCommand && (
            <Button kind="ghost" size="sm" renderIcon={Copy} onClick={handleCopyCommand}>
              Copy Command
            </Button>
          )}
        </div>
        </div>

        {/* Big Score Reduction Badge - Gamified */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '1.5rem',
          minWidth: '120px',
          backgroundColor: 'rgba(66, 190, 101, 0.1)',
          borderLeft: '1px solid var(--cve-border)'
        }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '0.25rem' }}>
            Score Drop
          </div>
          <div style={{
            fontSize: '2.5rem',
            fontWeight: 700,
            color: '#42BE65',
            lineHeight: 1
          }}>
            -{scoreReduction}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#42BE65', marginTop: '0.25rem' }}>
            points
          </div>
        </div>
      </div>

      {/* Expandable Details */}
      <Accordion>
        <AccordionItem title="View Details" open={expanded} onClick={() => setExpanded(!expanded)}>
          <div style={{ padding: '0.5rem' }}>
            {group.fixCommand && (
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                  Fix Command
                </div>
                <code
                  style={{
                    display: 'block',
                    padding: '0.75rem',
                    backgroundColor: 'var(--cve-background)',
                    borderRadius: '4px',
                    fontSize: '0.875rem'
                  }}
                >
                  {group.fixCommand}
                </code>
              </div>
            )}

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                Exposures Addressed ({getExposureIds(group).length})
              </div>
              <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                {getExposureIds(group).map((expId) => (
                  <Tag key={expId} type="gray" size="sm">
                    {expId}
                  </Tag>
                ))}
              </div>
            </div>
          </div>
        </AccordionItem>
      </Accordion>
    </Tile>
  );
}

function SLABadge({
  status,
  overdueCount,
  dueSoonCount
}: {
  status: 'overdue' | 'due_soon' | 'on_track';
  overdueCount: number;
  dueSoonCount: number;
}) {
  if (status === 'overdue') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#FA4D56' }}>
        <Warning size={16} />
        <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>
          {overdueCount} overdue
        </span>
      </div>
    );
  }

  if (status === 'due_soon') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#FF832B' }}>
        <Time size={16} />
        <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>
          {dueSoonCount} due soon
        </span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#42BE65' }}>
      <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>On track</span>
    </div>
  );
}

function getEffortTagType(effort: 'low' | 'medium' | 'high'): 'green' | 'gray' | 'red' {
  switch (effort) {
    case 'low':
      return 'green';
    case 'medium':
      return 'gray';
    case 'high':
      return 'red';
  }
}

export default Remediation;
