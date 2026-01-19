import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Modal,
  Tag,
  Tile,
  ProgressBar,
  Accordion,
  AccordionItem
} from '@carbon/react';
import {
  ArrowRight,
  Security,
  Certificate,
  Password,
  SettingsCheck,
  Document,
  Code,
  WarningAlt,
  Add,
  Star,
  Checkmark
} from '@carbon/icons-react';
import { useAppContext } from '../App';
import { ExtendedRemediationGroup } from '../types';
import { demoExtendedScanResult, demoExposures, demoExtendedFinancialAnalysis } from '../data/demoData';

// Exposure type colors
const EXPOSURE_COLORS: Record<string, string> = {
  cve: '#FA4D56',
  certificate: '#8A3FFC',
  secret: '#FF832B',
  misconfiguration: '#1192E8',
  license: '#009D9A',
  'code-security': '#6929C4'
};

const EXPOSURE_ICONS: Record<string, typeof Security> = {
  cve: Security,
  certificate: Certificate,
  secret: Password,
  misconfiguration: SettingsCheck,
  license: Document,
  'code-security': Code
};

const SLA_COLORS = {
  overdue: '#FA4D56',
  due_soon: '#FF832B',
  on_track: '#42BE65'
};

// Calculate score improvement for a group
// Returns { current, improved, reduction, xpReward }
function calculateScoreImprovement(
  currentScore: number,
  riskReductionPercent: number
): { current: number; improved: number; reduction: number; xpReward: number } {
  // Risk reduction is a percentage (0-100) of how much this group reduces overall risk
  // Convert to actual score reduction (on 0-10 scale)
  const maxScore = 10;
  const reduction = (riskReductionPercent / 100) * maxScore;
  const improved = Math.max(0, Math.round((currentScore - reduction) * 10) / 10);
  const actualReduction = Math.round((currentScore - improved) * 10) / 10;

  // XP reward is based on score points reduced × 100
  // So reducing score by 1.5 points = 150 XP
  const xpReward = Math.round(actualReduction * 100);

  return {
    current: Math.round(currentScore * 10) / 10,
    improved,
    reduction: actualReduction,
    xpReward
  };
}

function RemediationGroups() {
  const navigate = useNavigate();
  const { isDemoMode, currentScan, recordFix, fixedGroupIds, markGroupFixed } = useAppContext();
  const [selectedGroup, setSelectedGroup] = useState<ExtendedRemediationGroup | null>(null);
  const [showServiceNowModal, setShowServiceNowModal] = useState(false);
  const [selectedForIncident, setSelectedForIncident] = useState<ExtendedRemediationGroup | null>(null);

  // Use fixedGroupIds from context (shared with Dashboard)

  // Get remediation groups from demo or real scan
  const remediationGroups: ExtendedRemediationGroup[] = isDemoMode
    ? (demoExtendedScanResult.remediationGroups || [])
    : (currentScan?.remediationGroups as ExtendedRemediationGroup[] || []);

  const financialImpact = isDemoMode ? demoExtendedFinancialAnalysis : null;

  // Get current exposure score from scan summary
  const summary = isDemoMode
    ? demoExtendedScanResult.summary
    : currentScan?.summary;
  const currentExposureScore = (summary as any)?.riskScore?.concert || (summary as any)?.overallRiskScore || 7.8;

  // Calculate totals
  const totalExposures = remediationGroups.reduce((sum, g) => sum + g.exposuresCount, 0);
  const totalRiskReduction = remediationGroups.reduce((sum, g) => sum + g.riskReduction, 0);
  const totalEffortHours = remediationGroups.reduce((sum, g) => sum + g.effortHours, 0);
  const overdueGroups = remediationGroups.filter(g => g.slaStatus === 'overdue').length;

  // Calculate overall score improvement if all groups fixed
  const overallScoreImprovement = calculateScoreImprovement(currentExposureScore, totalRiskReduction);

  // Get all exposures from demo or real scan
  const allExposures = isDemoMode ? demoExposures : (currentScan?.exposures || []);

  // Get exposures for a group
  const getGroupExposures = (group: ExtendedRemediationGroup) => {
    return allExposures.filter((e: any) => group.exposures.includes(e.id));
  };

  const handleCreateIncident = (group: ExtendedRemediationGroup) => {
    setSelectedForIncident(group);
    setShowServiceNowModal(true);
  };

  // Handle marking a group as fixed
  const handleMarkFixed = (group: ExtendedRemediationGroup, e: React.MouseEvent) => {
    e.stopPropagation();
    if (fixedGroupIds.has(group.id)) return;

    // Get exposures for this group and record each fix
    const groupExposures = getGroupExposures(group);
    groupExposures.forEach((exposure: any) => {
      recordFix(exposure.severity, exposure.type);
    });

    // Mark group as fixed in context (shared with Dashboard and ExposuresList)
    // Pass exposure IDs so they can be filtered from the exposures list
    markGroupFixed(group.id, group.riskReduction, group.exposures);
  };

  // Calculate total potential XP based on score reduction
  // Each point of score reduction = 100 XP
  const totalPotentialXP = remediationGroups
    .filter(g => !fixedGroupIds.has(g.id))
    .reduce((sum, g) => {
      const scoreImp = calculateScoreImprovement(currentExposureScore, g.riskReduction);
      return sum + scoreImp.xpReward;
    }, 0);

  if (!isDemoMode && !currentScan) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <WarningAlt size={64} style={{ color: 'var(--cve-text-secondary)', marginBottom: '1rem' }} />
        <h2 style={{ marginBottom: '1rem' }}>No Scan Data Available</h2>
        <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '2rem' }}>
          Run a scan or enable demo mode to view remediation groups.
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
        <h1 style={{ fontSize: '2rem', fontWeight: 300, marginBottom: '0.5rem' }}>
          Remediation Groups
        </h1>
        <p style={{ color: 'var(--cve-text-secondary)' }}>
          Prioritized action groups to efficiently reduce risk across all exposure types
        </p>
      </div>

      {/* Summary Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Action Groups
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600 }}>
            {remediationGroups.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            {overdueGroups > 0 && <span style={{ color: '#FA4D56' }}>{overdueGroups} overdue</span>}
          </div>
        </Tile>

        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Total Exposures
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600 }}>
            {totalExposures}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            across all groups
          </div>
        </Tile>

        {/* Score Improvement Tile - Prominent display of exposure score change */}
        <Tile style={{
          padding: '1.25rem',
          backgroundColor: 'rgba(66, 190, 101, 0.1)',
          border: '1px solid #42BE65'
        }}>
          <div style={{ fontSize: '0.75rem', color: '#42BE65', marginBottom: '0.5rem' }}>
            Exposure Score Impact
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.75rem', fontWeight: 600, color: 'var(--cve-text-secondary)', textDecoration: 'line-through' }}>
              {overallScoreImprovement.current}
            </span>
            <ArrowRight size={20} style={{ color: '#42BE65' }} />
            <span style={{ fontSize: '2rem', fontWeight: 700, color: '#42BE65' }}>
              {overallScoreImprovement.improved}
            </span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#42BE65' }}>
            -{overallScoreImprovement.reduction} points if all fixed
          </div>
        </Tile>

        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Total Effort
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600 }}>
            {totalEffortHours}h
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            estimated hours
          </div>
        </Tile>

        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            ROI if Fixed
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: '#42BE65' }}>
            {financialImpact?.roi || 0}x
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            ${(financialImpact?.totalRisk || 0).toFixed(1)}M risk avoided
          </div>
        </Tile>

        {/* Gamification XP Tile */}
        <Tile style={{
          padding: '1.25rem',
          backgroundColor: 'rgba(138, 63, 252, 0.1)',
          border: '1px solid #8A3FFC'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <Star size={16} style={{ color: '#8A3FFC' }} />
            <span style={{ fontSize: '0.75rem', color: '#8A3FFC' }}>Potential XP</span>
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: '#8A3FFC' }}>
            +{totalPotentialXP.toLocaleString()}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            {fixedGroupIds.size} of {remediationGroups.length} groups fixed
          </div>
        </Tile>
      </div>

      {/* Remediation Groups List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {remediationGroups
          .sort((a, b) => b.priority - a.priority)
          .map((group) => {
            const Icon = EXPOSURE_ICONS[group.exposureType] || Security;
            const scoreImp = calculateScoreImprovement(currentExposureScore, group.riskReduction);

            return (
              <Tile
                key={group.id}
                style={{
                  padding: 0,
                  backgroundColor: '#161616',
                  border: group.slaStatus === 'overdue' ? '1px solid #FA4D56' : '1px solid #393939',
                  cursor: 'pointer',
                  overflow: 'hidden'
                }}
                onClick={() => setSelectedGroup(group)}
              >
                <div style={{ display: 'flex' }}>
                  {/* Main Content */}
                  <div style={{ flex: 1, padding: '1.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
                      <div style={{
                        width: 32,
                        height: 32,
                        borderRadius: 4,
                        backgroundColor: EXPOSURE_COLORS[group.exposureType] || '#8A3FFC',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        <Icon size={18} />
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontWeight: 600 }}>{group.title}</span>
                          <Tag
                            type={group.slaStatus === 'overdue' ? 'red' : group.slaStatus === 'due_soon' ? 'warm-gray' : 'green'}
                            size="sm"
                          >
                            {group.slaStatus === 'overdue' ? 'Overdue' : group.slaStatus === 'due_soon' ? 'Due Soon' : 'On Track'}
                          </Tag>
                          <Tag type="outline" size="sm">
                            Priority {group.priority}
                          </Tag>
                        </div>
                        <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '500px' }}>
                          {group.description}
                        </div>
                      </div>
                    </div>

                    {/* Stats row */}
                    <div style={{ display: 'flex', gap: '2rem', marginTop: '1rem', flexWrap: 'wrap' }}>
                      <div>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase' }}>
                          Exposures
                        </div>
                        <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>
                          {group.exposuresCount}
                          {group.overdueCount > 0 && (
                            <span style={{ fontSize: '0.75rem', color: '#FA4D56', marginLeft: '0.5rem' }}>
                              ({group.overdueCount} overdue)
                            </span>
                          )}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '0.6875rem', color: '#42BE65', textTransform: 'uppercase' }}>
                          Score After Fix
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--cve-text-secondary)', textDecoration: 'line-through' }}>
                            {scoreImp.current}
                          </span>
                          <ArrowRight size={14} style={{ color: '#42BE65' }} />
                          <span style={{ fontSize: '1.25rem', fontWeight: 700, color: '#42BE65' }}>
                            {scoreImp.improved}
                          </span>
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase' }}>
                          Effort
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontSize: '1.25rem', fontWeight: 600 }}>{group.effortHours}h</span>
                          <Tag
                            type={group.effort === 'low' ? 'green' : group.effort === 'medium' ? 'warm-gray' : 'red'}
                            size="sm"
                          >
                            {group.effort}
                          </Tag>
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase' }}>
                          Compliance Impact
                        </div>
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                          {group.complianceImpact.slice(0, 3).map((impact, i) => (
                            <Tag key={i} type="purple" size="sm">{impact}</Tag>
                          ))}
                          {group.complianceImpact.length > 3 && (
                            <Tag type="outline" size="sm">+{group.complianceImpact.length - 3}</Tag>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Progress bar */}
                    <div style={{ marginTop: '1rem' }}>
                      <ProgressBar
                        label={`${scoreImp.reduction} points score reduction`}
                        value={scoreImp.reduction}
                        max={currentExposureScore}
                        size="small"
                      />
                    </div>

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                      {!fixedGroupIds.has(group.id) && (
                        <Button
                          kind="primary"
                          size="sm"
                          onClick={(e: React.MouseEvent) => handleMarkFixed(group, e)}
                          style={{ backgroundColor: '#42BE65', borderColor: '#42BE65' }}
                        >
                          <Checkmark size={16} style={{ marginRight: '0.25rem' }} />
                          Mark Fixed
                        </Button>
                      )}
                      <Button
                        kind={fixedGroupIds.has(group.id) ? 'ghost' : 'secondary'}
                        size="sm"
                        onClick={(e: React.MouseEvent) => {
                          e.stopPropagation();
                          handleCreateIncident(group);
                        }}
                      >
                        <Add size={16} style={{ marginRight: '0.25rem' }} />
                        Create Incident
                      </Button>
                    </div>
                  </div>

                  {/* Right Side: Big Score Drop Badge with XP */}
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '1.5rem',
                    minWidth: '140px',
                    backgroundColor: fixedGroupIds.has(group.id) ? 'rgba(66, 190, 101, 0.1)' : 'rgba(66, 190, 101, 0.05)',
                    borderLeft: '1px solid var(--cve-border)'
                  }}>
                    {!fixedGroupIds.has(group.id) ? (
                      <>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '0.25rem' }}>
                          Score Drop
                        </div>
                        <div style={{
                          fontSize: '2.5rem',
                          fontWeight: 700,
                          color: '#42BE65',
                          lineHeight: 1
                        }}>
                          -{scoreImp.reduction}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#42BE65', marginBottom: '0.75rem' }}>
                          points
                        </div>
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                          padding: '0.375rem 0.5rem',
                          backgroundColor: 'rgba(138, 63, 252, 0.2)',
                          borderRadius: '4px'
                        }}>
                          <Star size={12} style={{ color: '#8A3FFC' }} />
                          <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#8A3FFC' }}>
                            +{scoreImp.xpReward} XP
                          </span>
                        </div>
                      </>
                    ) : (
                      <>
                        <Checkmark size={32} style={{ color: '#42BE65', marginBottom: '0.5rem' }} />
                        <div style={{ fontSize: '1rem', fontWeight: 600, color: '#42BE65' }}>
                          Fixed!
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
                          +{scoreImp.xpReward} XP earned
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </Tile>
            );
          })}
      </div>

      {/* Group Detail Modal */}
      <Modal
        open={selectedGroup !== null}
        onRequestClose={() => setSelectedGroup(null)}
        modalHeading={selectedGroup?.title || ''}
        primaryButtonText="Create ServiceNow Incident"
        secondaryButtonText="Close"
        onRequestSubmit={() => {
          if (selectedGroup) handleCreateIncident(selectedGroup);
          setSelectedGroup(null);
        }}
        size="lg"
      >
        {selectedGroup && (() => {
          const selectedScoreImp = calculateScoreImprovement(currentExposureScore, selectedGroup.riskReduction);
          return (
            <div>
              <p style={{ marginBottom: '1.5rem', color: 'var(--cve-text-secondary)' }}>
                {selectedGroup.description}
              </p>

              {/* Group stats */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Exposures</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>{selectedGroup.exposuresCount}</div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: 'rgba(66, 190, 101, 0.15)', borderRadius: 4, border: '1px solid #42BE65' }}>
                  <div style={{ fontSize: '0.75rem', color: '#42BE65' }}>Score After Fix</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <span style={{ fontSize: '1rem', color: 'var(--cve-text-secondary)', textDecoration: 'line-through' }}>{selectedScoreImp.current}</span>
                    <ArrowRight size={12} style={{ color: '#42BE65' }} />
                    <span style={{ fontSize: '1.5rem', fontWeight: 700, color: '#42BE65' }}>{selectedScoreImp.improved}</span>
                  </div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: 'rgba(138, 63, 252, 0.15)', borderRadius: 4, border: '1px solid #8A3FFC' }}>
                  <div style={{ fontSize: '0.75rem', color: '#8A3FFC' }}>XP Reward</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600, color: '#8A3FFC' }}>+{selectedScoreImp.xpReward}</div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Effort</div>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>{selectedGroup.effortHours}h</div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>SLA Status</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 600, color: SLA_COLORS[selectedGroup.slaStatus] }}>
                    {selectedGroup.slaStatus === 'overdue' ? 'Overdue' : selectedGroup.slaStatus === 'due_soon' ? 'Due Soon' : 'On Track'}
                  </div>
                </div>
              </div>

              {/* Compliance Impact */}
              <div style={{ marginBottom: '1.5rem' }}>
                <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Compliance Impact</h4>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {selectedGroup.complianceImpact.map((impact, i) => (
                    <Tag key={i} type="purple" size="sm">{impact}</Tag>
                  ))}
                </div>
              </div>

              {/* Affected Exposures */}
              <div>
                <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Affected Exposures ({selectedGroup.exposuresCount})</h4>
                <Accordion>
                  {getGroupExposures(selectedGroup).slice(0, 10).map((exposure) => (
                    <AccordionItem key={exposure.id} title={
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Tag
                          type={exposure.severity === 'critical' ? 'red' : exposure.severity === 'high' ? 'warm-gray' : 'cool-gray'}
                          size="sm"
                        >
                          {exposure.severity}
                        </Tag>
                        <span>{exposure.title}</span>
                      </div>
                    }>
                      <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                        {exposure.description}
                      </p>
                      <p style={{ fontSize: '0.8125rem', marginTop: '0.5rem' }}>
                        <strong>Location:</strong> {exposure.location}
                      </p>
                    </AccordionItem>
                  ))}
                </Accordion>
                {selectedGroup.exposuresCount > 10 && (
                  <p style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginTop: '1rem' }}>
                    ...and {selectedGroup.exposuresCount - 10} more exposures
                  </p>
                )}
              </div>
            </div>
          );
        })()}
      </Modal>

      {/* ServiceNow Modal */}
      <Modal
        open={showServiceNowModal}
        onRequestClose={() => setShowServiceNowModal(false)}
        modalHeading="Create ServiceNow Incident"
        primaryButtonText="Create Incident"
        secondaryButtonText="Cancel"
        onRequestSubmit={() => {
          // TODO: Implement ServiceNow integration
          alert('ServiceNow integration coming soon! Configure in Settings.');
          setShowServiceNowModal(false);
        }}
        size="md"
      >
        {selectedForIncident && (
          <div>
            <p style={{ marginBottom: '1.5rem' }}>
              This will create a ServiceNow incident for the remediation group:
            </p>
            <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4, marginBottom: '1rem' }}>
              <h4 style={{ marginBottom: '0.5rem' }}>{selectedForIncident.title}</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                {selectedForIncident.exposuresCount} exposures | {selectedForIncident.effortHours} hours estimated
              </p>
            </div>
            <div style={{
              padding: '1rem',
              backgroundColor: '#262626',
              borderRadius: 4,
              border: '1px solid #525252'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <WarningAlt size={16} style={{ color: '#F1C21B' }} />
                <span style={{ fontWeight: 600 }}>ServiceNow Not Configured</span>
              </div>
              <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                To create incidents, please configure your ServiceNow credentials in{' '}
                <Button
                  kind="ghost"
                  size="sm"
                  style={{ padding: 0 }}
                  onClick={() => {
                    setShowServiceNowModal(false);
                    navigate('/app/settings');
                  }}
                >
                  Settings
                </Button>
              </p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

export default RemediationGroups;
