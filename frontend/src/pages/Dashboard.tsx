import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Tile, Tag, ProgressBar } from '@carbon/react';
import { Add, WarningAlt, ArrowRight, Time, Security, Certificate, SettingsCheck, Information, Trophy, Fire, Star, Checkmark } from '@carbon/icons-react';
import { useAppContext } from '../App';
import { useNotifications } from '../components/NotificationProvider';
import { demoExtendedScanResult } from '../data/demoData';
import { PageLoadingSkeleton } from '../components/SkeletonLoaders';
import { LEVEL_THRESHOLDS } from '../types';
import { ScoreInfoModal, ScoreType } from '../components/ScoreInfoModal';

// Stat card with color indicator - simple and clear
function StatCard({
  value,
  label,
  color = '#0f62fe',
  isSelected = false,
  onClick
}: {
  value: number;
  total?: number;
  label: string;
  percentage?: string;
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
      {/* Color indicator bar */}
      <div style={{
        width: 4,
        height: '100%',
        minHeight: 40,
        backgroundColor: color,
        borderRadius: 2
      }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '1.5rem', fontWeight: 600, color: color }}>
          {value}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>{label}</div>
      </div>
      {onClick && (
        <ArrowRight size={16} style={{ color: 'var(--cve-text-secondary)' }} />
      )}
    </div>
  );
}

// Action card matching Concert style
function ActionCard({
  title,
  count,
  icon: Icon,
  onClick
}: {
  title: string;
  count: number;
  icon: typeof Security;
  onClick: () => void;
}) {
  return (
    <Tile
      onClick={onClick}
      style={{
        padding: '1.25rem',
        backgroundColor: '#161616',
        border: '1px solid #393939',
        cursor: 'pointer',
        height: '100%',
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
        Action
      </div>
      <h3 style={{ fontSize: '1rem', marginBottom: '0.75rem', lineHeight: 1.4 }}>{title}</h3>
      <Tag type="blue" style={{ marginBottom: 'auto' }}>
        {count} available actions
      </Tag>
      <div style={{ marginTop: '1.5rem' }}>
        <Icon size={48} style={{ color: '#525252' }} />
      </div>
      <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
        <ArrowRight size={20} style={{ color: 'var(--cve-text-secondary)' }} />
      </div>
    </Tile>
  );
}

// Helper to get risk level from contextualized score
function getRiskLevel(score: number, formula: 'concert' | 'comprehensive'): 'critical' | 'high' | 'medium' | 'low' {
  if (formula === 'concert') {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  } else {
    if (score >= 800) return 'critical';
    if (score >= 500) return 'high';
    if (score >= 200) return 'medium';
    return 'low';
  }
}

// Gamification Challenge Card
function ChallengeCard({ challenge }: { challenge: any }) {
  const progress = Math.min((challenge.progress / challenge.target) * 100, 100);

  return (
    <div style={{
      padding: '0.75rem',
      backgroundColor: challenge.completed ? 'rgba(66, 190, 101, 0.1)' : '#1a1a1a',
      border: `1px solid ${challenge.completed ? '#42BE65' : '#393939'}`,
      borderRadius: '8px',
      flex: '1 1 200px',
      maxWidth: '280px',
      minWidth: '180px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
        {challenge.completed ? (
          <Checkmark size={16} style={{ color: '#42BE65' }} />
        ) : (
          <span style={{ fontSize: '16px' }}>🎯</span>
        )}
        <span style={{ fontSize: '0.8125rem', fontWeight: 500 }}>{challenge.title}</span>
        <Tag size="sm" type="purple" style={{ marginLeft: 'auto' }}>+{challenge.xpReward} XP</Tag>
      </div>
      <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
        {challenge.description}
      </div>
      <ProgressBar value={progress} max={100} size="small" label="Progress" hideLabel />
      <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
        {challenge.progress}/{challenge.target} complete
      </div>
    </div>
  );
}

function Dashboard() {
  const { currentScan, isDemoMode, applicationContext, userProgress, challenges, fixedGroupIds, fixedExposureIds } = useAppContext();
  const navigate = useNavigate();
  const { showSuccess } = useNotifications();
  const [isLoading, setIsLoading] = useState(false);
  const [infoModalType, setInfoModalType] = useState<ScoreType | null>(null);

  // Simulate loading state for real scans (not demo mode)
  useEffect(() => {
    if (currentScan && !isDemoMode) {
      setIsLoading(true);
      // Simulate API call delay
      const timer = setTimeout(() => {
        setIsLoading(false);
        showSuccess('Dashboard loaded', 'Scan data is ready');
      }, 800);
      return () => clearTimeout(timer);
    }
  }, [currentScan, isDemoMode]);

  // Get the selected risk formula (default to concert)
  const selectedFormula = applicationContext?.formula || 'concert';

  if (!currentScan) {
    return (
      <div className="empty-state">
        <WarningAlt size={64} />
        <h3>No Scan Data Available</h3>
        <p>Start a new scan or try demo mode to see vulnerability analysis.</p>
        <Button kind="primary" renderIcon={Add} onClick={() => navigate('/app/scan')}>
          Start New Scan
        </Button>
      </div>
    );
  }

  // Show loading skeleton while data is being fetched
  if (isLoading) {
    return <PageLoadingSkeleton />;
  }

  const { summary, metadata, cves } = currentScan;

  // Get extended scan data (from demo or real scan)
  // Real scans now include full summary with byType, slaStatus, etc.
  const extendedSummary = isDemoMode ? demoExtendedScanResult.summary : (summary as any);

  // Calculate adjusted exposure score based on fixed exposures
  // Use proportional reduction: score reduces proportionally to the percentage of exposures fixed
  const originalExposureScore = extendedSummary?.riskScore?.concert || summary?.riskScore?.concert || 0;
  const totalExposureCount = extendedSummary?.totalExposures || (summary as any)?.totalCVEs || cves?.length || 0;
  const fixedCount = fixedExposureIds.size;
  // Calculate proportion of exposures remaining (unfixed)
  const proportionRemaining = totalExposureCount > 0 ? Math.max(0, (totalExposureCount - fixedCount) / totalExposureCount) : 1;
  const adjustedExposureScore = Math.round(originalExposureScore * proportionRemaining * 10) / 10;
  const scoreReduction = Math.round((originalExposureScore - adjustedExposureScore) * 10) / 10;
  const hasFixedGroups = fixedGroupIds.size > 0;

  // Calculate risk distribution based on CONTEXTUALIZED risk scores
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  cves?.forEach(cve => {
    const score = selectedFormula === 'concert'
      ? (cve.riskScore?.concert || 0)
      : (cve.riskScore?.comprehensive || 0);
    const level = getRiskLevel(score, selectedFormula);
    riskCounts[level]++;
  });

  const totalCVEs = (summary as any)?.totalCVEs ?? cves?.length ?? 0;

  // Total exposures across all 6 types
  const totalExposures = extendedSummary?.totalExposures || totalCVEs;

  // Get level info
  const levelInfo = LEVEL_THRESHOLDS.find(l => l.level === userProgress.level) || LEVEL_THRESHOLDS[0];
  const nextLevelInfo = LEVEL_THRESHOLDS.find(l => l.level === userProgress.level + 1);
  const xpProgress = ((userProgress.xp - levelInfo.minXp) / (levelInfo.maxXp - levelInfo.minXp)) * 100;
  const xpToNext = (nextLevelInfo?.minXp || levelInfo.maxXp) - userProgress.xp;

  // Get active challenges
  const activeChallenges = challenges.filter(c => !c.completed).slice(0, 3);

  return (
    <div>
      {/* Welcome Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 300, marginBottom: '0.5rem' }}>
          Welcome back{metadata?.context?.appName ? ',' : '.'}
        </h1>
        {metadata?.context?.appName && (
          <p style={{ fontSize: '1.25rem', color: 'var(--cve-text-secondary)' }}>
            {metadata.context.appName}
          </p>
        )}
      </div>

      {/* Large Exposure Score Display */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 2fr',
        gap: '1.5rem',
        marginBottom: '2rem'
      }}>
        {/* Risk Score Gauge */}
        <Tile style={{
          padding: '2rem',
          backgroundColor: '#161616',
          border: hasFixedGroups ? '1px solid #42BE65' : '1px solid #393939',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'relative'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>Unified Exposure Risk Score</span>
            <button
              onClick={() => setInfoModalType('exposure-score')}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
              title="How is this score calculated?"
            >
              <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
            </button>
          </div>
          <div style={{
            position: 'relative',
            width: 180,
            height: 180
          }}>
            {/* Background arc */}
            <svg width="180" height="180" style={{ transform: 'rotate(-90deg)' }}>
              <circle
                cx="90"
                cy="90"
                r="75"
                fill="none"
                stroke="#393939"
                strokeWidth="16"
              />
              <circle
                cx="90"
                cy="90"
                r="75"
                fill="none"
                stroke={getRiskColor(adjustedExposureScore)}
                strokeWidth="16"
                strokeDasharray={`${(adjustedExposureScore / 10) * 471} 471`}
                strokeLinecap="round"
              />
            </svg>
            {/* Center value */}
            <div style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              textAlign: 'center'
            }}>
              <div style={{
                fontSize: '3rem',
                fontWeight: 600,
                color: getRiskColor(adjustedExposureScore)
              }}>
                {adjustedExposureScore.toFixed(1)}
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                / 10
              </div>
            </div>
          </div>
          <div style={{
            marginTop: '1rem',
            fontSize: '1rem',
            fontWeight: 500,
            color: getRiskColor(adjustedExposureScore)
          }}>
            {adjustedExposureScore >= 7.0 ? 'High Exposure' :
             adjustedExposureScore >= 4.0 ? 'Medium Exposure' : 'Low Exposure'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
            {metadata?.context?.appName || 'Application'} Security Posture
          </div>
          {/* Show improvement indicator when groups are fixed */}
          {hasFixedGroups && (
            <div style={{
              marginTop: '0.75rem',
              padding: '0.5rem 0.75rem',
              backgroundColor: 'rgba(66, 190, 101, 0.1)',
              borderRadius: '4px',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <Checkmark size={16} style={{ color: '#42BE65' }} />
              <span style={{ fontSize: '0.75rem', color: '#42BE65' }}>
                -{scoreReduction.toFixed(1)} from fixes ({fixedGroupIds.size} groups)
              </span>
            </div>
          )}
        </Tile>

        {/* Quick Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Total Exposures</span>
              <button
                onClick={() => setInfoModalType('total-exposures')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="What counts as an exposure?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            <div style={{ fontSize: '2.5rem', fontWeight: 600 }}>
              {totalExposures}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
              across 6 categories
            </div>
          </Tile>

          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Critical + High</span>
              <button
                onClick={() => setInfoModalType('critical-high')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="What makes an exposure Critical or High?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            <div style={{ fontSize: '2.5rem', fontWeight: 600, color: '#FA4D56' }}>
              {(extendedSummary?.critical || riskCounts.critical) + (extendedSummary?.high || riskCounts.high)}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
              requiring immediate action
            </div>
          </Tile>

          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>CISA KEV</span>
              <button
                onClick={() => setInfoModalType('cisa-kev')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="What is CISA KEV?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            <div style={{
              fontSize: '2.5rem',
              fontWeight: 600,
              color: (extendedSummary?.cisaKEVCount || summary?.cisaKEVCount || 0) > 0 ? '#FF832B' : '#42BE65'
            }}>
              {extendedSummary?.cisaKEVCount || summary?.cisaKEVCount || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
              known exploited
            </div>
          </Tile>

          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>SLA Compliance</span>
              <button
                onClick={() => setInfoModalType('sla-compliance')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="How are SLAs calculated?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            {totalExposures > 0 ? (
              <>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 600,
                  color: (extendedSummary?.slaStatus?.complianceRate || 0) >= 80 ? '#42BE65' : '#FA4D56'
                }}>
                  {extendedSummary?.slaStatus?.complianceRate || 0}%
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                  {extendedSummary?.slaStatus?.overdue || 0} overdue
                </div>
              </>
            ) : (
              <>
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 600,
                  color: 'var(--cve-text-secondary)'
                }}>
                  N/A
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                  no exposures detected
                </div>
              </>
            )}
          </Tile>

          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: hasFixedGroups ? '1px solid #42BE65' : '1px solid #393939', position: 'relative' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Concert Score</span>
              <button
                onClick={() => setInfoModalType('concert-score')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="How is Concert Score calculated?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            <div style={{
              fontSize: '2.5rem',
              fontWeight: 600,
              color: adjustedExposureScore >= 7 ? '#FA4D56' :
                     adjustedExposureScore >= 4 ? '#F1C21B' : '#42BE65'
            }}>
              {adjustedExposureScore.toFixed(1)}<span style={{ fontSize: '1rem', color: 'var(--cve-text-secondary)' }}>/10</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
              {hasFixedGroups ? `was ${originalExposureScore.toFixed(1)}` : 'executive summary'}
            </div>
          </Tile>

          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939', position: 'relative' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Operational Risk Score</span>
              <button
                onClick={() => setInfoModalType('detailed-score')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' }}
                title="How is Operational Risk Score calculated?"
              >
                <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
              </button>
            </div>
            {(() => {
              // Comprehensive score is already on 0-10 scale (same as concert)
              const detailedScore = extendedSummary?.riskScore?.comprehensive || summary?.riskScore?.comprehensive || 0;
              return (
                <div style={{
                  fontSize: '2.5rem',
                  fontWeight: 600,
                  color: detailedScore >= 7 ? '#FA4D56' :
                         detailedScore >= 4 ? '#F1C21B' : '#42BE65'
                }}>
                  {detailedScore.toFixed(1)}<span style={{ fontSize: '1rem', color: 'var(--cve-text-secondary)' }}>/10</span>
                </div>
              );
            })()}
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
              operational context
            </div>
          </Tile>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div style={{ marginBottom: '2rem' }}>

        {/* Stats panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Total exposures */}
          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
              Total Exposures Detected
            </div>
            <div style={{ fontSize: '2.5rem', fontWeight: 300 }}>
              {totalExposures} <span style={{ fontSize: '1rem', color: 'var(--cve-text-secondary)' }}>across 6 categories</span>
            </div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginTop: '0.5rem' }}>
              Critical: <span style={{ color: '#FA4D56' }}>{extendedSummary?.critical || riskCounts.critical}</span> |
              High: <span style={{ color: '#FF832B' }}>{extendedSummary?.high || riskCounts.high}</span> |
              Medium: <span style={{ color: '#F1C21B' }}>{extendedSummary?.medium || riskCounts.medium}</span> |
              Low: <span style={{ color: '#42BE65' }}>{extendedSummary?.low || riskCounts.low}</span>
            </div>
            <ArrowRight size={16} style={{ marginTop: '0.5rem', color: 'var(--cve-text-secondary)', cursor: 'pointer' }} onClick={() => navigate('/app/exposures')} />
          </Tile>

          {/* Stats grid 2x3 - Exposure types */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
            <StatCard
              value={extendedSummary?.byType?.cve || totalCVEs}
              total={totalExposures}
              label="CVEs"
              color={EXPOSURE_COLORS.cve}
              onClick={() => navigate('/app/exposures?type=cve')}
            />
            <StatCard
              value={extendedSummary?.byType?.secret || 0}
              total={totalExposures}
              label="Secrets"
              color={EXPOSURE_COLORS.secret}
              onClick={() => navigate('/app/exposures?type=secret')}
            />
            <StatCard
              value={extendedSummary?.byType?.certificate || 0}
              total={totalExposures}
              label="Certificates"
              color={EXPOSURE_COLORS.certificate}
              onClick={() => navigate('/app/exposures?type=certificate')}
            />
            <StatCard
              value={extendedSummary?.byType?.misconfiguration || 0}
              total={totalExposures}
              label="Misconfigs"
              color={EXPOSURE_COLORS.misconfiguration}
              onClick={() => navigate('/app/exposures?type=misconfiguration')}
            />
            <StatCard
              value={extendedSummary?.byType?.license || 0}
              total={totalExposures}
              label="Licenses"
              color={EXPOSURE_COLORS.license}
              onClick={() => navigate('/app/exposures?type=license')}
            />
            <StatCard
              value={extendedSummary?.byType?.codeSecurity || 0}
              total={totalExposures}
              label="Code Security"
              color={EXPOSURE_COLORS.codeSecurity}
              onClick={() => navigate('/app/exposures?type=code-security')}
            />
          </div>
        </div>
      </div>

      {/* Available Actions Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
            Available actions
          </div>
          <div style={{ fontSize: '1rem', lineHeight: 1.4, marginBottom: '1rem' }}>
            You have <strong>{extendedSummary?.critical || riskCounts.critical}</strong> critical exposures requiring immediate attention
          </div>
          <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
            Total exposures: <strong>{totalExposures}</strong>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={() => navigate('/app/remediation')}
            style={{ padding: 0 }}
          >
            View all actions <ArrowRight size={16} />
          </Button>
        </Tile>

        <ActionCard
          title="Review critical CVEs and secrets"
          count={(extendedSummary?.byType?.cve || totalCVEs) + (extendedSummary?.byType?.secret || 0)}
          icon={Security}
          onClick={() => navigate('/app/exposures?severity=critical')}
        />

        <ActionCard
          title="Check expiring certificates"
          count={extendedSummary?.byType?.certificate || 0}
          icon={Certificate}
          onClick={() => navigate('/app/exposures?type=certificate')}
        />

        <ActionCard
          title="Fix infrastructure misconfigurations"
          count={extendedSummary?.byType?.misconfiguration || 0}
          icon={SettingsCheck}
          onClick={() => navigate('/app/exposures?type=misconfiguration')}
        />

        <ActionCard
          title="View remediation groups for batch fixes"
          count={demoExtendedScanResult?.remediationGroups?.length || currentScan?.remediationGroups?.length || 0}
          icon={Time}
          onClick={() => navigate('/app/remediation')}
        />
      </div>

      {/* Gamification Section */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 2fr',
        gap: '1rem',
        marginTop: '0.5rem',
        padding: '1.25rem',
        background: `linear-gradient(135deg, ${levelInfo.color}15 0%, transparent 50%, rgba(69, 137, 255, 0.1) 100%)`,
        borderRadius: '12px',
        border: `1px solid ${levelInfo.color}40`
      }}>
        {/* User Progress */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: `linear-gradient(135deg, ${levelInfo.color}40, ${levelInfo.color}20)`,
            border: `2px solid ${levelInfo.color}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.75rem'
          }}>
            {levelInfo.icon}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <span style={{ fontSize: '1.125rem', fontWeight: 600, color: levelInfo.color }}>
                Level {userProgress.level} {userProgress.rank}
              </span>
              <Tag size="sm" type="purple">{userProgress.xp.toLocaleString()} XP</Tag>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Fire size={14} style={{ color: '#FF832B' }} />
                <span style={{ fontSize: '0.8125rem' }}>{userProgress.currentStreak} day streak</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Trophy size={14} style={{ color: '#FFD700' }} />
                <span style={{ fontSize: '0.8125rem' }}>{userProgress.achievements.length} achievements</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Checkmark size={14} style={{ color: '#42BE65' }} />
                <span style={{ fontSize: '0.8125rem' }}>{userProgress.totalFixedExposures} fixed</span>
              </div>
            </div>
            <div style={{ width: '200px' }}>
              <ProgressBar value={xpProgress} max={100} size="small" label="XP Progress" hideLabel />
              <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
                {xpToNext > 0 ? `${xpToNext.toLocaleString()} XP to level ${userProgress.level + 1}` : 'Max level reached!'}
              </div>
            </div>
          </div>
        </div>

        {/* Active Challenges */}
        <div style={{ minWidth: 0, overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Star size={16} style={{ color: '#8A3FFC' }} />
            <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Active Challenges</span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {activeChallenges.length > 0 ? (
              activeChallenges.map(challenge => (
                <ChallengeCard key={challenge.id} challenge={challenge} />
              ))
            ) : (
              <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>
                All challenges completed! Check back tomorrow for new ones.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Score Info Modal */}
      {infoModalType && (
        <ScoreInfoModal
          open={!!infoModalType}
          onClose={() => setInfoModalType(null)}
          scoreType={infoModalType}
        />
      )}

    </div>
  );
}

function getRiskColor(score: number): string {
  if (score >= 9.0) return '#FA4D56';
  if (score >= 7.0) return '#FF832B';
  if (score >= 4.0) return '#F1C21B';
  return '#42BE65';
}

// Exposure type colors matching Carbon design
const EXPOSURE_COLORS: Record<string, string> = {
  cve: '#FA4D56',           // Red - vulnerabilities
  certificate: '#8A3FFC',   // Purple - certificates
  secret: '#FF832B',        // Orange - secrets
  misconfiguration: '#1192E8', // Blue - misconfigs
  license: '#009D9A',       // Teal - licenses
  codeSecurity: '#6929C4'   // Violet - code security
};

export default Dashboard;
