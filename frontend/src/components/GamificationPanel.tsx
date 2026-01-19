import { useState } from 'react';
import { Modal, Tag, ProgressBar, Tile } from '@carbon/react';
import { Trophy, Fire, Star, ChevronRight } from '@carbon/icons-react';
import { useAppContext } from '../App';
import { LEVEL_THRESHOLDS, ACHIEVEMENTS, Achievement } from '../types';

// Get level info helper
const getLevelInfo = (level: number) => {
  return LEVEL_THRESHOLDS.find(l => l.level === level) || LEVEL_THRESHOLDS[0];
};

// Rarity colors
const RARITY_COLORS = {
  common: '#6f6f6f',
  uncommon: '#42BE65',
  rare: '#0f62fe',
  epic: '#8A3FFC',
  legendary: '#FFD700'
};

// XP Progress Ring Component
function XPProgressRing({ xp, level }: { xp: number; level: number }) {
  const levelInfo = getLevelInfo(level);
  const nextLevelInfo = getLevelInfo(level + 1);

  const xpInCurrentLevel = xp - levelInfo.minXp;
  const xpNeededForLevel = (nextLevelInfo?.minXp || levelInfo.maxXp) - levelInfo.minXp;
  const progress = Math.min((xpInCurrentLevel / xpNeededForLevel) * 100, 100);

  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  return (
    <div style={{ position: 'relative', width: '100px', height: '100px' }}>
      <svg width="100" height="100" style={{ transform: 'rotate(-90deg)' }}>
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="#393939"
          strokeWidth="8"
        />
        {/* Progress circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={levelInfo.color}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '1.5rem' }}>{levelInfo.icon}</div>
        <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>{level}</div>
      </div>
    </div>
  );
}

// Compact stats for sidebar
export function GamificationSidebarWidget() {
  const { userProgress, challenges } = useAppContext();
  const [showModal, setShowModal] = useState(false);

  const levelInfo = getLevelInfo(userProgress.level);
  const nextLevelInfo = getLevelInfo(userProgress.level + 1);
  const xpToNext = (nextLevelInfo?.minXp || levelInfo.maxXp) - userProgress.xp;
  const xpProgress = ((userProgress.xp - levelInfo.minXp) / (levelInfo.maxXp - levelInfo.minXp)) * 100;

  const activeChallenges = challenges.filter(c => !c.completed).length;

  return (
    <>
      <div
        onClick={() => setShowModal(true)}
        style={{
          padding: '0.75rem',
          backgroundColor: 'rgba(69, 137, 255, 0.1)',
          borderRadius: '8px',
          cursor: 'pointer',
          transition: 'all 0.2s ease'
        }}
        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(69, 137, 255, 0.15)'}
        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'rgba(69, 137, 255, 0.1)'}
      >
        {/* Level and Rank */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '1.25rem' }}>{levelInfo.icon}</span>
          <div>
            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: levelInfo.color }}>
              Level {userProgress.level} {userProgress.rank}
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)' }}>
              {userProgress.xp.toLocaleString()} XP
            </div>
          </div>
          <ChevronRight size={16} style={{ marginLeft: 'auto', color: 'var(--cve-text-secondary)' }} />
        </div>

        {/* XP Progress Bar */}
        <div style={{ marginBottom: '0.5rem' }}>
          <ProgressBar
            value={xpProgress}
            max={100}
            size="small"
            label="XP Progress"
            hideLabel
          />
        </div>
        <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
          {xpToNext > 0 ? `${xpToNext.toLocaleString()} XP to next level` : 'Max level!'}
        </div>

        {/* Quick Stats */}
        <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <Fire size={14} style={{ color: '#FF832B' }} />
            <span>{userProgress.currentStreak}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <Trophy size={14} style={{ color: '#FFD700' }} />
            <span>{userProgress.achievements.length}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ fontSize: '14px' }}>🎯</span>
            <span>{activeChallenges}</span>
          </div>
        </div>
      </div>

      {/* Full Stats Modal */}
      <GamificationModal open={showModal} onClose={() => setShowModal(false)} />
    </>
  );
}

// Full gamification modal with all stats, achievements, challenges
function GamificationModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { userProgress, challenges } = useAppContext();
  const [activeTab, setActiveTab] = useState<'overview' | 'achievements' | 'challenges'>('overview');

  const levelInfo = getLevelInfo(userProgress.level);

  return (
    <Modal
      open={open}
      onRequestClose={onClose}
      modalHeading="Your Progress"
      passiveModal
      size="lg"
    >
      {/* Tab Navigation */}
      <div style={{
        display: 'flex',
        gap: '0',
        borderBottom: '1px solid var(--cve-border)',
        marginBottom: '1.5rem'
      }}>
        {(['overview', 'achievements', 'challenges'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '0.75rem 1rem',
              background: activeTab === tab ? 'var(--cve-background-tertiary)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === tab ? '2px solid #0f62fe' : '2px solid transparent',
              color: activeTab === tab ? 'var(--cve-text-primary)' : 'var(--cve-text-secondary)',
              cursor: 'pointer',
              fontSize: '0.875rem',
              textTransform: 'capitalize'
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div>
          {/* Level Display */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1.5rem',
            marginBottom: '2rem',
            padding: '1.5rem',
            background: `linear-gradient(135deg, ${levelInfo.color}15 0%, transparent 100%)`,
            borderRadius: '12px',
            border: `1px solid ${levelInfo.color}40`
          }}>
            <XPProgressRing xp={userProgress.xp} level={userProgress.level} />
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.25rem' }}>
                SECURITY RANK
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 600, color: levelInfo.color, marginBottom: '0.25rem' }}>
                {userProgress.rank}
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                Level {userProgress.level} • {userProgress.xp.toLocaleString()} XP
              </div>
            </div>
          </div>

          {/* Stats Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
            <StatCard icon={<span style={{ fontSize: '20px' }}>✅</span>} value={userProgress.totalFixedExposures} label="Exposures Fixed" color="#42BE65" />
            <StatCard icon={<Star size={20} />} value={userProgress.totalScans} label="Scans Completed" color="#0f62fe" />
            <StatCard icon={<Fire size={20} />} value={userProgress.currentStreak} label="Day Streak" color="#FF832B" />
            <StatCard icon={<Trophy size={20} />} value={userProgress.achievements.length} label="Achievements" color="#FFD700" />
          </div>

          {/* Recent Achievements */}
          <div>
            <h4 style={{ marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Trophy size={16} /> Recent Achievements
            </h4>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {userProgress.achievements.length === 0 ? (
                <p style={{ color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>
                  Complete actions to unlock achievements!
                </p>
              ) : (
                userProgress.achievements.slice(-6).map(id => {
                  const achievement = ACHIEVEMENTS.find(a => a.id === id);
                  if (!achievement) return null;
                  return (
                    <AchievementBadge key={id} achievement={achievement} unlocked />
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Achievements Tab */}
      {activeTab === 'achievements' && (
        <div>
          {['scanning', 'fixing', 'streaks', 'milestones', 'special'].map(category => (
            <div key={category} style={{ marginBottom: '1.5rem' }}>
              <h4 style={{ marginBottom: '0.75rem', textTransform: 'capitalize' }}>{category}</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '0.75rem' }}>
                {ACHIEVEMENTS.filter(a => a.category === category).map(achievement => (
                  <AchievementCard
                    key={achievement.id}
                    achievement={achievement}
                    unlocked={userProgress.achievements.includes(achievement.id)}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Challenges Tab */}
      {activeTab === 'challenges' && (
        <div>
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ marginBottom: '0.75rem' }}>Daily Challenges</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {challenges.filter(c => c.type === 'daily').map(challenge => (
                <ChallengeCard key={challenge.id} challenge={challenge} />
              ))}
            </div>
          </div>
          <div>
            <h4 style={{ marginBottom: '0.75rem' }}>Weekly Challenges</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {challenges.filter(c => c.type === 'weekly').map(challenge => (
                <ChallengeCard key={challenge.id} challenge={challenge} />
              ))}
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

// Stat Card
function StatCard({
  icon,
  value,
  label,
  color
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
  color: string;
}) {
  return (
    <Tile style={{
      padding: '1rem',
      backgroundColor: '#161616',
      border: '1px solid #393939',
      textAlign: 'center'
    }}>
      <div style={{ color, marginBottom: '0.5rem' }}>{icon}</div>
      <div style={{ fontSize: '1.5rem', fontWeight: 600, color }}>{value}</div>
      <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>{label}</div>
    </Tile>
  );
}

// Achievement Badge (compact)
function AchievementBadge({ achievement, unlocked }: { achievement: Achievement; unlocked: boolean }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.375rem',
        padding: '0.375rem 0.625rem',
        backgroundColor: unlocked ? `${RARITY_COLORS[achievement.rarity]}20` : '#262626',
        border: `1px solid ${unlocked ? RARITY_COLORS[achievement.rarity] : '#393939'}`,
        borderRadius: '16px',
        opacity: unlocked ? 1 : 0.5
      }}
      title={achievement.description}
    >
      <span style={{ fontSize: '0.875rem' }}>{achievement.icon}</span>
      <span style={{ fontSize: '0.75rem', color: unlocked ? RARITY_COLORS[achievement.rarity] : 'var(--cve-text-secondary)' }}>
        {achievement.name}
      </span>
    </div>
  );
}

// Achievement Card (full)
function AchievementCard({ achievement, unlocked }: { achievement: Achievement; unlocked: boolean }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '0.75rem',
      padding: '0.75rem',
      backgroundColor: unlocked ? `${RARITY_COLORS[achievement.rarity]}10` : '#1a1a1a',
      border: `1px solid ${unlocked ? RARITY_COLORS[achievement.rarity] : '#262626'}`,
      borderRadius: '8px',
      opacity: unlocked ? 1 : 0.6
    }}>
      <div style={{
        width: '40px',
        height: '40px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '1.5rem',
        backgroundColor: unlocked ? `${RARITY_COLORS[achievement.rarity]}20` : '#262626',
        borderRadius: '8px'
      }}>
        {unlocked ? achievement.icon : '🔒'}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.25rem'
        }}>
          <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{achievement.name}</span>
          <Tag
            size="sm"
            type={achievement.rarity === 'legendary' ? 'red' : achievement.rarity === 'epic' ? 'purple' : achievement.rarity === 'rare' ? 'blue' : achievement.rarity === 'uncommon' ? 'green' : 'gray'}
          >
            {achievement.rarity}
          </Tag>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
          {achievement.description}
        </div>
        <div style={{ fontSize: '0.6875rem', color: RARITY_COLORS[achievement.rarity], marginTop: '0.25rem' }}>
          +{achievement.xpReward} XP
        </div>
      </div>
    </div>
  );
}

// Challenge Card
function ChallengeCard({ challenge }: { challenge: any }) {
  const progress = Math.min((challenge.progress / challenge.target) * 100, 100);
  const timeLeft = new Date(challenge.expiresAt).getTime() - Date.now();
  const hoursLeft = Math.max(0, Math.floor(timeLeft / (1000 * 60 * 60)));

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '1rem',
      padding: '1rem',
      backgroundColor: challenge.completed ? 'rgba(66, 190, 101, 0.1)' : '#161616',
      border: `1px solid ${challenge.completed ? '#42BE65' : '#393939'}`,
      borderRadius: '8px'
    }}>
      <div style={{
        width: '44px',
        height: '44px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: challenge.completed ? 'rgba(66, 190, 101, 0.2)' : '#262626',
        borderRadius: '50%',
        fontSize: '1.25rem'
      }}>
        {challenge.completed ? '✅' : '🎯'}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
          <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{challenge.title}</span>
          <span style={{ fontSize: '0.75rem', color: '#8A3FFC' }}>+{challenge.xpReward} XP</span>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
          {challenge.description}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ flex: 1 }}>
            <ProgressBar
              value={progress}
              max={100}
              size="small"
              label="Challenge Progress"
              hideLabel
            />
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
            {challenge.progress}/{challenge.target}
          </span>
        </div>
        {!challenge.completed && (
          <div style={{ fontSize: '0.6875rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
            {hoursLeft}h remaining
          </div>
        )}
      </div>
    </div>
  );
}

// XP Animation Component (floating +XP indicator)
export function XPNotification() {
  const { xpAnimation } = useAppContext();

  if (!xpAnimation) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: '80px',
        right: '20px',
        padding: '0.75rem 1rem',
        backgroundColor: 'rgba(69, 137, 255, 0.95)',
        color: 'white',
        borderRadius: '8px',
        fontSize: '0.875rem',
        fontWeight: 600,
        zIndex: 10000,
        animation: 'slideInRight 0.3s ease, fadeOut 0.5s ease 1.5s forwards',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Star size={16} />
        <span>+{xpAnimation.amount} XP</span>
      </div>
      <div style={{ fontSize: '0.75rem', opacity: 0.9 }}>{xpAnimation.reason}</div>
    </div>
  );
}

// Level Up Celebration Modal
export function LevelUpModal() {
  const { showLevelUp, setShowLevelUp, userProgress } = useAppContext();
  const levelInfo = getLevelInfo(userProgress.level);

  if (!showLevelUp) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 10001,
        animation: 'fadeIn 0.3s ease'
      }}
      onClick={() => setShowLevelUp(false)}
    >
      <div
        style={{
          textAlign: 'center',
          padding: '3rem',
          backgroundColor: '#161616',
          borderRadius: '16px',
          border: `2px solid ${levelInfo.color}`,
          boxShadow: `0 0 60px ${levelInfo.color}40`,
          animation: 'scaleIn 0.5s ease'
        }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>{levelInfo.icon}</div>
        <div style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
          LEVEL UP!
        </div>
        <div style={{ fontSize: '3rem', fontWeight: 700, color: levelInfo.color, marginBottom: '0.5rem' }}>
          Level {userProgress.level}
        </div>
        <div style={{ fontSize: '1.25rem', color: levelInfo.color, marginBottom: '1.5rem' }}>
          {userProgress.rank}
        </div>
        <button
          onClick={() => setShowLevelUp(false)}
          style={{
            padding: '0.75rem 2rem',
            backgroundColor: levelInfo.color,
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            fontSize: '1rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Continue
        </button>
      </div>
    </div>
  );
}

export default GamificationSidebarWidget;
