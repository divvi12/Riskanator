import { Routes, Route, Navigate } from 'react-router-dom';
import { useState, createContext, useContext, useEffect, useCallback } from 'react';
import Layout from './components/Layout';
import { NotificationProvider } from './components/NotificationProvider';
import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import ScanSetup from './pages/ScanSetup';
// CVEList removed - using ExposuresList for all exposure types including CVEs
import ExposuresList from './pages/ExposuresList';
import Remediation from './pages/Remediation';
import RemediationGroups from './pages/RemediationGroups';
import ArenaView from './pages/ArenaView';
import Settings from './pages/Settings';
import Compliance from './pages/Compliance';
import ScanHistory from './pages/ScanHistory';
import {
  ScanResult,
  ApplicationContext,
  UserProgress,
  Challenge,
  LEVEL_THRESHOLDS,
  ACHIEVEMENTS,
  XP_REWARDS,
  ExposureSeverity,
  ExposureType
} from './types';
import { demoScanResult } from './data/demoData';

// Helper functions for gamification
const getLevelFromXp = (xp: number) => {
  const levelInfo = LEVEL_THRESHOLDS.find(l => xp >= l.minXp && xp < l.maxXp);
  return levelInfo || LEVEL_THRESHOLDS[0];
};

const getDefaultProgress = (): UserProgress => ({
  xp: 0,
  level: 1,
  rank: 'Rookie',
  totalFixedExposures: 0,
  totalScans: 0,
  currentStreak: 0,
  longestStreak: 0,
  lastActivityDate: new Date().toISOString().split('T')[0],
  achievements: [],
  unlockedBadges: []
});

const generateDailyChallenges = (): Challenge[] => {
  const today = new Date();
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);

  return [
    {
      id: 'daily_scan',
      title: 'Daily Scanner',
      description: 'Complete a security scan today',
      type: 'daily',
      xpReward: 25,
      progress: 0,
      target: 1,
      expiresAt: tomorrow.toISOString(),
      completed: false
    },
    {
      id: 'daily_fix_3',
      title: 'Triple Threat',
      description: 'Fix 3 exposures today',
      type: 'daily',
      xpReward: 50,
      progress: 0,
      target: 3,
      expiresAt: tomorrow.toISOString(),
      completed: false
    }
  ];
};

const generateWeeklyChallenges = (): Challenge[] => {
  const today = new Date();
  const nextWeek = new Date(today);
  nextWeek.setDate(nextWeek.getDate() + 7);

  return [
    {
      id: 'weekly_fix_10',
      title: 'Weekly Warrior',
      description: 'Fix 10 exposures this week',
      type: 'weekly',
      xpReward: 150,
      progress: 0,
      target: 10,
      expiresAt: nextWeek.toISOString(),
      completed: false
    },
    {
      id: 'weekly_critical',
      title: 'Critical Hunter',
      description: 'Fix 3 critical exposures this week',
      type: 'weekly',
      xpReward: 200,
      progress: 0,
      target: 3,
      expiresAt: nextWeek.toISOString(),
      completed: false
    }
  ];
};

// App Context
interface AppContextType {
  isDemoMode: boolean;
  setIsDemoMode: (value: boolean) => void;
  currentScan: ScanResult | null;
  setCurrentScan: (scan: ScanResult | null) => void;
  applicationContext: ApplicationContext | null;
  setApplicationContext: (context: ApplicationContext | null) => void;
  // Gamification
  userProgress: UserProgress;
  challenges: Challenge[];
  addXp: (amount: number, reason?: string) => void;
  recordFix: (severity: ExposureSeverity, exposureType: ExposureType) => void;
  recordScan: () => void;
  showLevelUp: boolean;
  setShowLevelUp: (show: boolean) => void;
  newAchievements: string[];
  clearNewAchievements: () => void;
  xpAnimation: { amount: number; reason: string } | null;
}

export const AppContext = createContext<AppContextType>({
  isDemoMode: false,
  setIsDemoMode: () => {},
  currentScan: null,
  setCurrentScan: () => {},
  applicationContext: null,
  setApplicationContext: () => {},
  // Gamification defaults
  userProgress: getDefaultProgress(),
  challenges: [],
  addXp: () => {},
  recordFix: () => {},
  recordScan: () => {},
  showLevelUp: false,
  setShowLevelUp: () => {},
  newAchievements: [],
  clearNewAchievements: () => {},
  xpAnimation: null
});

export const useAppContext = () => useContext(AppContext);

function App() {
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [applicationContext, setApplicationContext] = useState<ApplicationContext | null>(null);

  // Gamification state
  const [userProgress, setUserProgress] = useState<UserProgress>(() => {
    const saved = localStorage.getItem('riskanator_progress');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return getDefaultProgress();
      }
    }
    return getDefaultProgress();
  });

  const [challenges, setChallenges] = useState<Challenge[]>(() => {
    const saved = localStorage.getItem('riskanator_challenges');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        // Check if challenges are expired
        const now = new Date();
        const stillValid = parsed.filter((c: Challenge) => new Date(c.expiresAt) > now);
        if (stillValid.length === 0) {
          return [...generateDailyChallenges(), ...generateWeeklyChallenges()];
        }
        return stillValid;
      } catch {
        return [...generateDailyChallenges(), ...generateWeeklyChallenges()];
      }
    }
    return [...generateDailyChallenges(), ...generateWeeklyChallenges()];
  });

  const [showLevelUp, setShowLevelUp] = useState(false);
  const [newAchievements, setNewAchievements] = useState<string[]>([]);
  const [xpAnimation, setXpAnimation] = useState<{ amount: number; reason: string } | null>(null);

  // Save progress to localStorage
  useEffect(() => {
    localStorage.setItem('riskanator_progress', JSON.stringify(userProgress));
  }, [userProgress]);

  useEffect(() => {
    localStorage.setItem('riskanator_challenges', JSON.stringify(challenges));
  }, [challenges]);

  // Check for streak updates
  useEffect(() => {
    const today = new Date().toISOString().split('T')[0];
    const lastActivity = userProgress.lastActivityDate;

    if (lastActivity !== today) {
      const lastDate = new Date(lastActivity);
      const todayDate = new Date(today);
      const diffDays = Math.floor((todayDate.getTime() - lastDate.getTime()) / (1000 * 60 * 60 * 24));

      if (diffDays === 1) {
        // Continue streak
        setUserProgress(prev => ({
          ...prev,
          currentStreak: prev.currentStreak + 1,
          longestStreak: Math.max(prev.longestStreak, prev.currentStreak + 1),
          lastActivityDate: today
        }));
      } else if (diffDays > 1) {
        // Reset streak
        setUserProgress(prev => ({
          ...prev,
          currentStreak: 1,
          lastActivityDate: today
        }));
      }
    }
  }, [userProgress.lastActivityDate]);

  // Add XP function
  const addXp = useCallback((amount: number, reason: string = 'Action') => {
    setXpAnimation({ amount, reason });
    setTimeout(() => setXpAnimation(null), 2000);

    setUserProgress(prev => {
      const newXp = prev.xp + amount;
      const currentLevel = getLevelFromXp(prev.xp);
      const newLevel = getLevelFromXp(newXp);

      // Check for level up
      if (newLevel.level > currentLevel.level) {
        setShowLevelUp(true);
        setTimeout(() => setShowLevelUp(false), 3000);
      }

      return {
        ...prev,
        xp: newXp,
        level: newLevel.level,
        rank: newLevel.rank
      };
    });
  }, []);

  // Check and unlock achievements
  const checkAchievements = useCallback((progress: UserProgress) => {
    const newUnlocked: string[] = [];

    ACHIEVEMENTS.forEach(achievement => {
      if (progress.achievements.includes(achievement.id)) return;

      let unlocked = false;

      switch (achievement.requirement.type) {
        case 'scans':
          if (progress.totalScans >= (achievement.requirement.count || 0)) {
            unlocked = true;
          }
          break;
        case 'fixes':
          if (progress.totalFixedExposures >= (achievement.requirement.count || 0)) {
            unlocked = true;
          }
          break;
        case 'streak':
          if (progress.currentStreak >= (achievement.requirement.count || 0)) {
            unlocked = true;
          }
          break;
        // Other achievement types handled elsewhere
      }

      if (unlocked) {
        newUnlocked.push(achievement.id);
      }
    });

    if (newUnlocked.length > 0) {
      setNewAchievements(prev => [...prev, ...newUnlocked]);
      setUserProgress(prev => ({
        ...prev,
        achievements: [...prev.achievements, ...newUnlocked]
      }));

      // Award XP for achievements
      newUnlocked.forEach(id => {
        const achievement = ACHIEVEMENTS.find(a => a.id === id);
        if (achievement) {
          addXp(achievement.xpReward, `Achievement: ${achievement.name}`);
        }
      });
    }
  }, [addXp]);

  // Record a fix
  const recordFix = useCallback((severity: ExposureSeverity, _exposureType: ExposureType) => {
    // Add XP based on severity
    const xpAmount = severity === 'critical' ? XP_REWARDS.fix_critical :
                     severity === 'high' ? XP_REWARDS.fix_high :
                     severity === 'medium' ? XP_REWARDS.fix_medium :
                     XP_REWARDS.fix_low;

    addXp(xpAmount, `Fixed ${severity} exposure`);

    // Update progress
    setUserProgress(prev => {
      const updated = {
        ...prev,
        totalFixedExposures: prev.totalFixedExposures + 1,
        lastActivityDate: new Date().toISOString().split('T')[0]
      };
      setTimeout(() => checkAchievements(updated), 100);
      return updated;
    });

    // Update challenges
    setChallenges(prev => prev.map(c => {
      if (c.completed) return c;

      if (c.id === 'daily_fix_3' || c.id === 'weekly_fix_10') {
        const newProgress = c.progress + 1;
        if (newProgress >= c.target) {
          addXp(c.xpReward, `Challenge: ${c.title}`);
          return { ...c, progress: newProgress, completed: true };
        }
        return { ...c, progress: newProgress };
      }

      if ((c.id === 'weekly_critical') && severity === 'critical') {
        const newProgress = c.progress + 1;
        if (newProgress >= c.target) {
          addXp(c.xpReward, `Challenge: ${c.title}`);
          return { ...c, progress: newProgress, completed: true };
        }
        return { ...c, progress: newProgress };
      }

      return c;
    }));
  }, [addXp, checkAchievements]);

  // Record a scan
  const recordScan = useCallback(() => {
    addXp(XP_REWARDS.scan_complete, 'Completed scan');

    setUserProgress(prev => {
      const updated = {
        ...prev,
        totalScans: prev.totalScans + 1,
        lastActivityDate: new Date().toISOString().split('T')[0]
      };
      setTimeout(() => checkAchievements(updated), 100);
      return updated;
    });

    // Update challenges
    setChallenges(prev => prev.map(c => {
      if (c.completed) return c;

      if (c.id === 'daily_scan') {
        const newProgress = c.progress + 1;
        if (newProgress >= c.target) {
          addXp(c.xpReward, `Challenge: ${c.title}`);
          return { ...c, progress: newProgress, completed: true };
        }
        return { ...c, progress: newProgress };
      }

      return c;
    }));
  }, [addXp, checkAchievements]);

  const clearNewAchievements = useCallback(() => {
    setNewAchievements([]);
  }, []);

  const handleEnterDemoMode = () => {
    setIsDemoMode(true);
    setCurrentScan(demoScanResult);
    setApplicationContext(demoScanResult.metadata?.context || null);
  };

  const handleExitDemoMode = () => {
    setIsDemoMode(false);
    setCurrentScan(null);
    setApplicationContext(null);
  };

  return (
    <AppContext.Provider
      value={{
        isDemoMode,
        setIsDemoMode,
        currentScan,
        setCurrentScan,
        applicationContext,
        setApplicationContext,
        // Gamification
        userProgress,
        challenges,
        addXp,
        recordFix,
        recordScan,
        showLevelUp,
        setShowLevelUp,
        newAchievements,
        clearNewAchievements,
        xpAnimation
      }}
    >
      <NotificationProvider>
        <Routes>
        <Route
          path="/"
          element={
            <LandingPage
              onEnterDemo={handleEnterDemoMode}
            />
          }
        />
        <Route
          path="/app/*"
          element={
            <Layout onExitDemo={handleExitDemoMode} onEnterDemo={handleEnterDemoMode}>
              <Routes>
                <Route path="dashboard" element={<Dashboard />} />
                <Route path="arena" element={<ArenaView />} />
                <Route path="scan" element={<ScanSetup />} />
                {/* CVE route redirects to exposures */}
                <Route path="cves" element={<Navigate to="/app/exposures" replace />} />
                <Route path="exposures" element={<ExposuresList />} />
                <Route path="remediation" element={<RemediationGroups />} />
                <Route path="remediation-legacy" element={<Remediation />} />
                <Route path="compliance" element={<Compliance />} />
                <Route path="history" element={<ScanHistory />} />
                <Route path="settings" element={<Settings />} />
                <Route path="*" element={<Navigate to="dashboard" replace />} />
              </Routes>
            </Layout>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </NotificationProvider>
    </AppContext.Provider>
  );
}

export default App;
