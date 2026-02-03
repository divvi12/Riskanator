// Scan Request Types
export interface ScanRequest {
  repoUrl: string;
  isPrivate: boolean;
  pat?: string;
  branch: string;
  context?: ApplicationContext;
}

export interface ApplicationContext {
  appName: string;
  industry: string;
  purpose: string;
  criticality: number;
  dataSensitivity: DataSensitivity;
  accessControls: AccessControls;
  formula: 'concert' | 'comprehensive';
}

export interface DataSensitivity {
  pii: boolean;
  phi: boolean;
  pci: boolean;
  tradeSecrets: boolean;
}

export interface AccessControls {
  publicEndpoints: number;
  privateEndpoints: number;
  networkExposure: 'internal' | 'dmz' | 'public';
  controls: string[];
}

// CVE Types
export interface CVE {
  id: string;
  cvss: number;
  cvssVector?: string;
  epss?: number;
  epssPercentile?: number;
  cisaKEV: boolean;
  kevDateAdded?: string;
  component: string;
  version: string;
  fixedVersion?: string;
  source: 'npm' | 'pip' | 'semgrep' | 'trivy' | 'checkov' | 'demo';
  sourceType: 'sca' | 'sast' | 'container' | 'iac';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  references?: string[];
  riskScore?: RiskScore;
  complianceImpact?: string[];
  slaDeadline?: string;
  slaStatus?: 'overdue' | 'due_soon' | 'on_track';
  daysRemaining?: number;
}

export interface RiskScore {
  concert: number;
  comprehensive: number;
}

// ============================================================
// UNIFIED EXPOSURE MANAGEMENT TYPES
// ============================================================

export type ExposureType = 'cve' | 'certificate' | 'secret' | 'misconfiguration' | 'license' | 'code-security';

export type ExposureSeverity = 'critical' | 'high' | 'medium' | 'low';

// Base Exposure interface - common fields across all types
export interface BaseExposure {
  id: string;
  type: ExposureType;
  title: string;
  description: string;
  severity: ExposureSeverity;
  riskScore: RiskScore;
  location: string;
  detectedAt: string;
  source: string;
  complianceImpact?: string[];
  slaDeadline?: string;
  slaStatus?: 'overdue' | 'due_soon' | 'on_track';
  daysRemaining?: number;
}

// CVE Exposure (extends base)
export interface CVEExposure extends BaseExposure {
  type: 'cve';
  cveId: string;
  cvss: number;
  cvssVector?: string;
  epss?: number;
  epssPercentile?: number;
  cisaKEV: boolean;
  kevDateAdded?: string;
  component: string;
  version: string;
  fixedVersion?: string;
  sourceType: 'sca' | 'sast' | 'container' | 'iac';
  references?: string[];
}

// Certificate Exposure
export interface CertificateExposure extends BaseExposure {
  type: 'certificate';
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiration: number;
  algorithm: string;
  keySize?: number;
  serialNumber?: string;
  isExpired: boolean;
  isSelfSigned: boolean;
  hasWeakAlgorithm: boolean;
  certType: 'ssl' | 'code-signing' | 'client' | 'other';
}

// Secret Exposure
export interface SecretExposure extends BaseExposure {
  type: 'secret';
  secretType: 'aws' | 'api_key' | 'password' | 'private_key' | 'token' | 'generic';
  detectorName: string;
  verified: boolean;
  entropy?: number;
  inGitHistory: boolean;
  lineNumber?: number;
  codeSnippet?: string;
}

// Misconfiguration Exposure
export interface MisconfigurationExposure extends BaseExposure {
  type: 'misconfiguration';
  resourceType: string;
  checkId: string;
  checkName: string;
  guideline?: string;
  isPubliclyAccessible: boolean;
  framework?: string;
  resourceName?: string;
  codeSnippet?: string;
}

// License Exposure
export interface LicenseExposure extends BaseExposure {
  type: 'license';
  licenseType: string;
  licenseName: string;
  packageName: string;
  packageVersion: string;
  isCopyleft: boolean;
  isUnknown: boolean;
  requiresAttribution: boolean;
  commercialUseAllowed: boolean;
  repository?: string;
}

// Code Security Exposure
export interface CodeSecurityExposure extends BaseExposure {
  type: 'code-security';
  issueType: 'sql_injection' | 'xss' | 'command_injection' | 'path_traversal' | 'weak_cryptography' | 'insecure_randomness' | 'hardcoded_secret' | 'open_redirect' | 'information_disclosure' | 'code_injection' | 'security_misconfiguration' | 'broken_auth' | 'code_smell' | 'other';
  ruleId: string;
  ruleName: string;
  filePath?: string;
  lineNumber: number;
  endLineNumber?: number;
  codeSnippet?: string;
  fixSuggestion?: string;
  cwe?: string[];
  owasp?: string[];
}

// Union type for all exposures
export type Exposure = CVEExposure | CertificateExposure | SecretExposure | MisconfigurationExposure | LicenseExposure | CodeSecurityExposure;

// Extended Scan Summary with exposure breakdown
export interface ExtendedScanSummary {
  totalExposures: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  overallRiskScore: number;
  riskScore: RiskScore;
  cisaKEVCount: number;
  byType: {
    cve: number;
    certificate: number;
    secret: number;
    misconfiguration: number;
    license: number;
    codeSecurity: number;
  };
  bySource: Record<string, number>;
  slaStatus: SLAStatus;
}

// Extended Remediation Group for all exposure types
export interface ExtendedRemediationGroup {
  id: string;
  title: string;
  type: 'secret_removal' | 'certificate_renewal' | 'dependency_update' | 'config_fix' | 'license_resolution' | 'code_fix';
  exposureType: ExposureType;
  exposures: string[];
  exposuresCount: number;
  riskReduction: number;
  effort: 'low' | 'medium' | 'high';
  effortHours: number;
  priority: number;
  slaStatus: 'overdue' | 'due_soon' | 'on_track';
  overdueCount: number;
  dueSoonCount: number;
  complianceImpact: string[];
  fixCommand?: string;
  description?: string;
}

// Extended Financial Analysis
export interface ExtendedFinancialAnalysis {
  breachCost: number;
  secretBreachCost: number;
  downtimeCost: number;
  configurationRisk: number;
  legalFees: number;
  regulatoryFines: number;
  totalRisk: number;
  remediationCost: number;
  roi: number;
  breakdown: {
    cve: number;
    certificate: number;
    secret: number;
    misconfiguration: number;
    license: number;
    codeSecurity: number;
  };
}

// Extended Compliance Status
export interface ExtendedComplianceStatus {
  pciDss: { count: number; exposures: string[] };
  hipaa: { count: number; exposures: string[] };
  sox: { count: number; exposures: string[] };
  gdpr: { count: number; exposures: string[] };
  legal: { count: number; exposures: string[] };
}

// Extended Scan Result with unified exposures
export interface ExtendedScanResult {
  scanId: string;
  status: 'pending' | 'cloning' | 'detecting' | 'scanning' | 'enriching' | 'complete' | 'error';
  progress?: number;
  progressMessage?: string;
  metadata?: ScanMetadata;
  summary?: ExtendedScanSummary;
  exposures?: Exposure[];
  cves?: CVE[];
  topology?: ApplicationTopology;
  remediationGroups?: ExtendedRemediationGroup[];
  financialImpact?: ExtendedFinancialAnalysis;
  complianceStatus?: ExtendedComplianceStatus;
  error?: string;
}

// Legacy Non-CVE Exposure Types (for backward compatibility)
export interface NonCVEExposure {
  id: string;
  type: 'misconfiguration' | 'weakness' | 'code_smell' | 'secret_exposure' | 'insecure_default';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: string;
  category: string;
  recommendation: string;
  effort: 'low' | 'medium' | 'high';
  complianceImpact?: string[];
  riskScore: number;
}

// Arena Topology Types
export interface TopologyNode {
  id: string;
  name: string;
  type: 'application' | 'gateway' | 'service' | 'database' | 'cache' | 'queue' | 'external' | 'storage' | 'container';
  technology?: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'healthy';
  cveCount: number;
  exposureCount: number;
  x?: number;
  y?: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  label?: string;
  protocol?: string;
  encrypted?: boolean;
}

export interface ApplicationTopology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

// Scan Result Types
export interface ScanResult {
  scanId: string;
  status: 'pending' | 'cloning' | 'detecting' | 'scanning' | 'enriching' | 'complete' | 'error';
  progress?: number;
  progressMessage?: string;
  metadata?: ScanMetadata;
  summary?: ScanSummary | ExtendedScanSummary;
  cves?: CVE[];
  exposures?: Exposure[];
  nonCVEExposures?: NonCVEExposure[];
  topology?: ApplicationTopology;
  remediationGroups?: RemediationGroup[] | ExtendedRemediationGroup[];
  error?: string;
}

export interface ScanMetadata {
  repoUrl: string;
  branch: string;
  context?: ApplicationContext;
  languages: string[];
  scanTypes: string[];
  startTime: string;
  endTime?: string;
}

export interface ScanSummary {
  totalCVEs: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  riskScore: RiskScore;
  cisaKEVCount: number;
  bySource: Record<string, number>;
  bySourceType: Record<string, number>;
}

// Remediation Types
export interface RemediationGroup {
  id: string;
  title: string;
  type: 'dependency_update' | 'code_fix' | 'config_change' | 'base_image_update';
  cves: string[];
  cvesCount: number;
  riskReduction: number;
  effort: 'low' | 'medium' | 'high';
  effortHours: number;
  priority: number;
  slaStatus: 'overdue' | 'due_soon' | 'on_track';
  overdueCount: number;
  dueSoonCount: number;
  complianceImpact: string[];
  fixCommand?: string;
  targetVersion?: string;
}

// Financial Types
export interface FinancialAnalysis {
  breachCost: number;
  downtimeCost: number;
  regulatoryFines: number;
  totalRisk: number;
  remediationCost: number;
  roi: number;
}

// Compliance Types
export interface ComplianceStatus {
  pciDss: number;
  hipaa: number;
  sox: number;
  gdpr: number;
}

// SLA Types
export interface SLAStatus {
  overdue: number;
  dueSoon: number;
  onTrack: number;
  complianceRate: number;
}

// App State
export interface AppState {
  isDemoMode: boolean;
  currentScan: ScanResult | null;
  scanHistory: ScanResult[];
}

// Industry options
export const INDUSTRIES = [
  { value: 'financial', label: 'Financial Services' },
  { value: 'healthcare', label: 'Healthcare' },
  { value: 'retail', label: 'Retail / E-commerce' },
  { value: 'technology', label: 'Technology' },
  { value: 'manufacturing', label: 'Manufacturing' },
  { value: 'government', label: 'Government' },
  { value: 'education', label: 'Education' },
  { value: 'other', label: 'Other' }
];

// Security controls options
export const SECURITY_CONTROLS = [
  { id: 'waf', label: 'Web Application Firewall (WAF)' },
  { id: 'ids', label: 'Intrusion Detection System (IDS)' },
  { id: 'mfa', label: 'Multi-Factor Authentication (MFA)' },
  { id: 'encryption', label: 'Data Encryption at Rest' },
  { id: 'tls', label: 'TLS/SSL Encryption in Transit' },
  { id: 'siem', label: 'SIEM Monitoring' },
  { id: 'dlp', label: 'Data Loss Prevention (DLP)' },
  { id: 'rbac', label: 'Role-Based Access Control (RBAC)' }
];

// ============================================================
// GAMIFICATION TYPES
// ============================================================

export interface UserProgress {
  xp: number;
  level: number;
  rank: SecurityRank;
  totalFixedExposures: number;
  totalScans: number;
  currentStreak: number;
  longestStreak: number;
  lastActivityDate: string;
  achievements: string[];
  unlockedBadges: string[];
}

export type SecurityRank =
  | 'Rookie'
  | 'Defender'
  | 'Guardian'
  | 'Sentinel'
  | 'Protector'
  | 'Champion'
  | 'Elite'
  | 'Master'
  | 'Legend'
  | 'Mythic';

export interface Achievement {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'scanning' | 'fixing' | 'streaks' | 'milestones' | 'special';
  xpReward: number;
  requirement: AchievementRequirement;
  rarity: 'common' | 'uncommon' | 'rare' | 'epic' | 'legendary';
  unlockedAt?: string;
}

export interface AchievementRequirement {
  type: 'fixes' | 'scans' | 'streak' | 'severity' | 'type' | 'score' | 'special';
  count?: number;
  severity?: ExposureSeverity;
  exposureType?: ExposureType;
  scoreThreshold?: number;
}

export interface Challenge {
  id: string;
  title: string;
  description: string;
  type: 'daily' | 'weekly' | 'special';
  xpReward: number;
  progress: number;
  target: number;
  expiresAt: string;
  completed: boolean;
}

export interface LevelInfo {
  level: number;
  rank: SecurityRank;
  minXp: number;
  maxXp: number;
  color: string;
  icon: string;
}

export interface LeaderboardEntry {
  rank: number;
  username: string;
  avatar?: string;
  xp: number;
  level: number;
  fixedExposures: number;
}

// XP rewards for different actions
export const XP_REWARDS = {
  scan_complete: 50,
  fix_critical: 100,
  fix_high: 75,
  fix_medium: 50,
  fix_low: 25,
  daily_login: 10,
  streak_bonus: 5, // per day in streak
  first_scan: 100,
  achieve_zero_critical: 200,
  perfect_score: 500,
};

// Level thresholds and ranks
export const LEVEL_THRESHOLDS: LevelInfo[] = [
  { level: 1, rank: 'Rookie', minXp: 0, maxXp: 100, color: '#6f6f6f', icon: '🛡️' },
  { level: 2, rank: 'Rookie', minXp: 100, maxXp: 250, color: '#6f6f6f', icon: '🛡️' },
  { level: 3, rank: 'Defender', minXp: 250, maxXp: 500, color: '#42BE65', icon: '⚔️' },
  { level: 4, rank: 'Defender', minXp: 500, maxXp: 800, color: '#42BE65', icon: '⚔️' },
  { level: 5, rank: 'Guardian', minXp: 800, maxXp: 1200, color: '#0f62fe', icon: '🏰' },
  { level: 6, rank: 'Guardian', minXp: 1200, maxXp: 1700, color: '#0f62fe', icon: '🏰' },
  { level: 7, rank: 'Sentinel', minXp: 1700, maxXp: 2300, color: '#8A3FFC', icon: '👁️' },
  { level: 8, rank: 'Sentinel', minXp: 2300, maxXp: 3000, color: '#8A3FFC', icon: '👁️' },
  { level: 9, rank: 'Protector', minXp: 3000, maxXp: 4000, color: '#FF832B', icon: '🔰' },
  { level: 10, rank: 'Protector', minXp: 4000, maxXp: 5000, color: '#FF832B', icon: '🔰' },
  { level: 11, rank: 'Champion', minXp: 5000, maxXp: 6500, color: '#FA4D56', icon: '🏆' },
  { level: 12, rank: 'Champion', minXp: 6500, maxXp: 8000, color: '#FA4D56', icon: '🏆' },
  { level: 13, rank: 'Elite', minXp: 8000, maxXp: 10000, color: '#d4bbff', icon: '⭐' },
  { level: 14, rank: 'Elite', minXp: 10000, maxXp: 12500, color: '#d4bbff', icon: '⭐' },
  { level: 15, rank: 'Master', minXp: 12500, maxXp: 15000, color: '#FFD700', icon: '👑' },
  { level: 16, rank: 'Master', minXp: 15000, maxXp: 20000, color: '#FFD700', icon: '👑' },
  { level: 17, rank: 'Legend', minXp: 20000, maxXp: 30000, color: '#FF6B6B', icon: '🌟' },
  { level: 18, rank: 'Legend', minXp: 30000, maxXp: 50000, color: '#FF6B6B', icon: '🌟' },
  { level: 19, rank: 'Mythic', minXp: 50000, maxXp: 100000, color: '#00FFFF', icon: '💎' },
  { level: 20, rank: 'Mythic', minXp: 100000, maxXp: Infinity, color: '#00FFFF', icon: '💎' },
];

// Achievement definitions
export const ACHIEVEMENTS: Achievement[] = [
  // Scanning achievements
  { id: 'first_scan', name: 'First Steps', description: 'Complete your first security scan', icon: '🔍', category: 'scanning', xpReward: 100, requirement: { type: 'scans', count: 1 }, rarity: 'common' },
  { id: 'scan_10', name: 'Scanner Pro', description: 'Complete 10 security scans', icon: '📡', category: 'scanning', xpReward: 200, requirement: { type: 'scans', count: 10 }, rarity: 'uncommon' },
  { id: 'scan_50', name: 'Vigilant Eye', description: 'Complete 50 security scans', icon: '👁️', category: 'scanning', xpReward: 500, requirement: { type: 'scans', count: 50 }, rarity: 'rare' },
  { id: 'scan_100', name: 'Security Sentinel', description: 'Complete 100 security scans', icon: '🛡️', category: 'scanning', xpReward: 1000, requirement: { type: 'scans', count: 100 }, rarity: 'epic' },

  // Fixing achievements
  { id: 'first_fix', name: 'Bug Squasher', description: 'Fix your first exposure', icon: '🐛', category: 'fixing', xpReward: 50, requirement: { type: 'fixes', count: 1 }, rarity: 'common' },
  { id: 'fix_10', name: 'Exterminator', description: 'Fix 10 exposures', icon: '🔧', category: 'fixing', xpReward: 150, requirement: { type: 'fixes', count: 10 }, rarity: 'common' },
  { id: 'fix_50', name: 'Patch Master', description: 'Fix 50 exposures', icon: '🩹', category: 'fixing', xpReward: 400, requirement: { type: 'fixes', count: 50 }, rarity: 'uncommon' },
  { id: 'fix_100', name: 'Security Hero', description: 'Fix 100 exposures', icon: '🦸', category: 'fixing', xpReward: 800, requirement: { type: 'fixes', count: 100 }, rarity: 'rare' },
  { id: 'fix_500', name: 'Legendary Fixer', description: 'Fix 500 exposures', icon: '⚡', category: 'fixing', xpReward: 2000, requirement: { type: 'fixes', count: 500 }, rarity: 'legendary' },

  // Severity-specific achievements
  { id: 'fix_critical_1', name: 'Critical Responder', description: 'Fix your first critical exposure', icon: '🚨', category: 'fixing', xpReward: 100, requirement: { type: 'severity', count: 1, severity: 'critical' }, rarity: 'common' },
  { id: 'fix_critical_10', name: 'Crisis Manager', description: 'Fix 10 critical exposures', icon: '🔥', category: 'fixing', xpReward: 500, requirement: { type: 'severity', count: 10, severity: 'critical' }, rarity: 'rare' },
  { id: 'fix_critical_50', name: 'Fire Fighter', description: 'Fix 50 critical exposures', icon: '🧯', category: 'fixing', xpReward: 1500, requirement: { type: 'severity', count: 50, severity: 'critical' }, rarity: 'epic' },

  // Streak achievements
  { id: 'streak_3', name: 'On a Roll', description: 'Maintain a 3-day activity streak', icon: '🔥', category: 'streaks', xpReward: 50, requirement: { type: 'streak', count: 3 }, rarity: 'common' },
  { id: 'streak_7', name: 'Week Warrior', description: 'Maintain a 7-day activity streak', icon: '📅', category: 'streaks', xpReward: 150, requirement: { type: 'streak', count: 7 }, rarity: 'uncommon' },
  { id: 'streak_30', name: 'Dedicated Defender', description: 'Maintain a 30-day activity streak', icon: '🌙', category: 'streaks', xpReward: 500, requirement: { type: 'streak', count: 30 }, rarity: 'rare' },
  { id: 'streak_100', name: 'Unstoppable', description: 'Maintain a 100-day activity streak', icon: '💪', category: 'streaks', xpReward: 2000, requirement: { type: 'streak', count: 100 }, rarity: 'legendary' },

  // Milestone achievements
  { id: 'zero_critical', name: 'Clean Slate', description: 'Achieve zero critical exposures in a scan', icon: '✨', category: 'milestones', xpReward: 200, requirement: { type: 'special' }, rarity: 'uncommon' },
  { id: 'perfect_score', name: 'Perfection', description: 'Achieve a risk score of 0', icon: '💯', category: 'milestones', xpReward: 1000, requirement: { type: 'score', scoreThreshold: 0 }, rarity: 'legendary' },
  { id: 'level_5', name: 'Rising Star', description: 'Reach level 5', icon: '⭐', category: 'milestones', xpReward: 100, requirement: { type: 'special' }, rarity: 'common' },
  { id: 'level_10', name: 'Security Expert', description: 'Reach level 10', icon: '🌟', category: 'milestones', xpReward: 300, requirement: { type: 'special' }, rarity: 'uncommon' },
  { id: 'level_15', name: 'Master Guardian', description: 'Reach level 15', icon: '👑', category: 'milestones', xpReward: 750, requirement: { type: 'special' }, rarity: 'rare' },
  { id: 'level_20', name: 'Mythic Legend', description: 'Reach level 20', icon: '💎', category: 'milestones', xpReward: 2000, requirement: { type: 'special' }, rarity: 'legendary' },

  // Special achievements
  { id: 'secret_hunter', name: 'Secret Hunter', description: 'Fix 10 secret exposures', icon: '🔐', category: 'special', xpReward: 300, requirement: { type: 'type', count: 10, exposureType: 'secret' }, rarity: 'uncommon' },
  { id: 'cert_guardian', name: 'Certificate Guardian', description: 'Fix 10 certificate exposures', icon: '📜', category: 'special', xpReward: 300, requirement: { type: 'type', count: 10, exposureType: 'certificate' }, rarity: 'uncommon' },
  { id: 'config_master', name: 'Config Master', description: 'Fix 10 misconfiguration exposures', icon: '⚙️', category: 'special', xpReward: 300, requirement: { type: 'type', count: 10, exposureType: 'misconfiguration' }, rarity: 'uncommon' },
  { id: 'code_ninja', name: 'Code Ninja', description: 'Fix 10 code security issues', icon: '🥷', category: 'special', xpReward: 300, requirement: { type: 'type', count: 10, exposureType: 'code-security' }, rarity: 'uncommon' },
  { id: 'speed_demon', name: 'Speed Demon', description: 'Fix 5 exposures in one day', icon: '⚡', category: 'special', xpReward: 250, requirement: { type: 'special' }, rarity: 'rare' },
  { id: 'all_rounder', name: 'All-Rounder', description: 'Fix at least one of each exposure type', icon: '🎯', category: 'special', xpReward: 500, requirement: { type: 'special' }, rarity: 'epic' },
];

// ============================================================
// AI EXPLANATION TYPES
// ============================================================

export interface ExposureExplanation {
  exposureId: string;
  exposureType: string;
  summary: string;
  riskAnalysis: string;
  businessImpact: string;
  remediation: string[];
  fixedCode?: string;
  priority: string;
  priorityJustification: string;
  generatedAt: string;
}

export interface GeminiSettings {
  apiKey: string;
  enabled: boolean;
  model: string;
  autoExplain: boolean;
}

// Criticality tiers
export const CRITICALITY_TIERS = [
  {
    value: 1,
    label: 'Tier 1 - Non-Critical',
    description: 'Internal tools, development environments',
    examples: 'Dev servers, internal wikis, test environments'
  },
  {
    value: 2,
    label: 'Tier 2 - Low Criticality',
    description: 'Supporting systems with limited impact',
    examples: 'Marketing websites, internal dashboards'
  },
  {
    value: 3,
    label: 'Tier 3 - Moderate Criticality',
    description: 'Important business applications',
    examples: 'CRM systems, HR applications, reporting tools'
  },
  {
    value: 4,
    label: 'Tier 4 - High Criticality',
    description: 'Critical business operations',
    examples: 'Customer portals, order processing, core APIs'
  },
  {
    value: 5,
    label: 'Tier 5 - Mission Critical',
    description: 'Essential for business continuity',
    examples: 'Payment processing, authentication, core databases'
  }
];
