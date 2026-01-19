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
  criticality: number; // 1-5
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
  // New 0-100 scale fields (optional for backward compatibility)
  final?: number;
  breakdown?: RiskScoreBreakdown;
}

// Enhanced risk score with full breakdown (0-100 scale)
export interface EnhancedRiskScore {
  final: number;                    // 0-100 final score
  baseScore: number;                // Raw type-specific base score
  environmentalMultiplier: number;  // Geometric mean of (asset × data × network)
  overrideMultiplier: number;       // Applied override (1.0 if none)
  breakdown: RiskScoreBreakdown;
  // Legacy compatibility (0-10 scale)
  concert: number;
  comprehensive: number;
}

export interface RiskScoreBreakdown {
  assetCriticalityFactor: number;
  dataSensitivityFactor: number;
  networkExposureFactor: number;
  typeSpecificFactors?: Record<string, number>;
}

// Environmental context for scoring
export interface EnvironmentalContext {
  assetCriticality: 1 | 2 | 3 | 4 | 5;  // Tier 1-5
  dataSensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  networkExposure: 'air-gapped' | 'segmented' | 'internal' | 'dmz' | 'internet-facing';
}

// Score override configuration for manual adjustments
export interface ScoreOverride {
  multiplier?: number;       // Manual multiplier (e.g., 0.5 to reduce, 1.5 to increase)
  reason: string;            // Documentation for override
  appliedBy?: string;        // Who applied the override
  appliedAt?: string;        // When override was applied
  expiresAt?: string;        // Optional expiration
}

// Aggregate application risk score
export interface ApplicationRiskScore {
  overall: number;                      // 0-100
  highestCriticalScore: number;
  avgTop5Critical: number;
  avgTop10High: number;
  exposureVolumeContribution: number;
  breakdown: ApplicationRiskBreakdown;
}

export interface ApplicationRiskBreakdown {
  byType: Record<ExposureType, { count: number; avgScore: number; maxScore: number }>;
  bySeverity: Record<ExposureSeverity, { count: number; avgScore: number }>;
  totalExposures: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

// Topology Types
export interface TopologyNode {
  id: string;
  name: string;
  type: 'application' | 'service' | 'database' | 'cache' | 'queue' | 'external' | 'storage' | 'container';
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
  summary?: ScanSummary;
  cves?: CVE[];
  topology?: ApplicationTopology;
  remediationGroups?: RemediationGroup[];
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

// AI Types
export interface AIExplanationRequest {
  cveId: string;
  cveData: CVE;
  applicationContext?: ApplicationContext;
  vulnerableCode?: string;
  technologyStack?: string[];
}

export interface AIExplanationResponse {
  explanation: string;
  tokensUsed: number;
  estimatedCost: number;
}

// ServiceNow Types
export interface ServiceNowConfig {
  instanceUrl: string;
  authMethod: 'oauth' | 'basic' | 'token';
  username?: string;
  password?: string;
  clientId?: string;
  clientSecret?: string;
  token?: string;
  defaultAssignmentGroup?: string;
}

export interface ServiceNowIncidentRequest {
  remediationGroup: RemediationGroup;
  priority: number;
  additionalNotes?: string;
}

export interface ServiceNowIncidentResponse {
  incidentNumber: string;
  sysId: string;
  link: string;
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
  framework?: string; // terraform, kubernetes, cloudformation, etc.
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

// Extended Scan Result with unified exposures
export interface ExtendedScanResult {
  scanId: string;
  status: 'pending' | 'cloning' | 'detecting' | 'scanning' | 'enriching' | 'complete' | 'error';
  progress?: number;
  progressMessage?: string;
  metadata?: ScanMetadata;
  summary?: ExtendedScanSummary;
  exposures?: Exposure[];
  cves?: CVE[]; // Keep for backward compatibility
  topology?: ApplicationTopology;
  remediationGroups?: ExtendedRemediationGroup[];
  financialImpact?: ExtendedFinancialAnalysis;
  complianceStatus?: ExtendedComplianceStatus;
  error?: string;
}

// Extended Summary with exposure breakdown
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
  exposures: string[]; // exposure IDs
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
