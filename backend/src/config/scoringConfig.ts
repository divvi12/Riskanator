// ============================================================
// UNIFIED EXPOSURE RISK SCORING CONFIGURATION
// All scoring multipliers and constants for the 0-100 scale
// ============================================================

// ============================================================
// CVE SCORING CONFIGURATION
// Formula: (CVSS × 2.5) + (EPSS × 35) + (KEV ? 40 : 0)
// KEV automatically scores 100
// ============================================================
export const CVE_SCORING = {
  cvssMultiplier: 2.5,      // CVSS 0-10 → 0-25 points
  epssMultiplier: 35,       // EPSS 0-1 → 0-35 points
  kevBonus: 40,             // KEV adds 40 points
  kevAutoScore: 100,        // KEV = automatic Critical (100)
} as const;

// ============================================================
// SECRET SCORING CONFIGURATION
// Formula: BaseTypeSeverity × ValidityMultiplier × ContextMultiplier
// ============================================================
export const SECRET_SCORING = {
  baseTypeSeverity: {
    aws: 95,
    azure: 95,
    gcp: 95,
    db_password: 90,
    private_key: 95,
    api_key: 85,
    oauth: 80,
    token: 80,
    password: 85,
    generic: 70,
  } as Record<string, number>,

  validityMultiplier: {
    verified_active: 1.0,
    verified: 1.0,          // Alias for verified_active
    unknown: 0.7,
    unverified: 0.7,        // Alias for unknown
    revoked: 0.3,
  } as Record<string, number>,

  contextMultiplier: {
    production: 1.2,
    config_file: 1.1,
    default_branch: 1.15,
    test_dev: 0.5,
    git_history: 1.3,       // Applied additively if in git history
  } as Record<string, number>,
} as const;

// ============================================================
// CERTIFICATE SCORING CONFIGURATION
// Formula: max(0, 100 - (days / 1.8)) × AlgorithmModifier × CertTypeMultiplier
// ============================================================
export const CERTIFICATE_SCORING = {
  // Days until expiration divisor (180 days = 0 score)
  daysUntilExpirationDivisor: 1.8,

  algorithmModifier: {
    sha1: 1.2,
    'sha-1': 1.2,
    md5: 1.3,
    rsa1024: 1.2,
    'rsa-1024': 1.2,
    sha256: 1.0,
    'sha-256': 1.0,
    sha384: 1.0,
    sha512: 1.0,
    rsa2048: 1.0,
    'rsa-2048': 1.0,
    rsa4096: 1.0,
    'rsa-4096': 1.0,
    ecdsa: 1.0,
    ed25519: 1.0,
  } as Record<string, number>,

  certTypeMultiplier: {
    customer_facing: 1.3,
    ssl: 1.3,               // Alias for customer_facing
    'code-signing': 1.1,
    code_signing: 1.1,
    internal: 1.0,
    client: 1.0,
    dev_test: 0.7,
    other: 1.0,
  } as Record<string, number>,
} as const;

// ============================================================
// MISCONFIGURATION SCORING CONFIGURATION
// Formula: ScannerSeverity × ExposureMultiplier × DataMultiplier
// ============================================================
export const MISCONFIGURATION_SCORING = {
  scannerSeverity: {
    critical: { min: 90, max: 100, default: 95 },
    high: { min: 70, max: 89, default: 80 },
    medium: { min: 40, max: 69, default: 55 },
    low: { min: 10, max: 39, default: 25 },
  } as Record<string, { min: number; max: number; default: number }>,

  exposureMultiplier: {
    internet_facing: 1.5,
    'internet-facing': 1.5,
    public_ip_firewalled: 1.2,
    dmz: 1.2,
    internal: 1.0,
    isolated: 0.7,
    segmented: 0.7,
  } as Record<string, number>,

  dataMultiplier: {
    pii_phi_financial: 1.4,
    pii: 1.3,
    phi: 1.4,
    pci: 1.4,
    sensitive_business: 1.2,
    confidential: 1.2,
    non_sensitive: 1.0,
    internal: 1.0,
    public: 0.9,
  } as Record<string, number>,
} as const;

// ============================================================
// LICENSE SCORING CONFIGURATION
// Formula: RiskTier × DistributionMultiplier × ModificationFactor
// ============================================================
export const LICENSE_SCORING = {
  riskTier: {
    'AGPL-3.0': 90,
    'AGPL-3.0-only': 90,
    'AGPL-3.0-or-later': 90,
    'GPL-3.0': 75,
    'GPL-3.0-only': 75,
    'GPL-3.0-or-later': 75,
    'GPL-2.0': 75,
    'GPL-2.0-only': 75,
    'GPL-2.0-or-later': 75,
    'LGPL-3.0': 50,
    'LGPL-2.1': 50,
    'LGPL-2.0': 50,
    'MPL-2.0': 50,
    'MPL-1.1': 50,
    UNKNOWN: 70,
    'UNLICENSED': 70,
    'EPL-1.0': 40,
    'EPL-2.0': 40,
    'CPL-1.0': 40,
    'CDDL-1.0': 40,
    // Permissive licenses (low risk)
    'MIT': 10,
    'Apache-2.0': 10,
    'BSD-2-Clause': 10,
    'BSD-3-Clause': 10,
    'ISC': 10,
    'Unlicense': 10,
    '0BSD': 10,
    'CC0-1.0': 10,
    'WTFPL': 10,
    'Zlib': 10,
  } as Record<string, number>,

  distributionMultiplier: {
    saas: 1.3,
    commercial: 1.2,
    proprietary: 1.2,
    internal: 0.8,
    open_source: 0.5,
  } as Record<string, number>,

  modificationFactor: {
    modified: 1.2,
    unmodified: 1.0,
  } as Record<string, number>,
} as const;

// ============================================================
// CODE SECURITY SCORING CONFIGURATION
// Formula: CWESeverity × ConfidenceFactor × ReachabilityFactor
// ============================================================
export const CODE_SECURITY_SCORING = {
  cweSeverity: {
    sql_injection: 90,      // CWE-89
    command_injection: 90,  // CWE-78
    code_injection: 90,     // CWE-94
    xss: 85,                // CWE-79
    path_traversal: 75,     // CWE-22
    insecure_deserialization: 85, // CWE-502
    broken_auth: 80,        // CWE-287
    hardcoded_secret: 85,   // CWE-798
    weak_cryptography: 60,  // CWE-327/328
    insecure_randomness: 50, // CWE-330
    open_redirect: 55,      // CWE-601
    information_disclosure: 45, // CWE-200
    security_misconfiguration: 60, // CWE-16
    xxe: 80,                // CWE-611
    ssrf: 75,               // CWE-918
    idor: 70,               // CWE-639
    code_smell: 20,
    other: 50,
  } as Record<string, number>,

  confidenceFactor: {
    high: 1.0,
    medium: 0.8,
    low: 0.5,
  } as Record<string, number>,

  reachabilityFactor: {
    public_endpoint: 1.3,
    user_input: 1.3,
    authenticated: 1.1,
    internal: 0.9,
    dead_code: 0.3,
    unreachable: 0.3,
  } as Record<string, number>,
} as const;

// ============================================================
// ENVIRONMENTAL FACTORS CONFIGURATION
// Environmental Multiplier = ∛(Asset × Data × Network)
// ============================================================
export const ENVIRONMENTAL_FACTORS = {
  assetCriticality: {
    5: 1.5,   // Tier 5 - Mission Critical
    4: 1.25,  // Tier 4 - Business Critical
    3: 1.0,   // Tier 3 - Business Important
    2: 0.8,   // Tier 2 - Business Support
    1: 0.6,   // Tier 1 - Non-Critical
  } as Record<number, number>,

  dataSensitivity: {
    restricted: 1.4,        // PII/PHI/PCI
    confidential: 1.2,
    internal: 1.0,
    public: 0.7,
  } as Record<string, number>,

  networkExposure: {
    'internet-facing': 1.5,
    'internet_facing': 1.5,
    public: 1.5,
    dmz: 1.2,
    internal: 1.0,
    segmented: 0.8,
    'air-gapped': 0.6,
    airgapped: 0.6,
  } as Record<string, number>,
} as const;

// ============================================================
// AGGREGATE SCORING CONFIGURATION
// Overall = (MaxCritical × 0.4) + (AvgTop5 × 0.3) + (AvgTop10High × 0.2) + (log10(n) × 2)
// ============================================================
export const AGGREGATE_WEIGHTS = {
  highestCritical: 0.4,     // Weight for highest critical score
  avgTop5Critical: 0.3,     // Weight for average of top 5 criticals
  avgTop10High: 0.2,        // Weight for average of top 10 highs
  volumeMultiplier: 2,      // Multiplier for log10(total_exposures)
  maxScore: 100,            // Maximum possible score
} as const;

// ============================================================
// SEVERITY THRESHOLDS
// Used to categorize final scores into severity levels
// ============================================================
export const SEVERITY_THRESHOLDS = {
  critical: 90,   // Score >= 90 = Critical
  high: 70,       // Score >= 70 = High
  medium: 40,     // Score >= 40 = Medium
  low: 0,         // Score >= 0 = Low
} as const;

// ============================================================
// SLA CONFIGURATION
// SLA hours based on severity and asset criticality
// ============================================================
export const SLA_CONFIG = {
  // Hours by severity and tier
  byRiskScore: {
    critical: { tier5: 24, tier4: 48, tier3: 168, tier2: 336, tier1: 336 },  // 1d, 2d, 7d, 14d, 14d
    high: { tier5: 168, tier4: 336, tier3: 720, tier2: 720, tier1: 1440 },   // 7d, 14d, 30d, 30d, 60d
    medium: { tier5: 720, tier4: 1080, tier3: 1440, tier2: 2160, tier1: 2160 }, // 30d, 45d, 60d, 90d, 90d
    low: { tier5: 1440, tier4: 2160, tier3: 2160, tier2: 2160, tier1: 2160 }, // 60d, 90d, 90d, 90d, 90d
  },

  // Secrets are always immediate
  secretsImmediate: 0,

  // Certificates based on days until expiration
  certificates: {
    expired: 24,        // 1 day
    within7Days: 24,    // 1 day
    within30Days: 168,  // 7 days
    within90Days: 720,  // 30 days
    default: 720,       // 30 days
  },

  // Licenses have longer timelines (legal process)
  licenses: {
    high: 1440,         // 60 days
    default: 2160,      // 90 days
  },
} as const;

// ============================================================
// TYPE EXPORTS FOR STRONG TYPING
// ============================================================
export type SecretType = keyof typeof SECRET_SCORING.baseTypeSeverity;
export type ValidityStatus = keyof typeof SECRET_SCORING.validityMultiplier;
export type ContextType = keyof typeof SECRET_SCORING.contextMultiplier;
export type AlgorithmType = keyof typeof CERTIFICATE_SCORING.algorithmModifier;
export type CertType = keyof typeof CERTIFICATE_SCORING.certTypeMultiplier;
export type SeverityLevel = keyof typeof MISCONFIGURATION_SCORING.scannerSeverity;
export type ExposureLevel = keyof typeof MISCONFIGURATION_SCORING.exposureMultiplier;
export type DataLevel = keyof typeof MISCONFIGURATION_SCORING.dataMultiplier;
export type LicenseType = keyof typeof LICENSE_SCORING.riskTier;
export type DistributionType = keyof typeof LICENSE_SCORING.distributionMultiplier;
export type IssueType = keyof typeof CODE_SECURITY_SCORING.cweSeverity;
export type ConfidenceLevel = keyof typeof CODE_SECURITY_SCORING.confidenceFactor;
export type ReachabilityLevel = keyof typeof CODE_SECURITY_SCORING.reachabilityFactor;
export type AssetTier = keyof typeof ENVIRONMENTAL_FACTORS.assetCriticality;
export type DataSensitivityLevel = keyof typeof ENVIRONMENTAL_FACTORS.dataSensitivity;
export type NetworkExposureLevel = keyof typeof ENVIRONMENTAL_FACTORS.networkExposure;
