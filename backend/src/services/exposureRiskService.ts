import {
  Exposure,
  CVEExposure,
  CertificateExposure,
  SecretExposure,
  MisconfigurationExposure,
  LicenseExposure,
  CodeSecurityExposure,
  ApplicationContext,
  RiskScore,
  EnhancedRiskScore,
  EnvironmentalContext,
  ScoreOverride,
  ApplicationRiskScore,
  ConcertEnvironmentalContext,
  ConcertCVERiskScore,
  ConcertExposureRiskScore
} from '../types';

import {
  cveCalculator,
  secretCalculator,
  certificateCalculator,
  createMisconfigurationCalculator,
  createLicenseCalculator,
  createCodeSecurityCalculator,
  aggregateCalculator,
  BaseExposureCalculator,
  sastDastCalculator,
  SEVERITY_THRESHOLDS,
  SLA_CONFIG
} from './calculators';

// ============================================================
// EXPOSURE RISK SERVICE - IBM Concert Risk Scoring
// Three-Tier Risk Scoring Framework:
// - Formula 1: Concert CVE Risk Score (0.1-10)
// - Formula 2: Concert Exposure Risk Score for SAST/DAST (1-10)
// - Formula 3: Unified Exposure Risk Score (0-100)
// ============================================================

// ============================================================
// FORMULA 1: CONCERT CVE RISK SCORE (0.1-10)
// Score = Severity × Exploitability Factor × Environmental Factor
// ============================================================

/**
 * Calculate Concert CVE Risk Score (Formula 1)
 *
 * This is the IBM Concert methodology for scoring CVEs on a 0.1-10 scale.
 * Uses equilibrium-based EPSS scoring where 0.1 (10%) is the neutral point.
 *
 * @param exposure - CVE exposure to score
 * @param context - Concert environmental context with access points
 * @param lastModifiedDays - Days since CVE was last modified (for fallback severity)
 * @returns ConcertCVERiskScore with full breakdown
 */
export function calculateConcertCVEScore(
  exposure: CVEExposure,
  context?: ConcertEnvironmentalContext,
  lastModifiedDays?: number
): ConcertCVERiskScore {
  return cveCalculator.calculateConcertCVEScore(exposure, context, lastModifiedDays);
}

/**
 * Convert ApplicationContext to ConcertEnvironmentalContext
 */
export function toConcertEnvironmentalContext(context?: ApplicationContext): ConcertEnvironmentalContext | undefined {
  if (!context) return undefined;

  // Map ApplicationContext to ConcertEnvironmentalContext
  const dataSensitivityLevel = mapDataSensitivityToLevel(context.dataSensitivity);

  return {
    applicationCriticality: (context.criticality ?? 3) as 1 | 2 | 3 | 4 | 5,
    dataSensitivity: dataSensitivityLevel,
    publicAccessPoints: context.accessControls?.publicEndpoints ?? 0,
    privateAccessPoints: context.accessControls?.privateEndpoints ?? 0,
  };
}

/**
 * Map DataSensitivity object to numeric level (1-5)
 */
function mapDataSensitivityToLevel(ds?: { pii?: boolean; phi?: boolean; pci?: boolean; tradeSecrets?: boolean }): 1 | 2 | 3 | 4 | 5 {
  if (!ds) return 3; // Default to medium

  // PHI/PCI = Level 5 (Very High - Highly regulated)
  if (ds.phi || ds.pci) return 5;

  // PII = Level 4 (High - Confidential)
  if (ds.pii) return 4;

  // Trade secrets = Level 4 (High - Confidential)
  if (ds.tradeSecrets) return 4;

  // Default = Level 3 (Medium - Internal)
  return 3;
}

// ============================================================
// FORMULA 2: CONCERT EXPOSURE RISK SCORE (1-10)
// For SAST/DAST findings
// Score = Severity × Environmental Factor
// ============================================================

/**
 * Calculate Concert Exposure Risk Score for SAST findings (Formula 2)
 *
 * Uses the 5-tier SAST severity scale (Blocker, High, Medium, Low, Info)
 * multiplied by environmental factors.
 *
 * @param severityLevel - SAST severity level
 * @param context - Concert environmental context
 * @returns ConcertExposureRiskScore with full breakdown
 */
export function calculateSASTScore(
  severityLevel: string,
  context?: ConcertEnvironmentalContext
): ConcertExposureRiskScore {
  return sastDastCalculator.calculateSASTScore(severityLevel, context);
}

/**
 * Calculate Concert Exposure Risk Score for DAST findings (Formula 2)
 *
 * Uses the 15-tier DAST severity scale with confidence levels
 * (e.g., "High (High)", "Medium (Low)")
 *
 * @param severityLevel - DAST severity level with optional confidence
 * @param context - Concert environmental context
 * @returns ConcertExposureRiskScore with full breakdown
 */
export function calculateDASTScore(
  severityLevel: string,
  context?: ConcertEnvironmentalContext
): ConcertExposureRiskScore {
  return sastDastCalculator.calculateDASTScore(severityLevel, context);
}

/**
 * Calculate Concert Exposure Risk Score from CodeSecurityExposure
 *
 * Auto-detects tool type (SAST/DAST) from exposure properties.
 *
 * @param exposure - Code security exposure to score
 * @param toolType - Optional tool type override
 * @param context - Concert environmental context
 * @returns ConcertExposureRiskScore with full breakdown
 */
export function calculateCodeSecurityConcertScore(
  exposure: CodeSecurityExposure,
  toolType?: 'sast' | 'dast',
  context?: ConcertEnvironmentalContext
): ConcertExposureRiskScore {
  return sastDastCalculator.calculateFromExposure(exposure, toolType, context);
}

// ============================================================
// FORMULA 3: UNIFIED EXPOSURE RISK SCORE (0-100)
// Main unified scoring for all exposure types
// ============================================================

// ============================================================
// MAIN RISK CALCULATION FUNCTIONS
// ============================================================

/**
 * Calculate enhanced risk score for any exposure type (0-100 scale)
 * This is the new primary scoring function
 */
export function calculateExposureRiskV2(
  exposure: Exposure,
  context?: ApplicationContext,
  override?: ScoreOverride
): EnhancedRiskScore {
  // Convert ApplicationContext to EnvironmentalContext
  const envContext = BaseExposureCalculator.toEnvironmentalContext(context);

  switch (exposure.type) {
    case 'cve':
      return cveCalculator.calculateFinalScore(exposure as CVEExposure, envContext, override);

    case 'secret':
      return secretCalculator.calculateFinalScore(exposure as SecretExposure, envContext, override);

    case 'certificate':
      return certificateCalculator.calculateFinalScore(exposure as CertificateExposure, envContext, override);

    case 'misconfiguration': {
      const misconfigCalc = createMisconfigurationCalculator(context);
      return misconfigCalc.calculateFinalScore(exposure as MisconfigurationExposure, envContext, override);
    }

    case 'license': {
      const licenseCalc = createLicenseCalculator(context);
      return licenseCalc.calculateFinalScore(exposure as LicenseExposure, envContext, override);
    }

    case 'code-security': {
      const codeSecCalc = createCodeSecurityCalculator(context);
      return codeSecCalc.calculateFinalScore(exposure as CodeSecurityExposure, envContext, override);
    }

    default:
      // Return default score for unknown types
      return {
        final: 50,
        baseScore: 50,
        environmentalMultiplier: 1.0,
        overrideMultiplier: 1.0,
        breakdown: {
          assetCriticalityFactor: 1.0,
          dataSensitivityFactor: 1.0,
          networkExposureFactor: 1.0,
        },
        concert: 5.0,
        comprehensive: 5.0,
      };
  }
}

/**
 * Calculate risk score with backward compatibility (0-10 scale)
 * This wraps the new v2 function for existing code
 */
export function calculateExposureRisk(
  exposure: Exposure,
  context?: ApplicationContext
): RiskScore {
  const enhanced = calculateExposureRiskV2(exposure, context);

  return {
    concert: enhanced.concert,
    comprehensive: enhanced.comprehensive,
    final: enhanced.final,
    breakdown: enhanced.breakdown,
  };
}

/**
 * Calculate overall application risk score from all exposures
 */
export function calculateOverallApplicationRisk(exposures: Exposure[]): ApplicationRiskScore {
  return aggregateCalculator.calculateOverallRiskScore(exposures);
}

/**
 * Calculate Bayesian aggregate score (alternative aggregation)
 */
export function calculateBayesianRisk(exposures: Exposure[], topN: number = 20): number {
  return aggregateCalculator.calculateBayesianAggregateScore(exposures, topN);
}

// ============================================================
// BATCH PROCESSING
// ============================================================

/**
 * Process all exposures with new scoring (returns enhanced scores)
 */
export function processExposuresV2(
  exposures: Exposure[],
  context?: ApplicationContext
): Exposure[] {
  return exposures.map(exposure => ({
    ...exposure,
    riskScore: calculateExposureRisk(exposure, context),
  }));
}

/**
 * Process exposures with backward compatibility
 */
export function processExposures(
  exposures: Exposure[],
  context?: ApplicationContext
): Exposure[] {
  return processExposuresV2(exposures, context);
}

// ============================================================
// SLA CALCULATION
// ============================================================

/**
 * Calculate SLA deadline for an exposure
 */
export function calculateSLADeadline(
  exposure: Exposure,
  context?: ApplicationContext
): { deadline: string; status: 'overdue' | 'due_soon' | 'on_track'; daysRemaining: number } {
  const now = new Date();
  const detectedDate = new Date(exposure.detectedAt);
  let slaHours: number;

  // Secrets are ALWAYS immediate
  if (exposure.type === 'secret') {
    slaHours = SLA_CONFIG.secretsImmediate;
  }
  // Certificates based on days until expiration
  else if (exposure.type === 'certificate') {
    const certExposure = exposure as CertificateExposure;
    if (certExposure.isExpired || certExposure.daysUntilExpiration <= 0) {
      slaHours = SLA_CONFIG.certificates.expired;
    } else if (certExposure.daysUntilExpiration <= 7) {
      slaHours = SLA_CONFIG.certificates.within7Days;
    } else if (certExposure.daysUntilExpiration <= 30) {
      slaHours = SLA_CONFIG.certificates.within30Days;
    } else if (certExposure.daysUntilExpiration <= 90) {
      slaHours = SLA_CONFIG.certificates.within90Days;
    } else {
      slaHours = SLA_CONFIG.certificates.default;
    }
  }
  // Licenses have longer timelines (legal process)
  else if (exposure.type === 'license') {
    const riskScore = exposure.riskScore?.final ?? (exposure.riskScore?.concert ?? 5) * 10;
    slaHours = riskScore >= 70 ? SLA_CONFIG.licenses.high : SLA_CONFIG.licenses.default;
  }
  // Other types: risk-based SLA
  else {
    const tier = context?.criticality ?? 3;
    const riskScore = exposure.riskScore?.final ?? (exposure.riskScore?.concert ?? 5) * 10;

    // Map tier to config key
    const tierKey = `tier${tier}` as keyof typeof SLA_CONFIG.byRiskScore.critical;

    if (riskScore >= SEVERITY_THRESHOLDS.critical) {
      slaHours = SLA_CONFIG.byRiskScore.critical[tierKey] ?? 168;
    } else if (riskScore >= SEVERITY_THRESHOLDS.high) {
      slaHours = SLA_CONFIG.byRiskScore.high[tierKey] ?? 336;
    } else if (riskScore >= SEVERITY_THRESHOLDS.medium) {
      slaHours = SLA_CONFIG.byRiskScore.medium[tierKey] ?? 720;
    } else {
      slaHours = SLA_CONFIG.byRiskScore.low[tierKey] ?? 2160;
    }
  }

  const deadlineDate = new Date(detectedDate.getTime() + slaHours * 60 * 60 * 1000);
  const daysRemaining = Math.ceil((deadlineDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  // Determine status based on days remaining AND severity
  // Critical/High severity items are marked as compliance concerns even on new scans
  const riskScore = exposure.riskScore?.final ?? (exposure.riskScore?.concert ?? 5) * 10;
  const isCriticalSeverity = riskScore >= SEVERITY_THRESHOLDS.critical || exposure.severity === 'critical';
  const isHighSeverity = riskScore >= SEVERITY_THRESHOLDS.high || exposure.severity === 'high';
  const isSecret = exposure.type === 'secret';
  const isExpiredCert = exposure.type === 'certificate' && (exposure as CertificateExposure).isExpired;

  let status: 'overdue' | 'due_soon' | 'on_track';
  if (daysRemaining < 0 || isExpiredCert) {
    status = 'overdue';
  } else if (daysRemaining <= 7 || isCriticalSeverity || isSecret) {
    // Critical severity and secrets are ALWAYS "due_soon" - they need immediate attention
    status = 'due_soon';
  } else if (daysRemaining <= 14 && isHighSeverity) {
    // High severity items are "due_soon" if within 2 weeks
    status = 'due_soon';
  } else {
    status = 'on_track';
  }

  return {
    deadline: deadlineDate.toISOString(),
    status,
    daysRemaining,
  };
}

/**
 * Apply SLA to all exposures
 */
export function applySLAToExposures(
  exposures: Exposure[],
  context?: ApplicationContext
): Exposure[] {
  return exposures.map(exposure => {
    const sla = calculateSLADeadline(exposure, context);
    return {
      ...exposure,
      slaDeadline: sla.deadline,
      slaStatus: sla.status,
      daysRemaining: sla.daysRemaining,
    };
  });
}

// ============================================================
// OVERALL RISK SCORE - Legacy Functions (Backward Compatibility)
// ============================================================

/**
 * Concert Score (0-10): Quick executive summary
 * Now uses new aggregate calculator internally
 */
export function calculateOverallConcertScore(exposures: Exposure[]): number {
  if (exposures.length === 0) return 0;

  const appRisk = calculateOverallApplicationRisk(exposures);
  // Convert 0-100 to 0-10
  return Math.round(appRisk.overall / 10 * 10) / 10;
}

/**
 * Detailed/Comprehensive Score (0-10)
 *
 * More nuanced calculation that factors in:
 * - EPSS exploitation probability (likelihood of real-world attack)
 * - KEV status (actively exploited vulnerabilities)
 * - Exposure type diversity (multiple types = broader attack surface)
 * - SLA compliance (overdue items increase urgency)
 * - Severity distribution (not just count, but concentration)
 *
 * Formula:
 * Base = Concert Score
 * + EPSS Factor: avg(EPSS) × 1.5 (if high exploitation probability)
 * + KEV Factor: (kevCount / totalCVEs) × 2 (actively exploited = urgent)
 * + Diversity Penalty: (uniqueTypes - 1) × 0.3 (broader attack surface)
 * + SLA Factor: (overdueCount / total) × 1.5 (compliance urgency)
 *
 * Capped at 10
 */
export function calculateOverallDetailedScore(exposures: Exposure[]): number {
  if (exposures.length === 0) return 0;

  // Start with concert score as base
  const concertScore = calculateOverallConcertScore(exposures);

  // Get CVE-specific data
  const cves = exposures.filter(e => e.type === 'cve') as CVEExposure[];

  // 1. EPSS Factor - high exploitation probability increases risk
  const avgEPSS = cves.length > 0
    ? cves.reduce((sum, c) => sum + (c.epss || 0), 0) / cves.length
    : 0;
  const epssFactor = avgEPSS > 0.1 ? avgEPSS * 1.5 : avgEPSS * 0.5; // High EPSS (>10%) weighted more

  // 2. KEV Factor - actively exploited vulnerabilities are critical
  const kevCount = cves.filter(c => c.cisaKEV).length;
  const kevFactor = cves.length > 0 ? (kevCount / cves.length) * 2 : 0;

  // 3. Exposure Type Diversity - multiple types = broader attack surface
  const uniqueTypes = new Set(exposures.map(e => e.type)).size;
  const diversityPenalty = (uniqueTypes - 1) * 0.2; // Each additional type adds 0.2

  // 4. SLA Compliance Factor - overdue items increase urgency
  const overdueCount = exposures.filter(e => e.slaStatus === 'overdue').length;
  const slaFactor = exposures.length > 0 ? (overdueCount / exposures.length) * 1.5 : 0;

  // 5. Severity Concentration - more criticals in proportion = higher risk
  const criticalCount = exposures.filter(e => e.severity === 'critical').length;
  const criticalConcentration = exposures.length > 0
    ? (criticalCount / exposures.length) * 0.5
    : 0;

  // Calculate detailed score
  const detailedScore = concertScore + epssFactor + kevFactor + diversityPenalty + slaFactor + criticalConcentration;

  // Cap at 10 and round to 1 decimal
  return Math.round(Math.min(10, detailedScore) * 10) / 10;
}

/**
 * Combined overall risk score
 */
export function calculateOverallRiskScore(exposures: Exposure[]): number {
  return calculateOverallConcertScore(exposures);
}

/**
 * Get both scores with calculation breakdown
 */
export function calculateRiskScoresWithBreakdown(exposures: Exposure[]): {
  concert: number;
  detailed: number;
  breakdown: {
    totalExposures: number;
    criticalCount: number;
    highCount: number;
    secretsCount: number;
    kevCount: number;
    overdueCount: number;
    avgEPSS: number;
    exposureTypes: string[];
  };
  detailedFactors: {
    epssFactor: number;
    kevFactor: number;
    diversityPenalty: number;
    slaFactor: number;
    criticalConcentration: number;
  };
} {
  const appRisk = calculateOverallApplicationRisk(exposures);
  const cves = exposures.filter(e => e.type === 'cve') as CVEExposure[];

  // Calculate detailed score factors
  const avgEPSS = cves.length > 0
    ? cves.reduce((sum, c) => sum + (c.epss || 0), 0) / cves.length
    : 0;
  const epssFactor = avgEPSS > 0.1 ? avgEPSS * 1.5 : avgEPSS * 0.5;
  const kevCount = cves.filter(c => c.cisaKEV).length;
  const kevFactor = cves.length > 0 ? (kevCount / cves.length) * 2 : 0;
  const uniqueTypes = new Set(exposures.map(e => e.type)).size;
  const diversityPenalty = (uniqueTypes - 1) * 0.2;
  const overdueCount = exposures.filter(e => e.slaStatus === 'overdue').length;
  const slaFactor = exposures.length > 0 ? (overdueCount / exposures.length) * 1.5 : 0;
  const criticalCount = exposures.filter(e => e.severity === 'critical').length;
  const criticalConcentration = exposures.length > 0 ? (criticalCount / exposures.length) * 0.5 : 0;

  return {
    concert: calculateOverallConcertScore(exposures),
    detailed: calculateOverallDetailedScore(exposures),
    breakdown: {
      totalExposures: exposures.length,
      criticalCount: appRisk.breakdown.criticalCount,
      highCount: appRisk.breakdown.highCount,
      secretsCount: appRisk.breakdown.byType.secret?.count ?? 0,
      kevCount,
      overdueCount,
      avgEPSS: Math.round(avgEPSS * 100) / 100,
      exposureTypes: [...new Set(exposures.map(e => e.type))],
    },
    detailedFactors: {
      epssFactor: Math.round(epssFactor * 100) / 100,
      kevFactor: Math.round(kevFactor * 100) / 100,
      diversityPenalty: Math.round(diversityPenalty * 100) / 100,
      slaFactor: Math.round(slaFactor * 100) / 100,
      criticalConcentration: Math.round(criticalConcentration * 100) / 100,
    },
  };
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Get severity level from score
 */
export function getSeverityFromScore(score: number): 'critical' | 'high' | 'medium' | 'low' {
  return BaseExposureCalculator.getSeverityFromScore(score);
}

/**
 * Convert environmental context
 */
export function toEnvironmentalContext(context?: ApplicationContext): EnvironmentalContext | undefined {
  return BaseExposureCalculator.toEnvironmentalContext(context);
}
