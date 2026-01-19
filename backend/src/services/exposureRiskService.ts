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
  ApplicationRiskScore
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
  SEVERITY_THRESHOLDS,
  SLA_CONFIG
} from './calculators';

// ============================================================
// EXPOSURE RISK SERVICE - Unified Risk Scoring (v2)
// Uses new 0-100 scale calculators with backward compatibility
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

  let status: 'overdue' | 'due_soon' | 'on_track';
  if (daysRemaining < 0) {
    status = 'overdue';
  } else if (daysRemaining <= 7) {
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
 * Uses same calculation as concert for consistency
 */
export function calculateOverallDetailedScore(exposures: Exposure[]): number {
  return calculateOverallConcertScore(exposures);
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
} {
  const appRisk = calculateOverallApplicationRisk(exposures);
  const cves = exposures.filter(e => e.type === 'cve') as CVEExposure[];

  return {
    concert: Math.round(appRisk.overall / 10 * 10) / 10,
    detailed: Math.round(appRisk.overall / 10 * 10) / 10,
    breakdown: {
      totalExposures: exposures.length,
      criticalCount: appRisk.breakdown.criticalCount,
      highCount: appRisk.breakdown.highCount,
      secretsCount: appRisk.breakdown.byType.secret?.count ?? 0,
      kevCount: cves.filter(c => c.cisaKEV).length,
      overdueCount: exposures.filter(e => e.slaStatus === 'overdue').length,
      avgEPSS: cves.length > 0
        ? Math.round(cves.reduce((sum, c) => sum + (c.epss || 0), 0) / cves.length * 100) / 100
        : 0,
      exposureTypes: [...new Set(exposures.map(e => e.type))],
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
