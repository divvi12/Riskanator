import { CVEExposure, ConcertEnvironmentalContext, ConcertCVERiskScore } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import {
  CVE_SCORING,
  EPSS_EXPLOITABILITY_FACTOR,
  APP_CRITICALITY_F1,
  DATA_SENSITIVITY_F1,
  PUBLIC_ACCESS_POINTS,
  PRIVATE_ACCESS_POINTS
} from '../../config/scoringConfig';

// ============================================================
// CVE CALCULATOR
// Implements both Formula 1 (Concert CVE 0.1-10) and Formula 3 (Unified 0-100)
// ============================================================

export class CVECalculator extends BaseExposureCalculator<CVEExposure> {

  // ============================================================
  // FORMULA 1: Concert CVE Risk Score (0.1-10)
  // Score = Severity × Exploitability Factor × Environmental Factor
  // ============================================================

  /**
   * Calculate Concert CVE Risk Score (Formula 1)
   *
   * Formula: Severity × Exploitability Factor × Environmental Factor
   * - Severity: CVSS score 0-10 (with fallback logic for missing CVSS)
   * - Exploitability Factor: 0.5-1.25 based on EPSS with equilibrium at 0.1
   * - Environmental Factor: 0.25-1.25 based on app criticality, data sensitivity, access points
   *
   * @param exposure - The CVE exposure to score
   * @param context - Concert environmental context with access points
   * @param lastModifiedDays - Days since CVE was last modified (for fallback severity)
   * @returns ConcertCVERiskScore with full breakdown
   */
  calculateConcertCVEScore(
    exposure: CVEExposure,
    context?: ConcertEnvironmentalContext,
    lastModifiedDays?: number
  ): ConcertCVERiskScore {
    // 1. Calculate Severity (CVSS or fallback)
    const severity = this.getSeverityWithFallback(exposure.cvss, lastModifiedDays);

    // 2. Calculate Exploitability Factor from EPSS
    const exploitabilityFactor = this.getExploitabilityFactor(exposure.epss ?? 0);

    // 3. Calculate Environmental Factor
    const { factor: environmentalFactor, breakdown } = this.getEnvironmentalFactorF1(context);

    // 4. Calculate final score
    const rawScore = severity * exploitabilityFactor * environmentalFactor;
    const score = Math.min(10, Math.max(0.1, rawScore));

    return {
      score: Math.round(score * 100) / 100, // Round to 2 decimal places
      severity,
      exploitabilityFactor,
      environmentalFactor,
      breakdown
    };
  }

  /**
   * Get severity with fallback logic for missing CVSS
   * - If CVSS available: use it
   * - If new CVE (within 60 days): assume 10.0 (critical)
   * - Otherwise: assume 5.0 (medium)
   */
  private getSeverityWithFallback(cvss: number | undefined, lastModifiedDays?: number): number {
    if (cvss !== undefined && cvss !== null) {
      return Math.max(0.1, Math.min(10, cvss));
    }

    // Fallback for missing CVSS
    if (lastModifiedDays !== undefined && lastModifiedDays <= CVE_SCORING.newCveThresholdDays) {
      return CVE_SCORING.newCveDefaultScore; // 10.0 for new CVEs
    }

    return CVE_SCORING.oldCveDefaultScore; // 5.0 default
  }

  /**
   * Get Exploitability Factor from EPSS using equilibrium-based mapping
   * Equilibrium point: EPSS = 0.1 (factor = 1.0)
   * - Values below 0.1 reduce the score (0.5-0.8)
   * - Values above 0.1 increase the score (1.1-1.25)
   */
  private getExploitabilityFactor(epss: number): number {
    // Find the matching range
    for (const range of EPSS_EXPLOITABILITY_FACTOR.ranges) {
      if (epss >= range.min && epss < range.max) {
        return range.factor;
      }
    }

    // Handle edge cases
    if (epss >= 0.9) return EPSS_EXPLOITABILITY_FACTOR.maximum;
    if (epss < 0.0001) return EPSS_EXPLOITABILITY_FACTOR.minimum;

    return EPSS_EXPLOITABILITY_FACTOR.default;
  }

  /**
   * Get Environmental Factor for Formula 1
   * Formula: (Application Criticality + Data Sensitivity + Access Points) / 3
   * With graceful degradation if components are unavailable
   */
  private getEnvironmentalFactorF1(context?: ConcertEnvironmentalContext): {
    factor: number;
    breakdown: {
      applicationCriticalityFactor: number;
      dataSensitivityFactor: number;
      accessPointsFactor: number;
    };
  } {
    const components: number[] = [];
    let appCritFactor = 1.0;
    let dataSensFactor = 1.0;
    let accessPointsFactor = 1.0;

    if (context) {
      // Application Criticality
      if (context.applicationCriticality >= 1 && context.applicationCriticality <= 5) {
        appCritFactor = APP_CRITICALITY_F1[context.applicationCriticality] ?? 1.0;
        components.push(appCritFactor);
      }

      // Data Sensitivity
      if (context.dataSensitivity >= 1 && context.dataSensitivity <= 5) {
        dataSensFactor = DATA_SENSITIVITY_F1[context.dataSensitivity] ?? 1.0;
        components.push(dataSensFactor);
      }

      // Access Points - public takes precedence over private
      if (context.publicAccessPoints > 0) {
        const publicCount = Math.min(context.publicAccessPoints, 16);
        accessPointsFactor = PUBLIC_ACCESS_POINTS[publicCount] ?? 1.25;
        components.push(accessPointsFactor);
      } else if (context.privateAccessPoints > 0) {
        const privateCount = Math.min(context.privateAccessPoints, 4);
        accessPointsFactor = PRIVATE_ACCESS_POINTS[privateCount] ?? 1.0;
        components.push(accessPointsFactor);
      }
    }

    // Calculate average of available components (graceful degradation)
    const factor = components.length > 0
      ? components.reduce((sum, c) => sum + c, 0) / components.length
      : 1.0; // Neutral if no context

    return {
      factor: Math.round(factor * 1000) / 1000, // Round to 3 decimal places
      breakdown: {
        applicationCriticalityFactor: appCritFactor,
        dataSensitivityFactor: dataSensFactor,
        accessPointsFactor: accessPointsFactor
      }
    };
  }

  // ============================================================
  // FORMULA 3: Unified Exposure Risk Score (0-100)
  // Formula: (CVSS × 2.5) + (EPSS × 35) + (KEV ? 40 : 0)
  // ============================================================

  /**
   * Calculate base score for CVE exposure (Formula 3)
   *
   * Formula:
   * - If CISA KEV: automatic 100 (Critical)
   * - Otherwise: (CVSS × 2.5) + (EPSS × 35) capped at 100
   *
   * Example calculations:
   * - Log4Shell (CVSS 10.0, EPSS 0.892, KEV=true): 100 (auto-critical)
   * - Medium CVE (CVSS 6.0, EPSS 0.05, KEV=false): (6.0×2.5)+(0.05×35) = 15+1.75 = 16.75
   * - High CVE (CVSS 8.5, EPSS 0.3, KEV=false): (8.5×2.5)+(0.3×35) = 21.25+10.5 = 31.75
   */
  calculateBaseScore(exposure: CVEExposure): number {
    // CISA KEV = automatic Critical (100)
    if (exposure.cisaKEV) {
      return CVE_SCORING.kevAutoScore;
    }

    // Get CVSS score (default to 5.0 if not available)
    const cvss = exposure.cvss ?? 5.0;

    // Get EPSS probability (default to 0 if not available)
    const epss = exposure.epss ?? 0;

    // Calculate base score
    // (CVSS × 2.5) + (EPSS × 35)
    const cvssContribution = cvss * CVE_SCORING.cvssMultiplier;
    const epssContribution = epss * CVE_SCORING.epssMultiplier;

    const baseScore = cvssContribution + epssContribution;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: CVEExposure): Record<string, number> {
    const cvss = exposure.cvss ?? 5.0;
    const epss = exposure.epss ?? 0;

    return {
      cvssScore: cvss,
      cvssContribution: cvss * CVE_SCORING.cvssMultiplier,
      epssScore: epss,
      epssContribution: epss * CVE_SCORING.epssMultiplier,
      kevBonus: exposure.cisaKEV ? CVE_SCORING.kevBonus : 0,
      isCisaKev: exposure.cisaKEV ? 1 : 0,
      // Also include Formula 1 exploitability factor for reference
      exploitabilityFactor: this.getExploitabilityFactor(epss),
    };
  }
}

// Singleton instance for convenience
export const cveCalculator = new CVECalculator();
