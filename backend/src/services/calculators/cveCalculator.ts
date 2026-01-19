import { CVEExposure } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { CVE_SCORING } from '../../config/scoringConfig';

// ============================================================
// CVE CALCULATOR
// Formula: (CVSS × 2.5) + (EPSS × 35) + (KEV ? 40 : 0)
// If KEV = true, automatic score of 100
// ============================================================

export class CVECalculator extends BaseExposureCalculator<CVEExposure> {
  /**
   * Calculate base score for CVE exposure
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
    };
  }
}

// Singleton instance for convenience
export const cveCalculator = new CVECalculator();
