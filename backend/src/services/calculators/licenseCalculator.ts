import { LicenseExposure, ApplicationContext } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { LICENSE_SCORING } from '../../config/scoringConfig';

// ============================================================
// LICENSE CALCULATOR
// Formula: License_Risk_Tier × Distribution_Multiplier × Modification_Factor
// ============================================================

export class LicenseCalculator extends BaseExposureCalculator<LicenseExposure> {
  private distributionType: string = 'commercial';

  /**
   * Set distribution type based on application context
   */
  setDistributionType(context?: ApplicationContext): void {
    if (!context) {
      this.distributionType = 'commercial';
      return;
    }

    // Infer distribution type from context
    const industry = context.industry?.toLowerCase() ?? '';
    const purpose = context.purpose?.toLowerCase() ?? '';
    const combined = industry + ' ' + purpose;

    if (combined.includes('open source') || combined.includes('oss')) {
      this.distributionType = 'open_source';
    } else if (combined.includes('internal') || combined.includes('internal use')) {
      this.distributionType = 'internal';
    } else if (combined.includes('saas') || combined.includes('service') || combined.includes('cloud')) {
      this.distributionType = 'saas';
    } else {
      this.distributionType = 'commercial';
    }
  }

  /**
   * Calculate base score for License exposure
   *
   * Formula:
   * Base_Score = License_Risk_Tier × Distribution_Multiplier × Modification_Factor
   *
   * License_Risk_Tier:
   * - AGPL-3.0: 90 (strongest copyleft)
   * - GPL-3.0/GPL-2.0: 75
   * - LGPL/MPL: 50
   * - Unknown/No license: 70
   * - EPL/CPL: 40
   * - Permissive (MIT/BSD/Apache): 10
   *
   * Distribution_Multiplier:
   * - SaaS/hosted service: 1.3 (AGPL triggers)
   * - Commercial distribution: 1.2
   * - Internal use only: 0.8
   * - Open source project: 0.5
   *
   * Modification_Factor:
   * - Modified library: 1.2
   * - Unmodified: 1.0
   *
   * Example:
   * - AGPL library in SaaS product: 90 × 1.3 × 1.0 = 117 → capped at 100
   * - MIT license: 10 × 1.2 × 1.0 = 12
   */
  calculateBaseScore(exposure: LicenseExposure): number {
    // Get license risk tier
    const riskTier = this.getLicenseRiskTier(exposure);

    // Get distribution multiplier
    const distributionMultiplier = this.getDistributionMultiplier();

    // Get modification factor (default to unmodified as we typically don't know)
    const modificationFactor = this.getModificationFactor(exposure);

    // Calculate base score
    const baseScore = riskTier * distributionMultiplier * modificationFactor;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Get license risk tier based on license name/type
   */
  private getLicenseRiskTier(exposure: LicenseExposure): number {
    // Check for unknown license flag
    if (exposure.isUnknown) {
      return LICENSE_SCORING.riskTier.UNKNOWN;
    }

    const licenseName = exposure.licenseName?.toUpperCase() ?? '';
    const licenseType = exposure.licenseType?.toUpperCase() ?? '';

    // Try exact match first
    if (LICENSE_SCORING.riskTier[licenseName]) {
      return LICENSE_SCORING.riskTier[licenseName];
    }

    // Try to match known patterns
    if (licenseName.includes('AGPL') || licenseType.includes('AGPL')) {
      return LICENSE_SCORING.riskTier['AGPL-3.0'];
    }
    if (licenseName.includes('GPL') && !licenseName.includes('LGPL')) {
      return LICENSE_SCORING.riskTier['GPL-3.0'];
    }
    if (licenseName.includes('LGPL')) {
      return LICENSE_SCORING.riskTier['LGPL-3.0'];
    }
    if (licenseName.includes('MPL')) {
      return LICENSE_SCORING.riskTier['MPL-2.0'];
    }
    if (licenseName.includes('MIT')) {
      return LICENSE_SCORING.riskTier['MIT'];
    }
    if (licenseName.includes('APACHE')) {
      return LICENSE_SCORING.riskTier['Apache-2.0'];
    }
    if (licenseName.includes('BSD')) {
      return LICENSE_SCORING.riskTier['BSD-3-Clause'];
    }
    if (licenseName.includes('ISC')) {
      return LICENSE_SCORING.riskTier['ISC'];
    }
    if (licenseName.includes('EPL')) {
      return LICENSE_SCORING.riskTier['EPL-2.0'];
    }

    // Use copyleft flag if available
    if (exposure.isCopyleft) {
      return LICENSE_SCORING.riskTier['GPL-3.0'];
    }

    // Default to medium risk for unknown licenses
    return 50;
  }

  /**
   * Get distribution multiplier
   */
  private getDistributionMultiplier(): number {
    return LICENSE_SCORING.distributionMultiplier[this.distributionType]
      ?? LICENSE_SCORING.distributionMultiplier.commercial;
  }

  /**
   * Get modification factor
   * Note: This is typically not tracked, so we default to unmodified
   */
  private getModificationFactor(exposure: LicenseExposure): number {
    // If we had a flag for modification, we'd use it here
    // For now, default to unmodified
    return LICENSE_SCORING.modificationFactor.unmodified;
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: LicenseExposure): Record<string, number> {
    return {
      licenseRiskTier: this.getLicenseRiskTier(exposure),
      distributionMultiplier: this.getDistributionMultiplier(),
      modificationFactor: this.getModificationFactor(exposure),
      isCopyleft: exposure.isCopyleft ? 1 : 0,
      isUnknown: exposure.isUnknown ? 1 : 0,
      commercialUseAllowed: exposure.commercialUseAllowed ? 1 : 0,
      requiresAttribution: exposure.requiresAttribution ? 1 : 0,
    };
  }
}

// Factory function to create calculator with context
export function createLicenseCalculator(context?: ApplicationContext): LicenseCalculator {
  const calculator = new LicenseCalculator();
  calculator.setDistributionType(context);
  return calculator;
}

// Singleton instance for convenience (without context)
export const licenseCalculator = new LicenseCalculator();
