import {
  Exposure,
  EnhancedRiskScore,
  EnvironmentalContext,
  ScoreOverride,
  RiskScoreBreakdown,
  ApplicationContext
} from '../../types';

import { ENVIRONMENTAL_FACTORS, SEVERITY_THRESHOLDS } from '../../config/scoringConfig';

// ============================================================
// BASE EXPOSURE CALCULATOR
// Abstract base class for all exposure type calculators
// ============================================================

export abstract class BaseExposureCalculator<T extends Exposure> {
  /**
   * Calculate the base score for the specific exposure type (0-100)
   * Must be implemented by each type-specific calculator
   */
  abstract calculateBaseScore(exposure: T): number;

  /**
   * Get type-specific factors for the breakdown
   * Override in subclasses to provide detailed factor information
   */
  protected getTypeSpecificFactors(exposure: T): Record<string, number> {
    return {};
  }

  /**
   * Calculate environmental multiplier using geometric mean
   * Formula: ∛(Asset × Data × Network)
   */
  calculateEnvironmentalMultiplier(context?: EnvironmentalContext): number {
    if (!context) return 1.0;

    const assetFactor = ENVIRONMENTAL_FACTORS.assetCriticality[context.assetCriticality] ?? 1.0;
    const dataFactor = ENVIRONMENTAL_FACTORS.dataSensitivity[context.dataSensitivity] ?? 1.0;
    const networkFactor = ENVIRONMENTAL_FACTORS.networkExposure[context.networkExposure] ?? 1.0;

    // Geometric mean (cube root of product)
    return Math.cbrt(assetFactor * dataFactor * networkFactor);
  }

  /**
   * Get individual environmental factors for breakdown
   */
  getEnvironmentalFactors(context?: EnvironmentalContext): {
    assetCriticalityFactor: number;
    dataSensitivityFactor: number;
    networkExposureFactor: number;
  } {
    if (!context) {
      return {
        assetCriticalityFactor: 1.0,
        dataSensitivityFactor: 1.0,
        networkExposureFactor: 1.0,
      };
    }

    return {
      assetCriticalityFactor: ENVIRONMENTAL_FACTORS.assetCriticality[context.assetCriticality] ?? 1.0,
      dataSensitivityFactor: ENVIRONMENTAL_FACTORS.dataSensitivity[context.dataSensitivity] ?? 1.0,
      networkExposureFactor: ENVIRONMENTAL_FACTORS.networkExposure[context.networkExposure] ?? 1.0,
    };
  }

  /**
   * Apply score override multiplier
   */
  applyOverride(score: number, override?: ScoreOverride): number {
    if (!override || override.multiplier === undefined) return score;

    // Check if override has expired
    if (override.expiresAt && new Date(override.expiresAt) < new Date()) {
      return score;
    }

    return Math.min(100, Math.max(0, score * override.multiplier));
  }

  /**
   * Calculate the final enhanced risk score
   */
  calculateFinalScore(
    exposure: T,
    context?: EnvironmentalContext,
    override?: ScoreOverride
  ): EnhancedRiskScore {
    // Calculate base score (0-100)
    const baseScore = this.calculateBaseScore(exposure);

    // Calculate environmental multiplier
    const envMultiplier = this.calculateEnvironmentalMultiplier(context);

    // Apply environmental multiplier
    let adjustedScore = baseScore * envMultiplier;

    // Apply override
    const overrideMultiplier = override?.multiplier ?? 1.0;
    adjustedScore = this.applyOverride(adjustedScore, override);

    // Cap at 100
    const finalScore = Math.min(100, Math.max(0, adjustedScore));

    // Round to 1 decimal place
    const roundedFinal = Math.round(finalScore * 10) / 10;

    // Build breakdown
    const envFactors = this.getEnvironmentalFactors(context);
    const breakdown: RiskScoreBreakdown = {
      ...envFactors,
      typeSpecificFactors: this.getTypeSpecificFactors(exposure),
    };

    return {
      final: roundedFinal,
      baseScore: Math.round(baseScore * 10) / 10,
      environmentalMultiplier: Math.round(envMultiplier * 1000) / 1000,
      overrideMultiplier: Math.round(overrideMultiplier * 100) / 100,
      breakdown,
      // Legacy compatibility (0-10 scale)
      concert: Math.round((roundedFinal / 10) * 10) / 10,
      comprehensive: Math.round((roundedFinal / 10) * 10) / 10,
    };
  }

  /**
   * Determine severity level from final score
   */
  static getSeverityFromScore(score: number): 'critical' | 'high' | 'medium' | 'low' {
    if (score >= SEVERITY_THRESHOLDS.critical) return 'critical';
    if (score >= SEVERITY_THRESHOLDS.high) return 'high';
    if (score >= SEVERITY_THRESHOLDS.medium) return 'medium';
    return 'low';
  }

  /**
   * Convert ApplicationContext to EnvironmentalContext
   */
  static toEnvironmentalContext(appContext?: ApplicationContext): EnvironmentalContext | undefined {
    if (!appContext) return undefined;

    // Map criticality (1-5) directly
    const assetCriticality = Math.max(1, Math.min(5, appContext.criticality)) as 1 | 2 | 3 | 4 | 5;

    // Map data sensitivity based on flags
    let dataSensitivity: EnvironmentalContext['dataSensitivity'] = 'internal';
    if (appContext.dataSensitivity.pci || appContext.dataSensitivity.phi) {
      dataSensitivity = 'restricted';
    } else if (appContext.dataSensitivity.pii || appContext.dataSensitivity.tradeSecrets) {
      dataSensitivity = 'confidential';
    }

    // Map network exposure
    let networkExposure: EnvironmentalContext['networkExposure'] = 'internal';
    if (appContext.accessControls.networkExposure === 'public') {
      networkExposure = 'internet-facing';
    } else if (appContext.accessControls.networkExposure === 'dmz') {
      networkExposure = 'dmz';
    }

    return {
      assetCriticality,
      dataSensitivity,
      networkExposure,
    };
  }
}
