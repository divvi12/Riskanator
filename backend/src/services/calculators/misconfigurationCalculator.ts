import { MisconfigurationExposure, ApplicationContext } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { MISCONFIGURATION_SCORING } from '../../config/scoringConfig';

// ============================================================
// MISCONFIGURATION CALCULATOR
// Formula: Scanner_Severity × Exposure_Multiplier × Data_Multiplier
// ============================================================

export class MisconfigurationCalculator extends BaseExposureCalculator<MisconfigurationExposure> {
  private appContext?: ApplicationContext;

  /**
   * Set application context for data sensitivity assessment
   */
  setApplicationContext(context?: ApplicationContext): void {
    this.appContext = context;
  }

  /**
   * Calculate base score for Misconfiguration exposure
   *
   * Formula:
   * Base_Score = Scanner_Severity × Exposure_Multiplier × Data_Multiplier
   *
   * Scanner_Severity (from Checkov/tfsec/CIS):
   * - Critical: 90-100
   * - High: 70-89
   * - Medium: 40-69
   * - Low: 10-39
   *
   * Exposure_Multiplier:
   * - Internet-facing: 1.5
   * - Public IP but firewalled: 1.2
   * - Internal network only: 1.0
   * - Segmented/isolated: 0.7
   *
   * Data_Multiplier:
   * - Contains PII/PHI/Financial: 1.4
   * - Contains sensitive business data: 1.2
   * - Non-sensitive: 1.0
   *
   * Example:
   * - Public S3 bucket with customer data: 85 × 1.5 × 1.4 = 178.5 → capped at 100
   * - Internal security group too permissive: 60 × 1.0 × 1.0 = 60
   */
  calculateBaseScore(exposure: MisconfigurationExposure): number {
    // Get scanner severity score
    const severityScore = this.getScannerSeverityScore(exposure);

    // Get exposure multiplier
    const exposureMultiplier = this.getExposureMultiplier(exposure);

    // Get data sensitivity multiplier
    const dataMultiplier = this.getDataMultiplier();

    // Calculate base score
    const baseScore = severityScore * exposureMultiplier * dataMultiplier;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Get scanner severity score based on severity level
   */
  private getScannerSeverityScore(exposure: MisconfigurationExposure): number {
    const severity = exposure.severity?.toLowerCase() ?? 'medium';
    const severityConfig = MISCONFIGURATION_SCORING.scannerSeverity[severity];

    if (severityConfig) {
      return severityConfig.default;
    }

    // Fallback based on severity string
    switch (severity) {
      case 'critical': return 95;
      case 'high': return 80;
      case 'medium': return 55;
      case 'low': return 25;
      default: return 55;
    }
  }

  /**
   * Get exposure multiplier based on public accessibility
   */
  private getExposureMultiplier(exposure: MisconfigurationExposure): number {
    // Check for public accessibility
    if (exposure.isPubliclyAccessible) {
      return MISCONFIGURATION_SCORING.exposureMultiplier.internet_facing;
    }

    // Infer from resource type and context
    const resourceType = exposure.resourceType?.toLowerCase() ?? '';
    const checkName = exposure.checkName?.toLowerCase() ?? '';
    const combined = resourceType + ' ' + checkName;

    // Check for internet-facing indicators
    const publicIndicators = ['public', 'internet', 'ingress', 'external', 'open to world', '0.0.0.0'];
    if (publicIndicators.some(indicator => combined.includes(indicator))) {
      return MISCONFIGURATION_SCORING.exposureMultiplier.internet_facing;
    }

    // Check for DMZ/perimeter indicators
    const dmzIndicators = ['dmz', 'perimeter', 'edge', 'loadbalancer', 'lb', 'api gateway'];
    if (dmzIndicators.some(indicator => combined.includes(indicator))) {
      return MISCONFIGURATION_SCORING.exposureMultiplier.dmz;
    }

    // Default to internal
    return MISCONFIGURATION_SCORING.exposureMultiplier.internal;
  }

  /**
   * Get data sensitivity multiplier based on application context
   */
  private getDataMultiplier(): number {
    if (!this.appContext) {
      return 1.0;
    }

    const dataSensitivity = this.appContext.dataSensitivity;

    // Check for PII/PHI/PCI (highest sensitivity)
    if (dataSensitivity.pci || dataSensitivity.phi) {
      return MISCONFIGURATION_SCORING.dataMultiplier.pii_phi_financial;
    }

    if (dataSensitivity.pii) {
      return MISCONFIGURATION_SCORING.dataMultiplier.pii;
    }

    if (dataSensitivity.tradeSecrets) {
      return MISCONFIGURATION_SCORING.dataMultiplier.sensitive_business;
    }

    return MISCONFIGURATION_SCORING.dataMultiplier.non_sensitive;
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: MisconfigurationExposure): Record<string, number> {
    return {
      scannerSeverityScore: this.getScannerSeverityScore(exposure),
      exposureMultiplier: this.getExposureMultiplier(exposure),
      dataMultiplier: this.getDataMultiplier(),
      isPubliclyAccessible: exposure.isPubliclyAccessible ? 1 : 0,
    };
  }
}

// Factory function to create calculator with context
export function createMisconfigurationCalculator(context?: ApplicationContext): MisconfigurationCalculator {
  const calculator = new MisconfigurationCalculator();
  calculator.setApplicationContext(context);
  return calculator;
}

// Singleton instance for convenience (without context)
export const misconfigurationCalculator = new MisconfigurationCalculator();
