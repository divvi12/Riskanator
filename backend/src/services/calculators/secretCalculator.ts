import { SecretExposure } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { SECRET_SCORING } from '../../config/scoringConfig';

// ============================================================
// SECRET CALCULATOR
// Formula: BaseTypeSeverity × ValidityMultiplier × ContextMultiplier
// ============================================================

export class SecretCalculator extends BaseExposureCalculator<SecretExposure> {
  /**
   * Calculate base score for Secret exposure
   *
   * Formula:
   * Base_Score = Base_Type_Severity × Validity_Multiplier × Context_Multiplier
   *
   * Base_Type_Severity:
   * - AWS/Azure/GCP credentials: 95
   * - Database passwords: 90
   * - Private keys: 95
   * - API keys: 85
   * - OAuth tokens: 80
   * - Generic passwords: 70
   *
   * Validity_Multiplier:
   * - Verified active: 1.0
   * - Unknown/unverified: 0.7
   * - Verified revoked: 0.3
   *
   * Context_Multiplier:
   * - Production: 1.2
   * - Config file: 1.1
   * - Test/dev: 0.5
   * - In git history: additional 1.3 (applied multiplicatively)
   *
   * Example:
   * - AWS key (verified, production, in git): 95 × 1.0 × 1.2 × 1.3 = 148 → capped at 100
   * - Test API key (unverified): 85 × 0.7 × 0.5 = 29.75
   */
  calculateBaseScore(exposure: SecretExposure): number {
    // Get base type severity
    const secretType = this.normalizeSecretType(exposure.secretType);
    const baseTypeSeverity = SECRET_SCORING.baseTypeSeverity[secretType]
      ?? SECRET_SCORING.baseTypeSeverity.generic;

    // Get validity multiplier
    const validityStatus = this.getValidityStatus(exposure);
    const validityMultiplier = SECRET_SCORING.validityMultiplier[validityStatus]
      ?? SECRET_SCORING.validityMultiplier.unknown;

    // Get context multiplier (production vs test/dev)
    // We infer this from the location if available
    const contextType = this.inferContextType(exposure);
    const contextMultiplier = SECRET_SCORING.contextMultiplier[contextType]
      ?? 1.0;

    // Git history factor (multiplicative if in git history)
    const gitHistoryFactor = exposure.inGitHistory
      ? SECRET_SCORING.contextMultiplier.git_history
      : 1.0;

    // Calculate base score
    const baseScore = baseTypeSeverity * validityMultiplier * contextMultiplier * gitHistoryFactor;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Normalize secret type to match config keys
   */
  private normalizeSecretType(secretType: SecretExposure['secretType']): string {
    const typeMap: Record<string, string> = {
      aws: 'aws',
      api_key: 'api_key',
      password: 'password',
      private_key: 'private_key',
      token: 'token',
      generic: 'generic',
    };
    return typeMap[secretType] ?? 'generic';
  }

  /**
   * Determine validity status from exposure
   */
  private getValidityStatus(exposure: SecretExposure): string {
    if (exposure.verified === true) {
      return 'verified_active';
    } else if (exposure.verified === false) {
      return 'unknown';
    }
    return 'unknown';
  }

  /**
   * Infer context type from location/file path
   */
  private inferContextType(exposure: SecretExposure): string {
    const location = exposure.location?.toLowerCase() ?? '';
    const filePath = (exposure as any).filePath?.toLowerCase() ?? '';
    const combined = location + filePath;

    // Check for test/dev indicators
    const testIndicators = ['test', 'spec', 'mock', '.test.', '.spec.', '__tests__', 'fixtures', 'example', 'sample', 'demo'];
    if (testIndicators.some(indicator => combined.includes(indicator))) {
      return 'test_dev';
    }

    // Check for config file indicators
    const configIndicators = ['.env', 'config', 'settings', 'credentials', '.json', '.yaml', '.yml', '.toml'];
    if (configIndicators.some(indicator => combined.includes(indicator))) {
      return 'config_file';
    }

    // Default to production (more conservative)
    return 'production';
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: SecretExposure): Record<string, number> {
    const secretType = this.normalizeSecretType(exposure.secretType);
    const validityStatus = this.getValidityStatus(exposure);
    const contextType = this.inferContextType(exposure);

    return {
      baseTypeSeverity: SECRET_SCORING.baseTypeSeverity[secretType] ?? 70,
      validityMultiplier: SECRET_SCORING.validityMultiplier[validityStatus] ?? 0.7,
      contextMultiplier: SECRET_SCORING.contextMultiplier[contextType] ?? 1.0,
      gitHistoryFactor: exposure.inGitHistory ? SECRET_SCORING.contextMultiplier.git_history : 1.0,
      isVerified: exposure.verified ? 1 : 0,
      inGitHistory: exposure.inGitHistory ? 1 : 0,
      entropy: exposure.entropy ?? 0,
    };
  }
}

// Singleton instance for convenience
export const secretCalculator = new SecretCalculator();
