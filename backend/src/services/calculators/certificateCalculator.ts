import { CertificateExposure } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { CERTIFICATE_SCORING } from '../../config/scoringConfig';

// ============================================================
// CERTIFICATE CALCULATOR
// Formula: max(0, 100 - (Days_Until_Expiration / 1.8)) × Algorithm_Modifier × Cert_Type_Multiplier
// ============================================================

export class CertificateCalculator extends BaseExposureCalculator<CertificateExposure> {
  /**
   * Calculate base score for Certificate exposure
   *
   * Formula:
   * Base_Score = max(0, 100 - (Days_Until_Expiration / 1.8)) × Algorithm_Modifier × Cert_Type_Multiplier
   *
   * Days to Expiry → Score:
   * - 0 days (expired): 100 (Critical)
   * - 7 days: 96 (Critical)
   * - 14 days: 92 (Critical)
   * - 30 days: 83 (High)
   * - 60 days: 67 (Medium)
   * - 90 days: 50 (Medium)
   * - 180+ days: 0 (Low)
   *
   * Algorithm_Modifier:
   * - SHA-1 or RSA-1024: 1.2
   * - SHA-256, RSA-2048+: 1.0
   *
   * Certificate_Type:
   * - Customer-facing SSL/TLS: 1.3
   * - Internal PKI: 1.0
   * - Code signing: 1.1
   * - Dev/test: 0.7
   *
   * Example:
   * - Public API cert expires in 15 days: (100 - 15/1.8) × 1.0 × 1.3 = 91.67 × 1.3 = 119 → capped at 100
   * - Internal cert expires in 60 days: (100 - 60/1.8) × 1.0 × 1.0 = 66.67
   */
  calculateBaseScore(exposure: CertificateExposure): number {
    // Handle expired certificates
    if (exposure.isExpired) {
      // Expired = maximum base score of 100
      const algoModifier = this.getAlgorithmModifier(exposure);
      const certTypeMultiplier = this.getCertTypeMultiplier(exposure);
      return Math.min(100, 100 * algoModifier * certTypeMultiplier);
    }

    // Calculate expiration-based score
    const daysUntilExpiration = exposure.daysUntilExpiration ?? 180;
    const expirationScore = Math.max(0, 100 - (daysUntilExpiration / CERTIFICATE_SCORING.daysUntilExpirationDivisor));

    // Get algorithm modifier
    const algoModifier = this.getAlgorithmModifier(exposure);

    // Get certificate type multiplier
    const certTypeMultiplier = this.getCertTypeMultiplier(exposure);

    // Calculate base score
    const baseScore = expirationScore * algoModifier * certTypeMultiplier;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Get algorithm modifier based on certificate algorithm/key size
   */
  private getAlgorithmModifier(exposure: CertificateExposure): number {
    // Check for weak algorithm flag
    if (exposure.hasWeakAlgorithm) {
      return 1.2;
    }

    // Parse algorithm string
    const algorithm = exposure.algorithm?.toLowerCase() ?? '';
    const keySize = exposure.keySize ?? 2048;

    // Check for known weak algorithms
    if (algorithm.includes('sha1') || algorithm.includes('sha-1')) {
      return CERTIFICATE_SCORING.algorithmModifier.sha1;
    }
    if (algorithm.includes('md5')) {
      return CERTIFICATE_SCORING.algorithmModifier.md5;
    }

    // Check for weak key sizes
    if (keySize < 2048 && algorithm.includes('rsa')) {
      return CERTIFICATE_SCORING.algorithmModifier.rsa1024;
    }

    // Default to standard (no penalty)
    return 1.0;
  }

  /**
   * Get certificate type multiplier
   */
  private getCertTypeMultiplier(exposure: CertificateExposure): number {
    const certType = exposure.certType ?? 'other';

    // Map to config keys
    const typeMap: Record<string, string> = {
      ssl: 'customer_facing',
      'code-signing': 'code_signing',
      client: 'client',
      other: 'other',
    };

    const mappedType = typeMap[certType] ?? certType;

    // Check if it's a self-signed cert (additional risk for production)
    if (exposure.isSelfSigned && certType === 'ssl') {
      // Self-signed public certs are higher risk
      return (CERTIFICATE_SCORING.certTypeMultiplier[mappedType] ?? 1.0) * 1.15;
    }

    return CERTIFICATE_SCORING.certTypeMultiplier[mappedType]
      ?? CERTIFICATE_SCORING.certTypeMultiplier.internal;
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: CertificateExposure): Record<string, number> {
    const daysUntilExpiration = exposure.daysUntilExpiration ?? 180;
    const expirationScore = exposure.isExpired
      ? 100
      : Math.max(0, 100 - (daysUntilExpiration / CERTIFICATE_SCORING.daysUntilExpirationDivisor));

    return {
      daysUntilExpiration,
      expirationBaseScore: expirationScore,
      algorithmModifier: this.getAlgorithmModifier(exposure),
      certTypeMultiplier: this.getCertTypeMultiplier(exposure),
      isExpired: exposure.isExpired ? 1 : 0,
      isSelfSigned: exposure.isSelfSigned ? 1 : 0,
      hasWeakAlgorithm: exposure.hasWeakAlgorithm ? 1 : 0,
      keySize: exposure.keySize ?? 0,
    };
  }
}

// Singleton instance for convenience
export const certificateCalculator = new CertificateCalculator();
