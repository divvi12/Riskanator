import { CodeSecurityExposure, ApplicationContext } from '../../types';
import { BaseExposureCalculator } from './baseCalculator';
import { CODE_SECURITY_SCORING } from '../../config/scoringConfig';

// ============================================================
// CODE SECURITY CALCULATOR
// Formula: CWE_Severity × Confidence_Factor × Reachability_Factor
// ============================================================

export class CodeSecurityCalculator extends BaseExposureCalculator<CodeSecurityExposure> {
  private appContext?: ApplicationContext;

  /**
   * Set application context for reachability assessment
   */
  setApplicationContext(context?: ApplicationContext): void {
    this.appContext = context;
  }

  /**
   * Calculate base score for Code Security exposure
   *
   * Formula:
   * Base_Score = CWE_Severity × Confidence_Factor × Reachability_Factor
   *
   * CWE_Severity (from OWASP/CWE Top 25):
   * - SQL Injection (CWE-89): 90
   * - XSS (CWE-79): 85
   * - Command Injection (CWE-78): 90
   * - Path Traversal (CWE-22): 75
   * - Insecure Deserialization (CWE-502): 85
   * - Broken Authentication (CWE-287): 80
   * - Insecure Crypto (CWE-327): 60
   * - Code smells/quality: 20
   *
   * Confidence_Factor (false positive adjustment):
   * - High confidence: 1.0
   * - Medium confidence: 0.8
   * - Low confidence: 0.5
   *
   * Reachability_Factor:
   * - Public endpoint, user input: 1.3
   * - Authenticated endpoint: 1.1
   * - Internal function: 0.9
   * - Dead code: 0.3
   *
   * Example:
   * - SQL injection in login API (high confidence): 90 × 1.0 × 1.3 = 117 → capped at 100
   * - XSS in internal admin (low confidence): 85 × 0.5 × 0.9 = 38.25
   */
  calculateBaseScore(exposure: CodeSecurityExposure): number {
    // Get CWE severity score
    const cweSeverity = this.getCWESeverityScore(exposure);

    // Get confidence factor
    const confidenceFactor = this.getConfidenceFactor(exposure);

    // Get reachability factor
    const reachabilityFactor = this.getReachabilityFactor(exposure);

    // Calculate base score
    const baseScore = cweSeverity * confidenceFactor * reachabilityFactor;

    // Cap at 100
    return Math.min(100, Math.max(0, baseScore));
  }

  /**
   * Get CWE severity score based on issue type
   */
  private getCWESeverityScore(exposure: CodeSecurityExposure): number {
    const issueType = exposure.issueType ?? 'other';

    // Direct lookup
    if (CODE_SECURITY_SCORING.cweSeverity[issueType]) {
      return CODE_SECURITY_SCORING.cweSeverity[issueType];
    }

    // Check CWE mappings if available
    if (exposure.cwe && exposure.cwe.length > 0) {
      const cweScore = this.getCWEScoreFromId(exposure.cwe[0]);
      if (cweScore > 0) return cweScore;
    }

    // Fallback based on severity
    switch (exposure.severity) {
      case 'critical': return 90;
      case 'high': return 75;
      case 'medium': return 50;
      case 'low': return 25;
      default: return 50;
    }
  }

  /**
   * Get score from CWE ID (e.g., "CWE-89")
   */
  private getCWEScoreFromId(cweId: string): number {
    const cweMap: Record<string, string> = {
      'CWE-89': 'sql_injection',
      'CWE-79': 'xss',
      'CWE-78': 'command_injection',
      'CWE-22': 'path_traversal',
      'CWE-94': 'code_injection',
      'CWE-502': 'insecure_deserialization',
      'CWE-287': 'broken_auth',
      'CWE-798': 'hardcoded_secret',
      'CWE-327': 'weak_cryptography',
      'CWE-328': 'weak_cryptography',
      'CWE-330': 'insecure_randomness',
      'CWE-601': 'open_redirect',
      'CWE-200': 'information_disclosure',
      'CWE-611': 'xxe',
      'CWE-918': 'ssrf',
      'CWE-639': 'idor',
    };

    const issueType = cweMap[cweId.toUpperCase()];
    if (issueType && CODE_SECURITY_SCORING.cweSeverity[issueType]) {
      return CODE_SECURITY_SCORING.cweSeverity[issueType];
    }

    return 0;
  }

  /**
   * Get confidence factor
   * Note: This would typically come from the SAST tool output
   */
  private getConfidenceFactor(exposure: CodeSecurityExposure): number {
    // Check if we have an explicit confidence field
    const exposureAny = exposure as any;
    if (exposureAny.confidence) {
      const confidence = exposureAny.confidence.toLowerCase();
      return CODE_SECURITY_SCORING.confidenceFactor[confidence]
        ?? CODE_SECURITY_SCORING.confidenceFactor.medium;
    }

    // Infer from rule/tool patterns
    const ruleName = exposure.ruleName?.toLowerCase() ?? '';
    const ruleId = exposure.ruleId?.toLowerCase() ?? '';

    // Semgrep and other tools sometimes indicate confidence in rule names
    if (ruleName.includes('definite') || ruleName.includes('certain')) {
      return CODE_SECURITY_SCORING.confidenceFactor.high;
    }
    if (ruleName.includes('possible') || ruleName.includes('potential')) {
      return CODE_SECURITY_SCORING.confidenceFactor.medium;
    }
    if (ruleName.includes('suspicious') || ruleName.includes('might')) {
      return CODE_SECURITY_SCORING.confidenceFactor.low;
    }

    // Default to medium confidence
    return CODE_SECURITY_SCORING.confidenceFactor.medium;
  }

  /**
   * Get reachability factor based on code location and context
   */
  private getReachabilityFactor(exposure: CodeSecurityExposure): number {
    const filePath = exposure.filePath?.toLowerCase() ?? '';
    const location = exposure.location?.toLowerCase() ?? '';
    const combined = filePath + ' ' + location;

    // Check for test/dead code indicators
    const deadCodeIndicators = ['test', 'spec', '__tests__', 'mock', 'fixture', 'deprecated', 'unused', 'dead'];
    if (deadCodeIndicators.some(indicator => combined.includes(indicator))) {
      return CODE_SECURITY_SCORING.reachabilityFactor.dead_code;
    }

    // Check for public endpoint indicators
    const publicIndicators = ['controller', 'handler', 'route', 'api', 'endpoint', 'view', 'pages/', 'app/'];
    if (publicIndicators.some(indicator => combined.includes(indicator))) {
      // Check if it's authenticated or public
      const authIndicators = ['auth', 'login', 'session', 'middleware', 'protected'];
      if (authIndicators.some(indicator => combined.includes(indicator))) {
        return CODE_SECURITY_SCORING.reachabilityFactor.authenticated;
      }
      return CODE_SECURITY_SCORING.reachabilityFactor.public_endpoint;
    }

    // Check app context for network exposure
    if (this.appContext?.accessControls.networkExposure === 'public') {
      return CODE_SECURITY_SCORING.reachabilityFactor.authenticated;
    }

    // Default to internal
    return CODE_SECURITY_SCORING.reachabilityFactor.internal;
  }

  /**
   * Get type-specific factors for breakdown
   */
  protected getTypeSpecificFactors(exposure: CodeSecurityExposure): Record<string, number> {
    return {
      cweSeverity: this.getCWESeverityScore(exposure),
      confidenceFactor: this.getConfidenceFactor(exposure),
      reachabilityFactor: this.getReachabilityFactor(exposure),
      hasCweMapping: exposure.cwe && exposure.cwe.length > 0 ? 1 : 0,
      hasOwaspMapping: exposure.owasp && exposure.owasp.length > 0 ? 1 : 0,
      lineNumber: exposure.lineNumber ?? 0,
    };
  }
}

// Factory function to create calculator with context
export function createCodeSecurityCalculator(context?: ApplicationContext): CodeSecurityCalculator {
  const calculator = new CodeSecurityCalculator();
  calculator.setApplicationContext(context);
  return calculator;
}

// Singleton instance for convenience (without context)
export const codeSecurityCalculator = new CodeSecurityCalculator();
