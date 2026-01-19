import { CodeSecurityExposure, ConcertEnvironmentalContext, ConcertExposureRiskScore } from '../../types';
import {
  SAST_SEVERITY,
  DAST_SEVERITY,
  APP_CRITICALITY_F1,
  DATA_SENSITIVITY_F1,
  PUBLIC_ACCESS_POINTS,
  PRIVATE_ACCESS_POINTS
} from '../../config/scoringConfig';

// ============================================================
// SAST/DAST CALCULATOR
// Formula 2: Concert Exposure Risk Score (1-10)
// Score = Severity × Environmental Factor
// (No EPSS factor - used for CVEs only)
// ============================================================

export class SASTDASTCalculator {

  /**
   * Calculate Concert Exposure Risk Score for SAST findings (Formula 2)
   *
   * Formula: Severity × Environmental Factor
   * - Severity: 1-10 based on SAST severity level (5-tier scale)
   * - Environmental Factor: 0.25-1.25 from context
   *
   * @param severityLevel - SAST severity level (Blocker, High, Medium, Low, Info)
   * @param context - Concert environmental context
   * @returns ConcertExposureRiskScore with full breakdown
   */
  calculateSASTScore(
    severityLevel: string,
    context?: ConcertEnvironmentalContext
  ): ConcertExposureRiskScore {
    // 1. Get SAST severity score
    const severity = this.getSASTSeverity(severityLevel);

    // 2. Calculate Environmental Factor
    const { factor: environmentalFactor, breakdown } = this.getEnvironmentalFactor(context);

    // 3. Calculate final score
    const rawScore = severity * environmentalFactor;
    const score = Math.min(10, Math.max(1, rawScore));

    return {
      score: Math.round(score * 100) / 100,
      severity,
      environmentalFactor,
      toolType: 'sast',
      breakdown
    };
  }

  /**
   * Calculate Concert Exposure Risk Score for DAST findings (Formula 2)
   *
   * Formula: Severity × Environmental Factor
   * - Severity: 0.76-10 based on DAST severity with confidence levels (15-tier scale)
   * - Environmental Factor: 0.25-1.25 from context
   *
   * @param severityLevel - DAST severity level (e.g., "High (High)", "Medium", "Low (Low)")
   * @param context - Concert environmental context
   * @returns ConcertExposureRiskScore with full breakdown
   */
  calculateDASTScore(
    severityLevel: string,
    context?: ConcertEnvironmentalContext
  ): ConcertExposureRiskScore {
    // 1. Get DAST severity score
    const severity = this.getDASTSeverity(severityLevel);

    // 2. Calculate Environmental Factor
    const { factor: environmentalFactor, breakdown } = this.getEnvironmentalFactor(context);

    // 3. Calculate final score
    const rawScore = severity * environmentalFactor;
    const score = Math.min(10, Math.max(1, rawScore));

    return {
      score: Math.round(score * 100) / 100,
      severity,
      environmentalFactor,
      toolType: 'dast',
      breakdown
    };
  }

  /**
   * Calculate score from a CodeSecurityExposure, auto-detecting tool type
   *
   * @param exposure - CodeSecurityExposure to score
   * @param toolType - 'sast' or 'dast', or auto-detect from source
   * @param context - Concert environmental context
   * @returns ConcertExposureRiskScore
   */
  calculateFromExposure(
    exposure: CodeSecurityExposure,
    toolType?: 'sast' | 'dast',
    context?: ConcertEnvironmentalContext
  ): ConcertExposureRiskScore {
    // Auto-detect tool type if not provided
    const detectedToolType = toolType ?? this.detectToolType(exposure);

    // Get severity level from exposure
    const severityLevel = this.getSeverityLevelFromExposure(exposure, detectedToolType);

    if (detectedToolType === 'dast') {
      return this.calculateDASTScore(severityLevel, context);
    } else {
      return this.calculateSASTScore(severityLevel, context);
    }
  }

  /**
   * Get SAST severity value from level string
   * 5-tier scale: Blocker(10), High(7.5), Medium(5), Low(2.5), Info(1)
   */
  private getSASTSeverity(level: string): number {
    // Normalize the level string
    const normalized = this.normalizeLevel(level);

    // Direct lookup
    if (SAST_SEVERITY[normalized]) {
      return SAST_SEVERITY[normalized];
    }

    // Try with first letter capitalized
    const capitalized = normalized.charAt(0).toUpperCase() + normalized.slice(1).toLowerCase();
    if (SAST_SEVERITY[capitalized]) {
      return SAST_SEVERITY[capitalized];
    }

    // Fallback based on common patterns
    const lowerLevel = level.toLowerCase();
    if (lowerLevel.includes('critical') || lowerLevel.includes('blocker')) return 10.0;
    if (lowerLevel.includes('high') || lowerLevel.includes('error')) return 7.5;
    if (lowerLevel.includes('medium') || lowerLevel.includes('warning')) return 5.0;
    if (lowerLevel.includes('low')) return 2.5;
    if (lowerLevel.includes('info')) return 1.0;

    // Default to medium
    return 5.0;
  }

  /**
   * Get DAST severity value from level string
   * 15-tier scale with confidence levels
   */
  private getDASTSeverity(level: string): number {
    // Direct lookup first
    if (DAST_SEVERITY[level]) {
      return DAST_SEVERITY[level];
    }

    // Try normalized version
    const normalized = this.normalizeLevel(level);
    if (DAST_SEVERITY[normalized]) {
      return DAST_SEVERITY[normalized];
    }

    // Extract base severity and confidence from combined format
    const match = level.match(/^(\w+)(?:\s*\((\w+)\))?$/i);
    if (match) {
      const baseSeverity = match[1];
      const confidence = match[2];

      if (confidence) {
        // Try combined format
        const combined = `${this.capitalize(baseSeverity)} (${this.capitalize(confidence)})`;
        if (DAST_SEVERITY[combined]) {
          return DAST_SEVERITY[combined];
        }
      }

      // Try base severity only
      const base = this.capitalize(baseSeverity);
      if (DAST_SEVERITY[base]) {
        return DAST_SEVERITY[base];
      }
    }

    // Fallback based on common patterns
    const lowerLevel = level.toLowerCase();
    if (lowerLevel.includes('critical') || lowerLevel.includes('blocker')) return 10.0;
    if (lowerLevel.includes('error')) return 10.0;
    if (lowerLevel.includes('high')) return 6.84;
    if (lowerLevel.includes('medium')) return 3.80;
    if (lowerLevel.includes('low')) return 0.76;
    if (lowerLevel.includes('info')) return 0.50;

    // Default
    return 3.80; // Medium default
  }

  /**
   * Get Environmental Factor (same as Formula 1)
   * Formula: (Application Criticality + Data Sensitivity + Access Points) / 3
   */
  private getEnvironmentalFactor(context?: ConcertEnvironmentalContext): {
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

      // Access Points
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

    const factor = components.length > 0
      ? components.reduce((sum, c) => sum + c, 0) / components.length
      : 1.0;

    return {
      factor: Math.round(factor * 1000) / 1000,
      breakdown: {
        applicationCriticalityFactor: appCritFactor,
        dataSensitivityFactor: dataSensFactor,
        accessPointsFactor: accessPointsFactor
      }
    };
  }

  /**
   * Detect tool type from exposure properties
   */
  private detectToolType(exposure: CodeSecurityExposure): 'sast' | 'dast' {
    const source = exposure.source?.toLowerCase() ?? '';
    const ruleId = exposure.ruleId?.toLowerCase() ?? '';

    // DAST indicators
    const dastIndicators = ['zap', 'burp', 'dast', 'dynamic', 'scanner', 'runtime'];
    if (dastIndicators.some(i => source.includes(i) || ruleId.includes(i))) {
      return 'dast';
    }

    // Default to SAST (most code security findings are SAST)
    return 'sast';
  }

  /**
   * Get severity level string from exposure
   */
  private getSeverityLevelFromExposure(exposure: CodeSecurityExposure, toolType: 'sast' | 'dast'): string {
    // Check for explicit severity level
    const exposureAny = exposure as any;
    if (exposureAny.severityLevel) {
      return exposureAny.severityLevel;
    }

    // Check for confidence to create DAST-style combined level
    if (toolType === 'dast' && exposureAny.confidence) {
      const baseSeverity = this.capitalize(exposure.severity);
      const confidence = this.capitalize(exposureAny.confidence);
      return `${baseSeverity} (${confidence})`;
    }

    // Use base severity
    return this.capitalize(exposure.severity);
  }

  /**
   * Normalize a severity level string
   */
  private normalizeLevel(level: string): string {
    return level.trim();
  }

  /**
   * Capitalize first letter of a string
   */
  private capitalize(str: string): string {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  }
}

// Singleton instance
export const sastDastCalculator = new SASTDASTCalculator();
