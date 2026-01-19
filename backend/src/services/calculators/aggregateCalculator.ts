import {
  Exposure,
  ApplicationRiskScore,
  ApplicationRiskBreakdown,
  ExposureType,
  ExposureSeverity
} from '../../types';

import { AGGREGATE_WEIGHTS, SEVERITY_THRESHOLDS } from '../../config/scoringConfig';

// ============================================================
// AGGREGATE SCORE CALCULATOR
// Combines multiple exposures into a single application risk score
// ============================================================

export class AggregateScoreCalculator {
  /**
   * Calculate overall application risk score from all exposures
   *
   * Formula:
   * Overall_Risk_Score = (
   *     Highest_Critical_Score × 0.4 +
   *     avg(top_5_Critical) × 0.3 +
   *     avg(top_10_High) × 0.2 +
   *     log10(total_exposures) × 2
   * )
   * Cap at 100
   *
   * This uses a weighted maximum approach with diminishing returns
   * to prevent score inflation while still accounting for:
   * - The worst finding (most impactful)
   * - Concentration of critical issues
   * - Volume of high-severity issues
   * - Overall exposure count (volume penalty)
   *
   * Example with 75 exposures (21 Critical, 49 High, 5 Medium):
   * = 100 × 0.4 + 97 × 0.3 + 75 × 0.2 + log10(75) × 2
   * = 40 + 29.1 + 15 + 3.75
   * = 87.85 → 88
   */
  calculateOverallRiskScore(exposures: Exposure[]): ApplicationRiskScore {
    if (exposures.length === 0) {
      return this.createEmptyScore();
    }

    // Extract and sort scores descending
    const scores = this.extractScores(exposures);
    const sortedScores = [...scores].sort((a, b) => b - a);

    // Get critical exposures (score >= 90)
    const criticalScores = sortedScores.filter(s => s >= SEVERITY_THRESHOLDS.critical);

    // Get high exposures (score >= 70 and < 90)
    const highScores = sortedScores.filter(s =>
      s >= SEVERITY_THRESHOLDS.high && s < SEVERITY_THRESHOLDS.critical
    );

    // Calculate components
    const highestCriticalScore = sortedScores[0] || 0;
    const avgTop5Critical = this.average(criticalScores.slice(0, 5));
    const avgTop10High = this.average(highScores.slice(0, 10));
    const exposureVolumeContribution = Math.log10(exposures.length + 1) * AGGREGATE_WEIGHTS.volumeMultiplier;

    // Calculate overall score using weighted formula
    const overall = Math.min(AGGREGATE_WEIGHTS.maxScore,
      (highestCriticalScore * AGGREGATE_WEIGHTS.highestCritical) +
      (avgTop5Critical * AGGREGATE_WEIGHTS.avgTop5Critical) +
      (avgTop10High * AGGREGATE_WEIGHTS.avgTop10High) +
      exposureVolumeContribution
    );

    // Build breakdown
    const breakdown = this.calculateBreakdown(exposures);

    return {
      overall: Math.round(overall * 10) / 10,
      highestCriticalScore: Math.round(highestCriticalScore * 10) / 10,
      avgTop5Critical: Math.round(avgTop5Critical * 10) / 10,
      avgTop10High: Math.round(avgTop10High * 10) / 10,
      exposureVolumeContribution: Math.round(exposureVolumeContribution * 10) / 10,
      breakdown,
    };
  }

  /**
   * Alternative aggregation using Bayesian sum (diminishing returns)
   * This prevents many low-severity findings from equaling one critical
   *
   * Formula: Aggregated = A + B × (1 - A/100)
   * Applied iteratively for top N findings
   */
  calculateBayesianAggregateScore(exposures: Exposure[], topN: number = 20): number {
    if (exposures.length === 0) return 0;

    const scores = this.extractScores(exposures);
    const sortedScores = [...scores].sort((a, b) => b - a);
    const topScores = sortedScores.slice(0, topN);

    // Start with highest score
    let aggregated = topScores[0] || 0;

    // Apply Bayesian sum iteratively
    for (let i = 1; i < topScores.length; i++) {
      const nextScore = topScores[i];
      // Stop if adding more changes score by less than 1%
      const contribution = nextScore * (1 - aggregated / 100);
      if (contribution < 1) break;

      aggregated = aggregated + contribution;
    }

    return Math.min(100, Math.round(aggregated * 10) / 10);
  }

  /**
   * Extract risk scores from exposures
   */
  private extractScores(exposures: Exposure[]): number[] {
    return exposures
      .map(e => {
        // Prefer new 0-100 final score
        if (e.riskScore?.final !== undefined) {
          return e.riskScore.final;
        }
        // Fall back to concert score (0-10) converted to 0-100
        if (e.riskScore?.concert !== undefined) {
          return e.riskScore.concert * 10;
        }
        // Fall back to severity-based default
        return this.getDefaultScoreFromSeverity(e.severity);
      })
      .filter(score => !isNaN(score));
  }

  /**
   * Get default score from severity level
   */
  private getDefaultScoreFromSeverity(severity: ExposureSeverity): number {
    switch (severity) {
      case 'critical': return 95;
      case 'high': return 75;
      case 'medium': return 50;
      case 'low': return 25;
      default: return 50;
    }
  }

  /**
   * Calculate average of an array of numbers
   */
  private average(scores: number[]): number {
    if (scores.length === 0) return 0;
    return scores.reduce((a, b) => a + b, 0) / scores.length;
  }

  /**
   * Calculate breakdown by type and severity
   */
  private calculateBreakdown(exposures: Exposure[]): ApplicationRiskBreakdown {
    // Initialize type breakdown
    const byType: ApplicationRiskBreakdown['byType'] = {
      'cve': { count: 0, avgScore: 0, maxScore: 0 },
      'certificate': { count: 0, avgScore: 0, maxScore: 0 },
      'secret': { count: 0, avgScore: 0, maxScore: 0 },
      'misconfiguration': { count: 0, avgScore: 0, maxScore: 0 },
      'license': { count: 0, avgScore: 0, maxScore: 0 },
      'code-security': { count: 0, avgScore: 0, maxScore: 0 },
    };

    // Initialize severity breakdown
    const bySeverity: ApplicationRiskBreakdown['bySeverity'] = {
      'critical': { count: 0, avgScore: 0 },
      'high': { count: 0, avgScore: 0 },
      'medium': { count: 0, avgScore: 0 },
      'low': { count: 0, avgScore: 0 },
    };

    // Collect scores by type and severity
    const scoresByType: Record<ExposureType, number[]> = {
      'cve': [],
      'certificate': [],
      'secret': [],
      'misconfiguration': [],
      'license': [],
      'code-security': [],
    };

    const scoresBySeverity: Record<ExposureSeverity, number[]> = {
      'critical': [],
      'high': [],
      'medium': [],
      'low': [],
    };

    // Count and collect scores
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const exposure of exposures) {
      const score = exposure.riskScore?.final ?? (exposure.riskScore?.concert ?? 5) * 10;

      // By type
      if (byType[exposure.type]) {
        byType[exposure.type].count++;
        scoresByType[exposure.type].push(score);
        byType[exposure.type].maxScore = Math.max(byType[exposure.type].maxScore, score);
      }

      // By severity
      if (bySeverity[exposure.severity]) {
        bySeverity[exposure.severity].count++;
        scoresBySeverity[exposure.severity].push(score);
      }

      // Severity counts
      switch (exposure.severity) {
        case 'critical': criticalCount++; break;
        case 'high': highCount++; break;
        case 'medium': mediumCount++; break;
        case 'low': lowCount++; break;
      }
    }

    // Calculate averages
    for (const type of Object.keys(byType) as ExposureType[]) {
      if (scoresByType[type].length > 0) {
        byType[type].avgScore = Math.round(this.average(scoresByType[type]) * 10) / 10;
      }
    }

    for (const severity of Object.keys(bySeverity) as ExposureSeverity[]) {
      if (scoresBySeverity[severity].length > 0) {
        bySeverity[severity].avgScore = Math.round(this.average(scoresBySeverity[severity]) * 10) / 10;
      }
    }

    return {
      byType,
      bySeverity,
      totalExposures: exposures.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
    };
  }

  /**
   * Create empty score for no exposures
   */
  private createEmptyScore(): ApplicationRiskScore {
    return {
      overall: 0,
      highestCriticalScore: 0,
      avgTop5Critical: 0,
      avgTop10High: 0,
      exposureVolumeContribution: 0,
      breakdown: {
        byType: {
          'cve': { count: 0, avgScore: 0, maxScore: 0 },
          'certificate': { count: 0, avgScore: 0, maxScore: 0 },
          'secret': { count: 0, avgScore: 0, maxScore: 0 },
          'misconfiguration': { count: 0, avgScore: 0, maxScore: 0 },
          'license': { count: 0, avgScore: 0, maxScore: 0 },
          'code-security': { count: 0, avgScore: 0, maxScore: 0 },
        },
        bySeverity: {
          'critical': { count: 0, avgScore: 0 },
          'high': { count: 0, avgScore: 0 },
          'medium': { count: 0, avgScore: 0 },
          'low': { count: 0, avgScore: 0 },
        },
        totalExposures: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
      },
    };
  }
}

// Singleton instance for convenience
export const aggregateCalculator = new AggregateScoreCalculator();
