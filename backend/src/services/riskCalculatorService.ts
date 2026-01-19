import { CVE, ApplicationContext, RiskScore, ScanSummary, SLAStatus } from '../types';

// Concert Formula Risk Calculation
// Risk = CVSS × Exploitability(EPSS) × Environmental(Context)
// Capped at 10.0
export function calculateConcertRisk(cve: CVE, context?: ApplicationContext): number {
  const cvss = cve.cvss || 5.0;
  const epss = cve.epss || 5.0; // Default to 5% if unknown
  const cisaKEV = cve.cisaKEV;

  // Exploitability factor (1.0 to 2.0 based on EPSS)
  let exploitability = 1.0 + (epss / 100);
  if (cisaKEV) {
    exploitability = Math.max(exploitability, 1.8); // KEV gets high exploitability
  }

  // Environmental factor based on context (0.5 to 1.5)
  let environmental = 1.0;
  if (context) {
    // Criticality factor
    const criticalityFactor = 0.7 + (context.criticality * 0.16); // 0.86 to 1.5

    // Data sensitivity factor
    let dataSensitivity = 1.0;
    if (context.dataSensitivity.pci) dataSensitivity += 0.15;
    if (context.dataSensitivity.phi) dataSensitivity += 0.15;
    if (context.dataSensitivity.pii) dataSensitivity += 0.10;
    if (context.dataSensitivity.tradeSecrets) dataSensitivity += 0.10;

    // Network exposure factor
    let networkFactor = 1.0;
    if (context.accessControls.networkExposure === 'public') {
      networkFactor = 1.3;
    } else if (context.accessControls.networkExposure === 'dmz') {
      networkFactor = 1.15;
    }

    // Controls reduction
    const controlsCount = context.accessControls.controls?.length || 0;
    const controlsReduction = Math.min(controlsCount * 0.05, 0.3); // Max 30% reduction

    environmental = criticalityFactor * dataSensitivity * networkFactor * (1 - controlsReduction);
  }

  const risk = cvss * (exploitability / 2) * environmental;
  return Math.min(Math.round(risk * 10) / 10, 10.0);
}

// Comprehensive Formula Risk Calculation
// Risk = Likelihood × Impact × Exposure × (1-Controls) × 1000
// Capped at 1000
export function calculateComprehensiveRisk(cve: CVE, context?: ApplicationContext): number {
  const cvss = cve.cvss || 5.0;
  const epss = cve.epss || 5.0;
  const cisaKEV = cve.cisaKEV;

  // Likelihood (0.1 to 1.0)
  let likelihood = (epss / 100) * 0.7 + 0.1;
  if (cisaKEV) {
    likelihood = Math.max(likelihood, 0.9);
  }

  // Impact (0.1 to 1.0 based on CVSS)
  const impact = cvss / 10;

  // Exposure and Controls
  let exposure = 0.5;
  let controlsFactor = 0.5;

  if (context) {
    // Exposure based on criticality and network
    exposure = context.criticality / 5; // 0.2 to 1.0

    if (context.accessControls.networkExposure === 'public') {
      exposure = Math.min(exposure * 1.5, 1.0);
    } else if (context.accessControls.networkExposure === 'internal') {
      exposure = exposure * 0.7;
    }

    // Data sensitivity increases exposure
    if (context.dataSensitivity.pci) exposure = Math.min(exposure + 0.1, 1.0);
    if (context.dataSensitivity.phi) exposure = Math.min(exposure + 0.1, 1.0);

    // Controls factor (higher is better, so we use 1-controls)
    const controlsCount = context.accessControls.controls?.length || 0;
    controlsFactor = Math.max(1 - (controlsCount * 0.1), 0.2); // Min 20%
  }

  const risk = likelihood * impact * exposure * controlsFactor * 1000;
  return Math.min(Math.round(risk), 1000);
}

// Calculate risk scores for a CVE
export function calculateRiskScores(cve: CVE, context?: ApplicationContext): RiskScore {
  return {
    concert: calculateConcertRisk(cve, context),
    comprehensive: calculateComprehensiveRisk(cve, context)
  };
}

// Calculate aggregate risk score for all CVEs
export function calculateAggregateRiskScore(cves: CVE[], formula: 'concert' | 'comprehensive'): number {
  if (cves.length === 0) return 0;

  const scores = cves.map(cve => {
    if (!cve.riskScore) return 0;
    return formula === 'concert' ? cve.riskScore.concert : cve.riskScore.comprehensive;
  });

  // Weighted average giving more weight to higher scores
  const sortedScores = scores.sort((a, b) => b - a);
  let weightedSum = 0;
  let weightSum = 0;

  sortedScores.forEach((score, index) => {
    const weight = Math.max(1, sortedScores.length - index);
    weightedSum += score * weight;
    weightSum += weight;
  });

  const avgScore = weightedSum / weightSum;

  if (formula === 'concert') {
    return Math.round(avgScore * 10) / 10;
  } else {
    return Math.round(avgScore);
  }
}

// SLA Matrix (days to remediate)
const SLA_MATRIX: Record<string, Record<string, number>> = {
  'critical': { 'tier1': 2, 'tier2': 2, 'tier3': 7, 'tier4': 14, 'tier5': 14 },
  'high': { 'tier1': 7, 'tier2': 7, 'tier3': 14, 'tier4': 30, 'tier5': 30 },
  'medium': { 'tier1': 30, 'tier2': 30, 'tier3': 45, 'tier4': 60, 'tier5': 60 },
  'low': { 'tier1': 60, 'tier2': 60, 'tier3': 90, 'tier4': 90, 'tier5': 90 }
};

// Calculate SLA deadline for a CVE
export function calculateSLADeadline(cve: CVE, context?: ApplicationContext, scanDate: Date = new Date()): {
  slaDeadline: string;
  slaStatus: 'overdue' | 'due_soon' | 'on_track';
  daysRemaining: number;
} {
  const criticality = context?.criticality || 3;
  const tier = `tier${criticality}` as keyof typeof SLA_MATRIX['critical'];

  // Determine SLA based on risk score (using concert score)
  const riskScore = cve.riskScore?.concert || cve.cvss || 5.0;
  let severityKey = 'medium';
  if (riskScore >= 9.0) severityKey = 'critical';
  else if (riskScore >= 7.0) severityKey = 'high';
  else if (riskScore >= 4.0) severityKey = 'medium';
  else severityKey = 'low';

  const slaDays = SLA_MATRIX[severityKey][tier] || 30;
  const deadline = new Date(scanDate);
  deadline.setDate(deadline.getDate() + slaDays);

  const now = new Date();
  const daysRemaining = Math.ceil((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  let slaStatus: 'overdue' | 'due_soon' | 'on_track' = 'on_track';
  if (daysRemaining < 0) {
    slaStatus = 'overdue';
  } else if (daysRemaining <= 7) {
    slaStatus = 'due_soon';
  }

  return {
    slaDeadline: deadline.toISOString().split('T')[0],
    slaStatus,
    daysRemaining
  };
}

// Calculate SLA status summary
export function calculateSLAStatus(cves: CVE[]): SLAStatus {
  let overdue = 0;
  let dueSoon = 0;
  let onTrack = 0;

  for (const cve of cves) {
    if (cve.slaStatus === 'overdue') overdue++;
    else if (cve.slaStatus === 'due_soon') dueSoon++;
    else onTrack++;
  }

  const total = cves.length;
  const complianceRate = total > 0 ? Math.round(((total - overdue) / total) * 100) : 100;

  return {
    overdue,
    dueSoon,
    onTrack,
    complianceRate
  };
}

// Generate scan summary
export function generateScanSummary(cves: CVE[], context?: ApplicationContext): ScanSummary {
  const summary: ScanSummary = {
    totalCVEs: cves.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    riskScore: { concert: 0, comprehensive: 0 },
    cisaKEVCount: 0,
    bySource: {},
    bySourceType: {}
  };

  for (const cve of cves) {
    // Count by severity
    switch (cve.severity) {
      case 'critical': summary.critical++; break;
      case 'high': summary.high++; break;
      case 'medium': summary.medium++; break;
      case 'low': summary.low++; break;
    }

    // Count CISA KEV
    if (cve.cisaKEV) summary.cisaKEVCount++;

    // Count by source
    summary.bySource[cve.source] = (summary.bySource[cve.source] || 0) + 1;

    // Count by source type
    summary.bySourceType[cve.sourceType] = (summary.bySourceType[cve.sourceType] || 0) + 1;
  }

  // Calculate aggregate risk scores
  const formula = context?.formula || 'concert';
  summary.riskScore = {
    concert: calculateAggregateRiskScore(cves, 'concert'),
    comprehensive: calculateAggregateRiskScore(cves, 'comprehensive')
  };

  return summary;
}

// Apply risk calculations and SLA to all CVEs
export function processCVEs(cves: CVE[], context?: ApplicationContext): CVE[] {
  const scanDate = new Date();

  return cves.map(cve => {
    const riskScore = calculateRiskScores(cve, context);
    const sla = calculateSLADeadline({ ...cve, riskScore }, context, scanDate);

    return {
      ...cve,
      riskScore,
      slaDeadline: sla.slaDeadline,
      slaStatus: sla.slaStatus,
      daysRemaining: sla.daysRemaining
    };
  }).sort((a, b) => {
    // Sort by risk score descending
    const aScore = a.riskScore?.concert || 0;
    const bScore = b.riskScore?.concert || 0;
    return bScore - aScore;
  });
}
