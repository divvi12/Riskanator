import {
  Exposure,
  CVEExposure,
  ApplicationContext,
  ExtendedScanSummary,
  ExtendedRemediationGroup,
  SLAStatus,
  CVE,
  ApplicationRiskScore
} from '../types';
import { scanCertificates } from './certificateService';
import { runSecretScanning } from './secretService';
import { runLicenseScanning } from './licenseService';
import { runMisconfigScanning } from './misconfigService';
import { runCodeSecurityScanning } from './codeSecurityService';
import { scanRepository as runCVEScanning } from './scannerService';
import { enrichCVEs } from './cveEnrichmentService';
import {
  processExposures,
  applySLAToExposures,
  calculateOverallConcertScore,
  calculateOverallDetailedScore,
  calculateOverallApplicationRisk
} from './exposureRiskService';
import { v4 as uuidv4 } from 'uuid';

export interface ExposureScannerResult {
  exposures: Exposure[];
  summary: ExtendedScanSummary;
  remediationGroups: ExtendedRemediationGroup[];
  applicationRiskScore?: ApplicationRiskScore;
}

// Convert CVE from scanner to CVEExposure
function convertCVEToExposure(cve: CVE): CVEExposure {
  return {
    id: uuidv4(),
    type: 'cve',
    title: `${cve.id}: ${cve.description.substring(0, 60)}${cve.description.length > 60 ? '...' : ''}`,
    description: cve.description,
    severity: cve.severity,
    riskScore: cve.riskScore || { concert: 0, comprehensive: 0 },
    location: cve.component,
    detectedAt: new Date().toISOString(),
    source: cve.source,
    cveId: cve.id,
    cvss: cve.cvss,
    cvssVector: cve.cvssVector,
    epss: cve.epss,
    epssPercentile: cve.epssPercentile,
    cisaKEV: cve.cisaKEV,
    kevDateAdded: cve.kevDateAdded,
    component: cve.component,
    version: cve.version,
    fixedVersion: cve.fixedVersion,
    sourceType: cve.sourceType,
    references: cve.references,
    complianceImpact: cve.complianceImpact,
    slaDeadline: cve.slaDeadline,
    slaStatus: cve.slaStatus,
    daysRemaining: cve.daysRemaining
  };
}

// Generate summary from exposures
function generateSummary(exposures: Exposure[]): ExtendedScanSummary {
  const byType = {
    cve: 0,
    certificate: 0,
    secret: 0,
    misconfiguration: 0,
    license: 0,
    codeSecurity: 0
  };

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const bySource: Record<string, number> = {};
  let cisaKEVCount = 0;
  const slaStatus: SLAStatus = { overdue: 0, dueSoon: 0, onTrack: 0, complianceRate: 0 };

  for (const exposure of exposures) {
    // Count by type
    if (exposure.type === 'cve') byType.cve++;
    else if (exposure.type === 'certificate') byType.certificate++;
    else if (exposure.type === 'secret') byType.secret++;
    else if (exposure.type === 'misconfiguration') byType.misconfiguration++;
    else if (exposure.type === 'license') byType.license++;
    else if (exposure.type === 'code-security') byType.codeSecurity++;

    // Count by severity
    bySeverity[exposure.severity]++;

    // Count by source
    bySource[exposure.source] = (bySource[exposure.source] || 0) + 1;

    // Count CISA KEV
    if (exposure.type === 'cve' && (exposure as CVEExposure).cisaKEV) {
      cisaKEVCount++;
    }

    // Count SLA status
    if (exposure.slaStatus === 'overdue') slaStatus.overdue++;
    else if (exposure.slaStatus === 'due_soon') slaStatus.dueSoon++;
    else slaStatus.onTrack++;
  }

  // Calculate compliance rate
  slaStatus.complianceRate = exposures.length > 0
    ? Math.round(((exposures.length - slaStatus.overdue) / exposures.length) * 100)
    : 100;

  // Calculate both Concert and Detailed scores
  const concertScore = calculateOverallConcertScore(exposures);
  const detailedScore = calculateOverallDetailedScore(exposures);

  return {
    totalExposures: exposures.length,
    critical: bySeverity.critical,
    high: bySeverity.high,
    medium: bySeverity.medium,
    low: bySeverity.low,
    overallRiskScore: concertScore,
    riskScore: { concert: concertScore, comprehensive: detailedScore },
    cisaKEVCount,
    byType,
    bySource,
    slaStatus
  };
}

// Generate remediation groups from exposures
function generateRemediationGroups(exposures: Exposure[]): ExtendedRemediationGroup[] {
  const groups: ExtendedRemediationGroup[] = [];

  // Group 1: Secrets (ALWAYS FIRST - highest priority)
  const secrets = exposures.filter(e => e.type === 'secret');
  if (secrets.length > 0) {
    const riskReduction = secrets.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);
    groups.push({
      id: 'secret-removal',
      title: 'Remove Hardcoded Secrets',
      type: 'secret_removal',
      exposureType: 'secret',
      exposures: secrets.map(e => e.id),
      exposuresCount: secrets.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: 'medium',
      effortHours: secrets.length * 2,
      priority: 100,
      slaStatus: secrets.some(e => e.slaStatus === 'overdue') ? 'overdue' : 'due_soon',
      overdueCount: secrets.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: secrets.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 3.4', 'SOX Section 404', 'GDPR Article 32'],
      description: 'Rotate all credentials immediately and move to a secrets manager'
    });
  }

  // Group 2: Certificates
  const certificates = exposures.filter(e => e.type === 'certificate');
  if (certificates.length > 0) {
    const riskReduction = certificates.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);
    groups.push({
      id: 'certificate-renewal',
      title: 'Renew Expiring Certificates',
      type: 'certificate_renewal',
      exposureType: 'certificate',
      exposures: certificates.map(e => e.id),
      exposuresCount: certificates.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: 'low',
      effortHours: certificates.length * 0.5,
      priority: 90,
      slaStatus: certificates.some(e => e.slaStatus === 'overdue') ? 'overdue' :
                 certificates.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: certificates.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: certificates.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 4.1'],
      description: 'Renew certificates before they expire to prevent service outages'
    });
  }

  // Group 3: CVEs by component
  const cves = exposures.filter(e => e.type === 'cve') as CVEExposure[];
  const cvesByComponent = new Map<string, CVEExposure[]>();

  for (const cve of cves) {
    const key = cve.component;
    if (!cvesByComponent.has(key)) {
      cvesByComponent.set(key, []);
    }
    cvesByComponent.get(key)!.push(cve);
  }

  for (const [component, componentCves] of cvesByComponent) {
    const riskReduction = componentCves.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);
    const hasCISAKEV = componentCves.some(c => c.cisaKEV);
    const hasOverdue = componentCves.some(e => e.slaStatus === 'overdue');

    groups.push({
      id: `cve-${component.replace(/[^a-zA-Z0-9]/g, '-')}`,
      title: `Update ${component}`,
      type: 'dependency_update',
      exposureType: 'cve',
      exposures: componentCves.map(e => e.id),
      exposuresCount: componentCves.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: 'low',
      effortHours: 2,
      priority: hasCISAKEV ? 85 : hasOverdue ? 80 : 70,
      slaStatus: hasOverdue ? 'overdue' :
                 componentCves.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: componentCves.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: componentCves.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: hasCISAKEV ? ['PCI-DSS 6.2', 'SOX 404', 'GDPR Art 32'] : ['PCI-DSS 6.2'],
      fixCommand: componentCves[0].fixedVersion ? `npm update ${component.split('@')[0]}` : undefined,
      description: `${componentCves.length} CVE${componentCves.length > 1 ? 's' : ''} found${hasCISAKEV ? ' including CISA KEV entries' : ''}`
    });
  }

  // Group 4: Misconfigurations by resource type
  const misconfigs = exposures.filter(e => e.type === 'misconfiguration');
  const misconfigsByType = new Map<string, typeof misconfigs>();

  for (const misconfig of misconfigs) {
    const key = (misconfig as any).resourceType || 'Unknown';
    if (!misconfigsByType.has(key)) {
      misconfigsByType.set(key, []);
    }
    misconfigsByType.get(key)!.push(misconfig);
  }

  for (const [resourceType, configs] of misconfigsByType) {
    const riskReduction = configs.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);

    groups.push({
      id: `config-${resourceType.replace(/[^a-zA-Z0-9]/g, '-')}`,
      title: `Fix ${resourceType} Configuration`,
      type: 'config_fix',
      exposureType: 'misconfiguration',
      exposures: configs.map(e => e.id),
      exposuresCount: configs.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: configs.length > 5 ? 'high' : 'medium',
      effortHours: configs.length * 1,
      priority: 60,
      slaStatus: configs.some(e => e.slaStatus === 'overdue') ? 'overdue' :
                 configs.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: configs.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: configs.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 2.2', 'GDPR Art 32'],
      description: `${configs.length} misconfiguration${configs.length > 1 ? 's' : ''} in ${resourceType} resources`
    });
  }

  // Group 5: Code Security issues by file
  const codeIssues = exposures.filter(e => e.type === 'code-security');
  if (codeIssues.length > 0) {
    const riskReduction = codeIssues.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);

    groups.push({
      id: 'code-security-fixes',
      title: 'Fix Code Security Issues',
      type: 'code_fix',
      exposureType: 'code-security',
      exposures: codeIssues.map(e => e.id),
      exposuresCount: codeIssues.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: codeIssues.length > 10 ? 'high' : 'medium',
      effortHours: codeIssues.length * 1.5,
      priority: 55,
      slaStatus: codeIssues.some(e => e.slaStatus === 'overdue') ? 'overdue' :
                 codeIssues.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: codeIssues.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: codeIssues.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['OWASP Top 10', 'PCI-DSS 6.5'],
      description: `${codeIssues.length} code security issue${codeIssues.length > 1 ? 's' : ''} found`
    });
  }

  // Group 6: License issues
  const licenses = exposures.filter(e => e.type === 'license');
  if (licenses.length > 0) {
    const riskReduction = licenses.reduce((sum, e) => sum + (e.riskScore?.concert || 0), 0);

    groups.push({
      id: 'license-resolution',
      title: 'Resolve License Issues',
      type: 'license_resolution',
      exposureType: 'license',
      exposures: licenses.map(e => e.id),
      exposuresCount: licenses.length,
      riskReduction: Math.round(riskReduction * 10) / 10,
      effort: 'high',
      effortHours: licenses.length * 4,
      priority: 40,
      slaStatus: 'on_track', // Licenses have longer SLAs
      overdueCount: licenses.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: licenses.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['Legal - IP Compliance'],
      description: `${licenses.length} license compliance issue${licenses.length > 1 ? 's' : ''} to resolve`
    });
  }

  // Sort by priority (descending)
  return groups.sort((a, b) => b.priority - a.priority);
}

// Main exposure scanning function
export async function runExposureScanning(
  repoPath: string,
  languages: string[],
  context?: ApplicationContext,
  onProgress?: (message: string) => void
): Promise<ExposureScannerResult> {
  const allExposures: Exposure[] = [];
  const discoveryLog: string[] = [];

  // Helper to report discoveries
  const reportDiscovery = (type: string, count: number, details?: string) => {
    const msg = details
      ? `Found ${count} ${type} ${count === 1 ? 'issue' : 'issues'}: ${details}`
      : `Found ${count} ${type} ${count === 1 ? 'issue' : 'issues'}`;
    discoveryLog.push(msg);
    onProgress?.(msg);
  };

  // 1. Start CVE scanning immediately
  onProgress?.('Starting CVE vulnerability scan (npm audit, pip-audit, Trivy)...');
  const cves = await runCVEScanning(repoPath, languages, (msg) => {
    onProgress?.(msg);
  });

  if (cves.length > 0) {
    const critical = cves.filter(c => c.severity === 'critical').length;
    const high = cves.filter(c => c.severity === 'high').length;
    reportDiscovery('CVE vulnerabilities', cves.length,
      `${critical} critical, ${high} high severity`);
  } else {
    onProgress?.('No CVE vulnerabilities found');
  }

  // 2. Start parallel scans AND CVE enrichment concurrently
  onProgress?.('Starting parallel security scans (certificates, secrets, misconfigs, licenses, SAST)...');

  // Run enrichment and other scanners in parallel for maximum speed
  const [enrichedCves, certResult, secretResult, misconfigResult, licenseResult, codeSecResult] = await Promise.all([
    // CVE Enrichment
    (async () => {
      const cveIdsToEnrich = cves.filter(cve => cve.id.startsWith('CVE-'));
      if (cveIdsToEnrich.length === 0) {
        onProgress?.('CVE enrichment: Skipped (no CVE IDs to enrich)');
        return cves;
      }

      onProgress?.(`Enriching ${cveIdsToEnrich.length} CVEs with NVD/EPSS/KEV data...`);
      const enriched = await enrichCVEs(cveIdsToEnrich, (current, total) => {
        onProgress?.(`Enriching CVE data (${current}/${total})...`);
      });
      onProgress?.(`CVE enrichment: Complete (${cveIdsToEnrich.length} CVEs enriched)`);
      return enriched;
    })(),

    // Certificate scanning
    scanCertificates(repoPath).then(result => {
      if (result.success && result.exposures.length > 0) {
        const expiring = result.exposures.filter((e: any) => e.daysUntilExpiry <= 30).length;
        reportDiscovery('certificate', result.exposures.length,
          expiring > 0 ? `${expiring} expiring within 30 days` : 'none critical');
      } else {
        onProgress?.('Certificate scan: Complete (no issues found)');
      }
      return result;
    }),

    // Secret scanning
    runSecretScanning(repoPath).then(result => {
      if (result.success && result.exposures.length > 0) {
        const types = [...new Set(result.exposures.map((e: any) => e.secretType || 'unknown'))];
        reportDiscovery('hardcoded secret', result.exposures.length,
          `types: ${types.slice(0, 3).join(', ')}${types.length > 3 ? '...' : ''}`);
      } else {
        onProgress?.('Secret scan: Complete (no hardcoded secrets found)');
      }
      return result;
    }),

    // Misconfiguration scanning
    runMisconfigScanning(repoPath).then(result => {
      if (result.success && result.exposures.length > 0) {
        const resources = [...new Set(result.exposures.map((e: any) => e.resourceType || 'unknown'))];
        reportDiscovery('misconfiguration', result.exposures.length,
          `in ${resources.slice(0, 3).join(', ')}${resources.length > 3 ? '...' : ''}`);
      } else {
        onProgress?.('Misconfiguration scan: Complete (no issues found)');
      }
      return result;
    }),

    // License scanning
    runLicenseScanning(repoPath, languages).then(result => {
      if (result.success && result.exposures.length > 0) {
        const licenses = [...new Set(result.exposures.map((e: any) => e.license || 'unknown'))];
        reportDiscovery('license', result.exposures.length,
          `problematic: ${licenses.slice(0, 3).join(', ')}${licenses.length > 3 ? '...' : ''}`);
      } else {
        onProgress?.('License scan: Complete (no problematic licenses found)');
      }
      return result;
    }),

    // Code security scanning (SAST)
    runCodeSecurityScanning(repoPath).then(result => {
      if (result.success && result.exposures.length > 0) {
        const issueTypes = [...new Set(result.exposures.map((e: any) => e.issueType || 'unknown'))];
        reportDiscovery('code security issue', result.exposures.length,
          `types: ${issueTypes.slice(0, 3).join(', ')}${issueTypes.length > 3 ? '...' : ''}`);
      } else {
        onProgress?.('SAST code scan: Complete (no security issues found)');
      }
      return result;
    })
  ]);

  // Merge enriched CVE data back
  const enrichedMap = new Map(enrichedCves.map(cve => [cve.id, cve]));
  const mergedCves = cves.map(cve => enrichedMap.get(cve.id) || cve);

  // Report CISA KEV findings
  const kevCount = mergedCves.filter(c => c.cisaKEV).length;
  if (kevCount > 0) {
    onProgress?.(`WARNING: ${kevCount} vulnerabilities are in CISA Known Exploited Vulnerabilities catalog!`);
  }

  // Convert CVEs to exposures
  const cveExposures = mergedCves.map(convertCVEToExposure);
  allExposures.push(...cveExposures);

  // Collect results from parallel scans
  if (certResult.success) {
    allExposures.push(...certResult.exposures);
  }
  if (secretResult.success) {
    allExposures.push(...secretResult.exposures);
  }
  if (misconfigResult.success) {
    allExposures.push(...misconfigResult.exposures);
  }
  if (licenseResult.success) {
    allExposures.push(...licenseResult.exposures);
  }
  if (codeSecResult.success) {
    allExposures.push(...codeSecResult.exposures);
  }

  onProgress?.(`Scan complete: ${allExposures.length} total exposures found`);

  // 6. Calculate risk scores for all exposures
  onProgress?.('Calculating risk scores...');
  const scoredExposures = processExposures(allExposures, context);

  // 7. Apply SLA deadlines
  onProgress?.('Applying SLA deadlines...');
  const exposuresWithSLA = applySLAToExposures(scoredExposures, context);

  // 8. Generate summary
  const summary = generateSummary(exposuresWithSLA);

  // 9. Generate remediation groups
  onProgress?.('Generating remediation groups...');
  const remediationGroups = generateRemediationGroups(exposuresWithSLA);

  // 10. Calculate overall application risk score (0-100 scale)
  const applicationRiskScore = calculateOverallApplicationRisk(exposuresWithSLA);
  onProgress?.(`Overall Application Risk Score: ${applicationRiskScore.overall}/100`);

  return {
    exposures: exposuresWithSLA,
    summary,
    remediationGroups,
    applicationRiskScore
  };
}
