import { ScanResult, ExtendedScanResult, ExtendedScanSummary, ScanSummary } from '../types';

const STORAGE_KEY = 'riskanator_scan_history';
const MAX_ENTRIES = 50;

export interface ScanHistoryEntry {
  scanId: string;
  repoUrl: string;
  repoName: string;
  branch?: string;
  scanDate: string;
  totalExposures: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  byType: {
    cve: number;
    secret: number;
    certificate: number;
    misconfiguration: number;
    license: number;
    codeSecurity: number;
  };
  riskScore: {
    concert: number;
    comprehensive: number;
  };
  formula: 'concert' | 'comprehensive';
  status: 'complete' | 'error';
}

function extractRepoName(repoUrl: string): string {
  if (!repoUrl) return 'Unknown Repository';

  // Handle GitHub, GitLab, Bitbucket URLs
  const match = repoUrl.match(/(?:github\.com|gitlab\.com|bitbucket\.org)\/([^/]+\/[^/]+?)(?:\.git)?$/);
  if (match) return match[1];

  // Fallback: get last path segment
  const parts = repoUrl.replace(/\.git$/, '').split('/');
  return parts[parts.length - 1] || repoUrl;
}

function isExtendedScanSummary(summary: ExtendedScanSummary | ScanSummary): summary is ExtendedScanSummary {
  return 'byType' in summary && 'totalExposures' in summary;
}

export function saveToHistory(scan: ScanResult | ExtendedScanResult): void {
  if (!scan.scanId || scan.status === 'pending' || scan.status === 'cloning' ||
      scan.status === 'detecting' || scan.status === 'scanning' || scan.status === 'enriching') {
    return; // Don't save incomplete scans
  }

  const history = getHistory();

  // Check if this scan already exists
  const existingIndex = history.findIndex(h => h.scanId === scan.scanId);
  if (existingIndex !== -1) {
    history.splice(existingIndex, 1); // Remove existing entry
  }

  const summary = scan.summary;
  const metadata = scan.metadata;

  // Calculate totals from summary
  let bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  let byType = { cve: 0, secret: 0, certificate: 0, misconfiguration: 0, license: 0, codeSecurity: 0 };
  let totalExposures = 0;
  let riskScore = { concert: 0, comprehensive: 0 };

  if (summary) {
    bySeverity = {
      critical: summary.critical || 0,
      high: summary.high || 0,
      medium: summary.medium || 0,
      low: summary.low || 0
    };

    // Handle both ExtendedScanSummary and ScanSummary
    if (isExtendedScanSummary(summary)) {
      totalExposures = summary.totalExposures || (bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low);

      byType = {
        cve: summary.byType.cve || 0,
        secret: summary.byType.secret || 0,
        certificate: summary.byType.certificate || 0,
        misconfiguration: summary.byType.misconfiguration || 0,
        license: summary.byType.license || 0,
        codeSecurity: summary.byType.codeSecurity || 0
      };

      // ExtendedScanSummary has overallRiskScore
      if (summary.overallRiskScore !== undefined) {
        riskScore.concert = summary.overallRiskScore;
        riskScore.comprehensive = summary.overallRiskScore;
      }
      if (summary.riskScore) {
        riskScore.concert = summary.riskScore.concert || riskScore.concert;
        riskScore.comprehensive = summary.riskScore.comprehensive || riskScore.comprehensive;
      }
    } else {
      // ScanSummary - CVE only
      totalExposures = (summary as ScanSummary).totalCVEs || (bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low);

      if (scan.cves) {
        byType.cve = scan.cves.length;
      }

      // ScanSummary uses riskScore
      if (summary.riskScore) {
        riskScore.concert = summary.riskScore.concert || 0;
        riskScore.comprehensive = summary.riskScore.comprehensive || 0;
      }
    }
  }

  const entry: ScanHistoryEntry = {
    scanId: scan.scanId,
    repoUrl: metadata?.repoUrl || '',
    repoName: extractRepoName(metadata?.repoUrl || ''),
    branch: metadata?.branch,
    scanDate: metadata?.startTime || new Date().toISOString(),
    totalExposures,
    bySeverity,
    byType,
    riskScore,
    formula: metadata?.context?.formula || 'concert',
    status: scan.status === 'complete' ? 'complete' : 'error'
  };

  // Add to beginning (newest first)
  history.unshift(entry);

  // Enforce max entries (FIFO eviction)
  if (history.length > MAX_ENTRIES) {
    history.splice(MAX_ENTRIES);
  }

  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
}

export function getHistory(): ScanHistoryEntry[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return [];
    return JSON.parse(stored) as ScanHistoryEntry[];
  } catch {
    return [];
  }
}

export function getScanById(scanId: string): ScanHistoryEntry | null {
  const history = getHistory();
  return history.find(h => h.scanId === scanId) || null;
}

export function clearHistory(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function deleteFromHistory(scanId: string): void {
  const history = getHistory();
  const filtered = history.filter(h => h.scanId !== scanId);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
}

export function getRepoScans(repoUrl: string): ScanHistoryEntry[] {
  const history = getHistory();
  return history.filter(h => h.repoUrl === repoUrl);
}

export function getUniqueRepos(): string[] {
  const history = getHistory();
  const repos = new Set(history.map(h => h.repoUrl).filter(Boolean));
  return Array.from(repos);
}

export function getHistoryStats() {
  const history = getHistory();

  if (history.length === 0) {
    return {
      totalScans: 0,
      uniqueRepos: 0,
      averageRiskScore: 0,
      totalExposuresFixed: 0,
      latestScan: null
    };
  }

  const uniqueRepos = new Set(history.map(h => h.repoUrl).filter(Boolean)).size;
  const avgRisk = history.reduce((sum, h) => sum + (h.riskScore.concert || 0), 0) / history.length;

  return {
    totalScans: history.length,
    uniqueRepos,
    averageRiskScore: Math.round(avgRisk * 10) / 10,
    latestScan: history[0] || null
  };
}

export function exportHistoryAsCSV(): string {
  const history = getHistory();

  const headers = [
    'Scan ID',
    'Repository',
    'Branch',
    'Date',
    'Total Exposures',
    'Critical',
    'High',
    'Medium',
    'Low',
    'CVEs',
    'Secrets',
    'Certificates',
    'Misconfigurations',
    'Licenses',
    'Code Security',
    'Risk Score',
    'Status'
  ];

  const rows = history.map(h => [
    h.scanId,
    h.repoName,
    h.branch || '',
    new Date(h.scanDate).toLocaleString(),
    h.totalExposures,
    h.bySeverity.critical,
    h.bySeverity.high,
    h.bySeverity.medium,
    h.bySeverity.low,
    h.byType.cve,
    h.byType.secret,
    h.byType.certificate,
    h.byType.misconfiguration,
    h.byType.license,
    h.byType.codeSecurity,
    h.riskScore.concert,
    h.status
  ]);

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}
