import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { CVE } from '../types';

const execAsync = promisify(exec);

export interface ScanResult {
  cves: CVE[];
  scanType: string;
  success: boolean;
  error?: string;
}

// NPM Audit Scanner
export async function runNpmAudit(repoPath: string): Promise<ScanResult> {
  const packageJsonPath = path.join(repoPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return { cves: [], scanType: 'npm', success: true };
  }

  try {
    // First install dependencies (with package-lock generation)
    try {
      await execAsync('npm install --package-lock-only --ignore-scripts', {
        cwd: repoPath,
        timeout: 120000
      });
    } catch (installError) {
      // Continue even if install fails, audit might still work
    }

    // Run npm audit
    const { stdout } = await execAsync('npm audit --json 2>/dev/null || true', {
      cwd: repoPath,
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024
    });

    const cves = parseNpmAuditOutput(stdout);
    return { cves, scanType: 'npm', success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { cves: [], scanType: 'npm', success: false, error: errorMessage };
  }
}

function parseNpmAuditOutput(output: string): CVE[] {
  const cves: CVE[] = [];

  try {
    if (!output || output.trim() === '') {
      return cves;
    }

    const auditData = JSON.parse(output);

    // Handle npm audit v2 format
    if (auditData.vulnerabilities) {
      for (const [pkgName, vuln] of Object.entries(auditData.vulnerabilities)) {
        const vulnData = vuln as any;

        for (const via of vulnData.via || []) {
          if (typeof via === 'object' && via.source) {
            const cve: CVE = {
              id: via.name || `GHSA-${via.source}`,
              cvss: via.cvss?.score || mapSeverityToCvss(vulnData.severity),
              component: pkgName,
              version: vulnData.range || 'unknown',
              fixedVersion: vulnData.fixAvailable?.version || undefined,
              source: 'npm',
              sourceType: 'sca',
              severity: mapSeverity(vulnData.severity),
              description: via.title || 'No description available',
              references: via.url ? [via.url] : [],
              cisaKEV: false
            };

            // Avoid duplicates
            if (!cves.find(c => c.id === cve.id && c.component === cve.component)) {
              cves.push(cve);
            }
          }
        }
      }
    }

    // Handle npm audit v1 format
    if (auditData.advisories) {
      for (const [, advisory] of Object.entries(auditData.advisories)) {
        const adv = advisory as any;

        const cve: CVE = {
          id: adv.cves?.[0] || `GHSA-${adv.id}`,
          cvss: adv.cvss?.score || mapSeverityToCvss(adv.severity),
          component: adv.module_name,
          version: adv.vulnerable_versions || 'unknown',
          fixedVersion: adv.patched_versions || undefined,
          source: 'npm',
          sourceType: 'sca',
          severity: mapSeverity(adv.severity),
          description: adv.title || adv.overview || 'No description available',
          references: adv.url ? [adv.url] : [],
          cisaKEV: false
        };

        if (!cves.find(c => c.id === cve.id && c.component === cve.component)) {
          cves.push(cve);
        }
      }
    }
  } catch (error) {
    console.error('Error parsing npm audit output:', error);
  }

  return cves;
}

// Pip Audit Scanner
export async function runPipAudit(repoPath: string): Promise<ScanResult> {
  const requirementsPath = path.join(repoPath, 'requirements.txt');
  const pipfilePath = path.join(repoPath, 'Pipfile');
  const pyprojectPath = path.join(repoPath, 'pyproject.toml');

  if (!fs.existsSync(requirementsPath) && !fs.existsSync(pipfilePath) && !fs.existsSync(pyprojectPath)) {
    return { cves: [], scanType: 'pip', success: true };
  }

  try {
    // Check if pip-audit is installed
    try {
      await execAsync('pip-audit --version', { timeout: 10000 });
    } catch {
      return {
        cves: [],
        scanType: 'pip',
        success: false,
        error: 'pip-audit not installed. Run: pip install pip-audit'
      };
    }

    let command = 'pip-audit --format json';
    if (fs.existsSync(requirementsPath)) {
      command += ` -r ${requirementsPath}`;
    }

    const { stdout } = await execAsync(command + ' 2>/dev/null || true', {
      cwd: repoPath,
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });

    const cves = parsePipAuditOutput(stdout);
    return { cves, scanType: 'pip', success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { cves: [], scanType: 'pip', success: false, error: errorMessage };
  }
}

function parsePipAuditOutput(output: string): CVE[] {
  const cves: CVE[] = [];

  try {
    if (!output || output.trim() === '') {
      return cves;
    }

    const auditData = JSON.parse(output);

    for (const vuln of auditData) {
      const cve: CVE = {
        id: vuln.id || vuln.vuln_id || `PYSEC-${Date.now()}`,
        cvss: vuln.cvss || mapSeverityToCvss(vuln.severity || 'medium'),
        component: vuln.name,
        version: vuln.version || 'unknown',
        fixedVersion: vuln.fix_versions?.[0] || undefined,
        source: 'pip',
        sourceType: 'sca',
        severity: mapSeverity(determinePipSeverity(vuln)),
        description: vuln.description || 'No description available',
        references: vuln.aliases || [],
        cisaKEV: false
      };

      cves.push(cve);
    }
  } catch (error) {
    console.error('Error parsing pip-audit output:', error);
  }

  return cves;
}

function determinePipSeverity(vuln: any): string {
  if (vuln.cvss && vuln.cvss >= 9.0) return 'critical';
  if (vuln.cvss && vuln.cvss >= 7.0) return 'high';
  if (vuln.cvss && vuln.cvss >= 4.0) return 'medium';
  if (vuln.cvss) return 'low';
  return 'medium';
}

// Semgrep Scanner (SAST)
export async function runSemgrep(repoPath: string): Promise<ScanResult> {
  try {
    // Check if semgrep is installed
    try {
      await execAsync('semgrep --version', { timeout: 10000 });
    } catch {
      return {
        cves: [],
        scanType: 'semgrep',
        success: false,
        error: 'Semgrep not installed. Run: pip install semgrep'
      };
    }

    const { stdout } = await execAsync(
      'semgrep --config auto --json --quiet 2>/dev/null || true',
      {
        cwd: repoPath,
        timeout: 300000, // 5 minutes
        maxBuffer: 20 * 1024 * 1024
      }
    );

    const cves = parseSemgrepOutput(stdout, repoPath);
    return { cves, scanType: 'semgrep', success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { cves: [], scanType: 'semgrep', success: false, error: errorMessage };
  }
}

function parseSemgrepOutput(output: string, repoPath: string): CVE[] {
  const cves: CVE[] = [];

  try {
    if (!output || output.trim() === '') {
      return cves;
    }

    const semgrepData = JSON.parse(output);

    for (const result of semgrepData.results || []) {
      const relativePath = result.path.replace(repoPath + '/', '');
      const cve: CVE = {
        id: result.check_id || `SAST-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        cvss: mapSeverityToCvss(result.extra?.severity || 'medium'),
        component: relativePath,
        version: `Line ${result.start?.line || 'unknown'}`,
        source: 'semgrep',
        sourceType: 'sast',
        severity: mapSeverity(result.extra?.severity || 'medium'),
        description: result.extra?.message || result.check_id || 'Code vulnerability detected',
        references: result.extra?.metadata?.references || [],
        cisaKEV: false
      };

      cves.push(cve);
    }
  } catch (error) {
    console.error('Error parsing semgrep output:', error);
  }

  return cves;
}

// Trivy Scanner (Container)
export async function runTrivy(repoPath: string): Promise<ScanResult> {
  const dockerfilePath = path.join(repoPath, 'Dockerfile');

  if (!fs.existsSync(dockerfilePath)) {
    return { cves: [], scanType: 'trivy', success: true };
  }

  try {
    // Check if trivy is installed
    try {
      await execAsync('trivy --version', { timeout: 10000 });
    } catch {
      return {
        cves: [],
        scanType: 'trivy',
        success: false,
        error: 'Trivy not installed. See: https://aquasecurity.github.io/trivy/'
      };
    }

    const { stdout } = await execAsync(
      `trivy fs --format json --scanners vuln ${repoPath} 2>/dev/null || true`,
      {
        cwd: repoPath,
        timeout: 300000,
        maxBuffer: 20 * 1024 * 1024
      }
    );

    const cves = parseTrivyOutput(stdout);
    return { cves, scanType: 'trivy', success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { cves: [], scanType: 'trivy', success: false, error: errorMessage };
  }
}

function parseTrivyOutput(output: string): CVE[] {
  const cves: CVE[] = [];

  try {
    if (!output || output.trim() === '') {
      return cves;
    }

    const trivyData = JSON.parse(output);

    for (const result of trivyData.Results || []) {
      for (const vuln of result.Vulnerabilities || []) {
        const cve: CVE = {
          id: vuln.VulnerabilityID,
          cvss: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || mapSeverityToCvss(vuln.Severity),
          component: vuln.PkgName,
          version: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion || undefined,
          source: 'trivy',
          sourceType: 'container',
          severity: mapSeverity(vuln.Severity),
          description: vuln.Description || vuln.Title || 'No description available',
          references: vuln.References || [],
          cisaKEV: false
        };

        if (!cves.find(c => c.id === cve.id && c.component === cve.component)) {
          cves.push(cve);
        }
      }
    }
  } catch (error) {
    console.error('Error parsing trivy output:', error);
  }

  return cves;
}

// Helper functions
function mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
  const s = severity?.toLowerCase() || 'medium';
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  return 'low';
}

function mapSeverityToCvss(severity: string): number {
  const s = severity?.toLowerCase() || 'medium';
  if (s === 'critical') return 9.5;
  if (s === 'high') return 7.5;
  if (s === 'medium' || s === 'moderate') return 5.5;
  return 3.0;
}

// Main scanning orchestrator
export async function scanRepository(
  repoPath: string,
  languages: string[],
  onProgress?: (message: string) => void
): Promise<CVE[]> {
  const allCves: CVE[] = [];

  // Build list of scanners to run based on detected languages
  const scanners: Array<{
    name: string;
    run: () => Promise<ScanResult>;
    condition: boolean;
  }> = [
    {
      name: 'npm audit',
      run: () => runNpmAudit(repoPath),
      condition: languages.includes('javascript')
    },
    {
      name: 'pip-audit',
      run: () => runPipAudit(repoPath),
      condition: languages.includes('python')
    },
    {
      name: 'Semgrep SAST',
      run: () => runSemgrep(repoPath),
      condition: true // Always run SAST
    },
    {
      name: 'Trivy container',
      run: () => runTrivy(repoPath),
      condition: languages.includes('docker')
    }
  ];

  const activeScanners = scanners.filter(s => s.condition);
  onProgress?.(`Running ${activeScanners.length} scanner(s) in parallel: ${activeScanners.map(s => s.name).join(', ')}`);

  // Run all scanners in parallel, reporting results as they complete
  const scanPromises = activeScanners.map(async (scanner) => {
    onProgress?.(`Starting ${scanner.name}...`);
    const startTime = Date.now();
    const result = await scanner.run();
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    if (result.success) {
      if (result.cves.length > 0) {
        const critical = result.cves.filter(c => c.severity === 'critical').length;
        const high = result.cves.filter(c => c.severity === 'high').length;
        onProgress?.(`${scanner.name} complete (${elapsed}s): ${result.cves.length} vulnerabilities found (${critical} critical, ${high} high)`);
      } else {
        onProgress?.(`${scanner.name} complete (${elapsed}s): No vulnerabilities found`);
      }
    } else {
      onProgress?.(`${scanner.name} warning: ${result.error || 'unknown error'}`);
    }

    return result;
  });

  const results = await Promise.all(scanPromises);

  for (const result of results) {
    if (result.success) {
      allCves.push(...result.cves);
    }
  }

  // Report summary
  if (allCves.length > 0) {
    const uniqueCves = [...new Set(allCves.map(c => c.id))].length;
    onProgress?.(`CVE scanning complete: ${allCves.length} total findings (${uniqueCves} unique)`);
  }

  return allCves;
}
