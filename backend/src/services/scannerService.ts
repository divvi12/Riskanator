import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { CVE } from '../types';

const execPromise = promisify(exec);

// Simple exec wrapper with proper string conversion
const execAsync = async (command: string, options?: any): Promise<{ stdout: string; stderr: string }> => {
  const result = await execPromise(command, options);
  return {
    stdout: result.stdout?.toString() || '',
    stderr: result.stderr?.toString() || ''
  };
};

export interface ScanResult {
  cves: CVE[];
  scanType: string;
  success: boolean;
  error?: string;
}

// NPM Audit Scanner
export async function runNpmAudit(repoPath: string): Promise<ScanResult> {
  const packageJsonPath = path.join(repoPath, 'package.json');
  const packageLockPath = path.join(repoPath, 'package-lock.json');
  const shrinkwrapPath = path.join(repoPath, 'npm-shrinkwrap.json');

  console.log('=== NPM AUDIT DIAGNOSTICS ===');
  console.log('repoPath:', repoPath);
  console.log('package.json exists:', fs.existsSync(packageJsonPath));
  console.log('package-lock.json exists:', fs.existsSync(packageLockPath));

  if (!fs.existsSync(packageJsonPath)) {
    console.log('No package.json found, skipping npm audit');
    console.log('=== NPM AUDIT DIAGNOSTICS END ===');
    return { cves: [], scanType: 'npm', success: true };
  }

  try {
    // Check if lockfile already exists
    let hasLockfile = fs.existsSync(packageLockPath) || fs.existsSync(shrinkwrapPath);

    // If no lockfile, try to create one
    if (!hasLockfile) {
      console.log('No lockfile found, running npm install --package-lock-only...');
      try {
        await execAsync('npm install --package-lock-only --ignore-scripts', {
          cwd: repoPath,
          timeout: 180000 // 3 minutes for large repos
        });
        console.log('npm install completed');
        hasLockfile = fs.existsSync(packageLockPath);
      } catch (installError: any) {
        console.log('npm install failed:', installError.message?.substring(0, 200));
      }
    } else {
      console.log('Lockfile already exists, skipping npm install');
    }

    // Check if we have a lockfile now
    if (!hasLockfile) {
      console.log('No lockfile available, cannot run npm audit');
      console.log('=== NPM AUDIT DIAGNOSTICS END ===');
      return {
        cves: [],
        scanType: 'npm',
        success: false,
        error: 'npm audit requires a lockfile (package-lock.json) which could not be generated'
      };
    }

    // Run npm audit
    console.log('Running npm audit --json...');
    try {
      const { stdout, stderr } = await execAsync('npm audit --json', {
        cwd: repoPath,
        timeout: 120000, // 2 minutes
        maxBuffer: 10 * 1024 * 1024
      });

      console.log('npm audit stdout length:', stdout.length);
      if (stderr) {
        console.log('npm audit stderr:', stderr.substring(0, 500));
      }
      console.log('=== NPM AUDIT DIAGNOSTICS END ===');

      const cves = parseNpmAuditOutput(stdout);
      return { cves, scanType: 'npm', success: true };
    } catch (auditError: any) {
      // npm audit exits with non-zero when vulnerabilities are found
      const output = auditError.stdout?.toString() || '';
      const stderr = auditError.stderr?.toString() || '';

      console.log('npm audit exited non-zero (normal when vulns found)');
      console.log('npm audit stdout length:', output.length);
      console.log('npm audit stderr preview:', stderr.substring(0, 500));
      console.log('=== NPM AUDIT DIAGNOSTICS END ===');

      // If we got JSON output, try to parse it
      if (output && output.trim().startsWith('{')) {
        const cves = parseNpmAuditOutput(output);
        return { cves, scanType: 'npm', success: true };
      }

      // Check if it's ENOLOCK error
      if (stderr.includes('ENOLOCK')) {
        return {
          cves: [],
          scanType: 'npm',
          success: false,
          error: 'npm audit requires a lockfile which could not be generated'
        };
      }

      return { cves: [], scanType: 'npm', success: false, error: auditError.message };
    }
  } catch (error: any) {
    console.error('npm audit error:', error.message);
    console.log('=== NPM AUDIT DIAGNOSTICS END ===');
    return { cves: [], scanType: 'npm', success: false, error: error.message };
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
    const pipAudit = '/usr/local/bin/pip-audit';

    // Diagnostic logging
    console.log('=== PIP-AUDIT DIAGNOSTICS ===');
    console.log('repoPath:', repoPath);

    // Check binary exists
    try {
      const { stdout: lsOut } = await execAsync(`ls -la ${pipAudit}`, { timeout: 5000 });
      console.log('ls pip-audit:', lsOut.trim());
    } catch (e: any) {
      console.log('ls failed:', e.message);
    }

    // Skip version check in production - pip-audit hangs while downloading databases
    // Instead, just verify the binary exists (we did ls check above)
    console.log('Skipping pip-audit --version check (causes timeout on first DB download)');

    // Use --progress-spinner off to prevent stdout buffering issues
    // Use 5 minute timeout since pip-audit needs to:
    // 1. Download vulnerability database from PyPI
    // 2. Resolve and check all packages in requirements.txt
    let command = `${pipAudit} --format json --progress-spinner off`;
    if (fs.existsSync(requirementsPath)) {
      command += ` -r ${requirementsPath}`;
    }

    console.log('Running pip-audit command:', command);

    try {
      const { stdout, stderr } = await execAsync(command + ' 2>&1', {
        cwd: repoPath,
        timeout: 300000, // 5 minutes
        maxBuffer: 10 * 1024 * 1024
      });

      console.log('pip-audit stdout length:', stdout.length);
      console.log('=== PIP-AUDIT DIAGNOSTICS END ===');

      const cves = parsePipAuditOutput(stdout);
      return { cves, scanType: 'pip', success: true };
    } catch (cmdError: any) {
      // pip-audit returns non-zero exit code when vulnerabilities are found
      // Check if we got valid JSON output despite the error
      const output = cmdError.stdout?.toString() || '';
      const stderr = cmdError.stderr?.toString() || '';

      console.log('pip-audit command error:', cmdError.message);
      console.log('pip-audit killed:', cmdError.killed);
      console.log('pip-audit signal:', cmdError.signal);
      console.log('pip-audit stdout preview:', output.substring(0, 500));
      console.log('pip-audit stderr preview:', stderr.substring(0, 500));

      // If we got JSON output, try to parse it (pip-audit exits non-zero when vulns found)
      if (output && output.trim().startsWith('[')) {
        console.log('pip-audit has JSON output despite error, parsing...');
        const cves = parsePipAuditOutput(output);
        return { cves, scanType: 'pip', success: true };
      }

      // If timeout, report it clearly
      if (cmdError.killed || cmdError.signal === 'SIGTERM') {
        return {
          cves: [],
          scanType: 'pip',
          success: false,
          error: 'pip-audit timed out (>5 min) - repository may have too many dependencies'
        };
      }

      return { cves: [], scanType: 'pip', success: false, error: cmdError.message };
    }
  } catch (error: any) {
    console.error('pip-audit unexpected error:', error.message);
    return { cves: [], scanType: 'pip', success: false, error: error.message };
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
    const trivy = '/usr/local/bin/trivy';

    // Diagnostic logging
    console.log('=== TRIVY DIAGNOSTICS ===');
    console.log('repoPath:', repoPath);
    console.log('cwd:', process.cwd());
    console.log('PATH:', process.env.PATH);

    // Check binary exists
    try {
      const { stdout: lsOut } = await execAsync(`ls -la ${trivy}`, { timeout: 5000 });
      console.log('ls trivy:', lsOut.trim());
    } catch (e: any) {
      console.log('ls failed:', e.message);
    }

    // Check binary type
    try {
      const { stdout: fileOut } = await execAsync(`file ${trivy}`, { timeout: 5000 });
      console.log('file trivy:', fileOut.trim());
    } catch (e: any) {
      console.log('file cmd failed:', e.message);
    }

    // Try version check with detailed error capture
    console.log('Testing trivy --version...');
    try {
      const { stdout: vOut, stderr: vErr } = await execAsync(`${trivy} --version`, { timeout: 30000 });
      console.log('trivy version OK:', vOut.trim());
    } catch (vErr: any) {
      console.error('trivy --version FAILED');
      console.error('  message:', vErr.message);
      console.error('  code:', vErr.code);
      console.error('  signal:', vErr.signal);
      console.error('  killed:', vErr.killed);
      console.error('  stdout:', vErr.stdout?.toString().substring(0, 200));
      console.error('  stderr:', vErr.stderr?.toString().substring(0, 200));
      return {
        cves: [],
        scanType: 'trivy',
        success: false,
        error: `Trivy version check failed: code=${vErr.code}, signal=${vErr.signal}, msg=${vErr.message}`
      };
    }

    // Run the actual scan - use --quiet to suppress progress output
    // Do NOT redirect stderr to stdout (2>&1) as it corrupts JSON output
    console.log('Running trivy fs scan...');
    try {
      const { stdout, stderr } = await execAsync(
        `${trivy} fs --format json --scanners vuln --quiet ${repoPath}`,
        {
          cwd: repoPath,
          timeout: 300000,
          maxBuffer: 20 * 1024 * 1024
        }
      );

      console.log('trivy scan stdout length:', stdout.length);
      if (stderr) {
        console.log('trivy stderr:', stderr.substring(0, 500));
      }
      console.log('=== TRIVY DIAGNOSTICS END ===');

      const cves = parseTrivyOutput(stdout);
      return { cves, scanType: 'trivy', success: true };
    } catch (trivyError: any) {
      // Trivy may exit non-zero but still produce valid JSON output
      const output = trivyError.stdout?.toString() || '';
      const stderr = trivyError.stderr?.toString() || '';

      console.log('trivy command error:', trivyError.message);
      console.log('trivy stdout preview:', output.substring(0, 500));
      console.log('trivy stderr preview:', stderr.substring(0, 500));

      // If we got JSON output, try to parse it
      if (output && (output.trim().startsWith('{') || output.trim().startsWith('['))) {
        console.log('trivy has JSON output despite error, parsing...');
        const cves = parseTrivyOutput(output);
        return { cves, scanType: 'trivy', success: true };
      }

      return { cves: [], scanType: 'trivy', success: false, error: trivyError.message };
    }
  } catch (error: any) {
    console.error('Trivy unexpected error:', error.message);
    console.error('Stack:', error.stack);
    return { cves: [], scanType: 'trivy', success: false, error: error.message };
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
  // Note: Semgrep is disabled as it requires glibc and is too large for cloud builds
  // Trivy DB is pre-downloaded in Dockerfile to avoid first-run delays
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
      // TODO: pip-audit disabled - consistently times out (>5min) downloading vuln DB on Cloud Run
      // Need to either pre-cache the DB in Dockerfile or use a different Python scanner
      condition: false // languages.includes('python')
    },
    {
      name: 'Trivy',
      run: () => runTrivy(repoPath),
      condition: languages.includes('docker')
    }
  ];

  const activeScanners = scanners.filter(s => s.condition);

  // Log which tools are available and being used
  console.log('=== CVE SCANNER TOOLS ===');
  console.log('Tools being used for this scan:');
  activeScanners.forEach(s => console.log(`  - ${s.name}`));
  console.log('Tools NOT being used (conditions not met):');
  scanners.filter(s => !s.condition).forEach(s => console.log(`  - ${s.name}`));
  console.log('=========================');

  onProgress?.(`Running ${activeScanners.length} scanner(s) in parallel: ${activeScanners.map(s => s.name).join(', ')}`);

  // Run all scanners in parallel, reporting results as they complete
  const scanPromises = activeScanners.map(async (scanner) => {
    console.log(`[TOOL] Starting ${scanner.name}...`);
    onProgress?.(`Starting ${scanner.name}...`);
    const startTime = Date.now();

    // Set up periodic progress updates while scanner is running
    let isRunning = true;
    const progressInterval = setInterval(() => {
      if (isRunning) {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        onProgress?.(`Scanning with ${scanner.name}... (${elapsed}s elapsed)`);
      }
    }, 20000); // Update every 20 seconds

    try {
      const result = await scanner.run();
      isRunning = false;
      clearInterval(progressInterval);

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      if (result.success) {
        if (result.cves.length > 0) {
          const critical = result.cves.filter(c => c.severity === 'critical').length;
          const high = result.cves.filter(c => c.severity === 'high').length;
          console.log(`[TOOL] ${scanner.name} complete (${elapsed}s): ${result.cves.length} vulnerabilities found`);
          onProgress?.(`${scanner.name} complete (${elapsed}s): ${result.cves.length} vulnerabilities found (${critical} critical, ${high} high)`);
        } else {
          console.log(`[TOOL] ${scanner.name} complete (${elapsed}s): No vulnerabilities found`);
          onProgress?.(`${scanner.name} complete (${elapsed}s): No vulnerabilities found`);
        }
      } else {
        console.log(`[TOOL] ${scanner.name} warning: ${result.error || 'unknown error'}`);
        onProgress?.(`${scanner.name} warning: ${result.error || 'unknown error'}`);
      }

      return result;
    } catch (error) {
      isRunning = false;
      clearInterval(progressInterval);
      throw error;
    }
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
