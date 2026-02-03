import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { MisconfigurationExposure } from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

export interface MisconfigScanResult {
  exposures: MisconfigurationExposure[];
  success: boolean;
  error?: string;
}

// Resource types that are publicly accessible when misconfigured
const PUBLIC_ACCESS_CHECKS = [
  'public',
  's3',
  'bucket',
  'acl',
  'security_group',
  'firewall',
  '0.0.0.0',
  'internet',
  'everyone',
  'all_users',
  'anonymous'
];

// Map Checkov severity to our severity
function mapSeverity(checkovSeverity: string): 'critical' | 'high' | 'medium' | 'low' {
  const severity = checkovSeverity?.toUpperCase() || 'MEDIUM';

  if (severity === 'CRITICAL') return 'critical';
  if (severity === 'HIGH') return 'high';
  if (severity === 'MEDIUM') return 'medium';
  return 'low';
}

// Determine if the misconfiguration could lead to public access
function isPubliclyAccessible(checkId: string, checkName: string, guideline: string): boolean {
  const combined = `${checkId} ${checkName} ${guideline}`.toLowerCase();
  return PUBLIC_ACCESS_CHECKS.some(keyword => combined.includes(keyword));
}

// Determine framework from file path
function determineFramework(filePath: string): string {
  const lower = filePath.toLowerCase();

  if (lower.includes('.tf') || lower.includes('terraform')) return 'terraform';
  if (lower.includes('kubernetes') || lower.includes('k8s') || lower.endsWith('.yaml') || lower.endsWith('.yml')) {
    // Check for k8s-specific patterns
    if (lower.includes('deployment') || lower.includes('service') || lower.includes('pod')) {
      return 'kubernetes';
    }
  }
  if (lower.includes('cloudformation') || lower.includes('.template')) return 'cloudformation';
  if (lower.includes('ansible')) return 'ansible';
  if (lower.includes('docker')) return 'docker';
  if (lower.includes('helm')) return 'helm';
  if (lower.includes('serverless')) return 'serverless';

  return 'iac';
}

// Generate a user-friendly title
function generateTitle(checkName: string, resourceType: string): string {
  // Clean up check name
  let title = checkName
    .replace(/^(Ensure|Check|Verify)\s+/i, '')
    .replace(/\s+is\s+(set|enabled|configured|defined)/i, '')
    .trim();

  // Capitalize first letter
  title = title.charAt(0).toUpperCase() + title.slice(1);

  // Truncate if too long
  if (title.length > 80) {
    title = title.substring(0, 77) + '...';
  }

  return title;
}

// Run Checkov scanner
export async function scanWithCheckov(repoPath: string): Promise<MisconfigScanResult> {
  const exposures: MisconfigurationExposure[] = [];

  try {
    // Check if Checkov is installed
    try {
      await execAsync('checkov --version', { timeout: 10000 });
    } catch {
      return {
        exposures: [],
        success: false,
        error: 'Checkov not installed. Run: pip install checkov'
      };
    }

    console.log('Running Checkov scan...');

    // Run Checkov with JSON output
    const { stdout, stderr } = await execAsync(
      `checkov -d "${repoPath}" --output json --quiet 2>/dev/null || true`,
      {
        cwd: repoPath,
        timeout: 600000, // 10 minutes
        maxBuffer: 100 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      // No IaC files found or no issues
      return { exposures: [], success: true };
    }

    try {
      const results = JSON.parse(stdout);

      // Checkov returns an array of check type objects like:
      // [{ "check_type": "terraform", "results": { "failed_checks": [...] } }]
      const checkTypes = Array.isArray(results) ? results : (results.results || [results]);

      for (const checkType of checkTypes) {
        const checks = checkType as any;
        // failed_checks can be directly on checks or nested under checks.results
        const failedChecks = checks?.failed_checks || checks?.results?.failed_checks;

        if (!failedChecks || failedChecks.length === 0) continue;

        for (const check of failedChecks) {
          const checkId = check.check_id || 'UNKNOWN';
          const checkName = check.check || check.check_name || 'Unknown Check';
          const guideline = check.guideline || '';
          const severity = mapSeverity(check.severity);
          const resourceType = check.resource || check.resource_type || 'Unknown';
          const filePath = check.file_path || check.path || 'unknown';
          const lineNumber = check.file_line_range?.[0] || check.resource_line || undefined;

          const relativePath = filePath.replace(repoPath + '/', '').replace(repoPath, '').replace(/^\//, '');
          const location = lineNumber ? `${relativePath}:${lineNumber}` : relativePath;
          const framework = determineFramework(filePath);
          const isPublic = isPubliclyAccessible(checkId, checkName, guideline);

          const exposure: MisconfigurationExposure = {
            id: uuidv4(),
            type: 'misconfiguration',
            title: generateTitle(checkName, resourceType),
            description: `${checkName}. ${guideline ? 'Guideline: ' + guideline : ''}`.trim(),
            severity,
            riskScore: { concert: 0, comprehensive: 0 },
            location,
            detectedAt: new Date().toISOString(),
            source: 'checkov',
            resourceType,
            checkId,
            checkName,
            guideline: guideline || undefined,
            isPubliclyAccessible: isPublic,
            framework,
            resourceName: check.resource_address || check.resource || undefined,
            codeSnippet: check.code_block ? check.code_block.join('\n') : undefined
          };

          exposures.push(exposure);
        }
      }
    } catch (parseError) {
      console.error('Error parsing Checkov output:', parseError);
      // Try to extract individual JSON objects
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.trim().startsWith('{')) {
          try {
            const result = JSON.parse(line);
            // Process if it's a valid result
          } catch {
            continue;
          }
        }
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error running Checkov';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Run tfsec for Terraform-specific scanning
export async function scanWithTfsec(repoPath: string): Promise<MisconfigScanResult> {
  const exposures: MisconfigurationExposure[] = [];

  // Check if there are any Terraform files
  const hasTerraform = fs.readdirSync(repoPath, { recursive: true })
    .some(file => String(file).endsWith('.tf'));

  if (!hasTerraform) {
    return { exposures: [], success: true };
  }

  try {
    // Check if tfsec is installed
    try {
      await execAsync('tfsec --version', { timeout: 10000 });
    } catch {
      return {
        exposures: [],
        success: true,
        error: 'tfsec not installed. See: https://github.com/aquasecurity/tfsec'
      };
    }

    const { stdout } = await execAsync(
      `tfsec "${repoPath}" --format json 2>/dev/null || true`,
      {
        cwd: repoPath,
        timeout: 300000,
        maxBuffer: 50 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    try {
      const results = JSON.parse(stdout);

      for (const result of results.results || []) {
        const severity = mapSeverity(result.severity);
        const isPublic = isPubliclyAccessible(result.rule_id, result.rule_description, result.description);

        const exposure: MisconfigurationExposure = {
          id: uuidv4(),
          type: 'misconfiguration',
          title: generateTitle(result.rule_description, result.resource || 'Terraform'),
          description: result.description || result.rule_description,
          severity,
          riskScore: { concert: 0, comprehensive: 0 },
          location: result.location?.filename
            ? `${result.location.filename}:${result.location.start_line}`
            : 'unknown',
          detectedAt: new Date().toISOString(),
          source: 'tfsec',
          resourceType: result.resource || 'terraform_resource',
          checkId: result.rule_id,
          checkName: result.rule_description,
          guideline: result.resolution,
          isPubliclyAccessible: isPublic,
          framework: 'terraform',
          resourceName: result.resource,
          codeSnippet: result.location?.snippet
        };

        exposures.push(exposure);
      }
    } catch (parseError) {
      console.error('Error parsing tfsec output:', parseError);
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error running tfsec';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Scan for Kubernetes misconfigurations
export async function scanKubernetes(repoPath: string): Promise<MisconfigScanResult> {
  const exposures: MisconfigurationExposure[] = [];

  // Check if there are any Kubernetes YAML files
  const hasK8s = fs.readdirSync(repoPath, { recursive: true })
    .some(file => {
      const f = String(file);
      return (f.endsWith('.yaml') || f.endsWith('.yml')) &&
             (f.includes('kubernetes') || f.includes('k8s') ||
              f.includes('deployment') || f.includes('service'));
    });

  if (!hasK8s) {
    return { exposures: [], success: true };
  }

  try {
    // Check if kubesec is installed
    try {
      await execAsync('kubesec version 2>/dev/null', { timeout: 10000 });
    } catch {
      // kubesec not installed, skip
      return { exposures: [], success: true };
    }

    // Find all YAML files that might be Kubernetes manifests
    const yamlFiles: string[] = [];
    const walkDir = (dir: string) => {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory() && !['node_modules', '.git'].includes(file)) {
          walkDir(fullPath);
        } else if (file.endsWith('.yaml') || file.endsWith('.yml')) {
          yamlFiles.push(fullPath);
        }
      }
    };
    walkDir(repoPath);

    for (const yamlFile of yamlFiles) {
      try {
        const { stdout } = await execAsync(
          `kubesec scan "${yamlFile}" --format json 2>/dev/null || true`,
          {
            cwd: repoPath,
            timeout: 60000,
            maxBuffer: 10 * 1024 * 1024
          }
        );

        if (!stdout || stdout.trim() === '') continue;

        const results = JSON.parse(stdout);

        for (const result of results) {
          // Process critical findings
          for (const finding of result.scoring?.critical || []) {
            const relativePath = yamlFile.replace(repoPath + '/', '');

            const exposure: MisconfigurationExposure = {
              id: uuidv4(),
              type: 'misconfiguration',
              title: finding.selector || 'Kubernetes Security Issue',
              description: finding.reason || 'Critical security misconfiguration in Kubernetes manifest',
              severity: 'critical',
              riskScore: { concert: 0, comprehensive: 0 },
              location: relativePath,
              detectedAt: new Date().toISOString(),
              source: 'kubesec',
              resourceType: result.object?.kind || 'kubernetes_resource',
              checkId: finding.id || 'KUBESEC',
              checkName: finding.selector,
              isPubliclyAccessible: false,
              framework: 'kubernetes',
              resourceName: result.object?.metadata?.name
            };

            exposures.push(exposure);
          }

          // Process advise (high/medium)
          for (const finding of result.scoring?.advise || []) {
            const relativePath = yamlFile.replace(repoPath + '/', '');

            const exposure: MisconfigurationExposure = {
              id: uuidv4(),
              type: 'misconfiguration',
              title: finding.selector || 'Kubernetes Security Advisory',
              description: finding.reason || 'Security improvement recommended for Kubernetes manifest',
              severity: 'medium',
              riskScore: { concert: 0, comprehensive: 0 },
              location: relativePath,
              detectedAt: new Date().toISOString(),
              source: 'kubesec',
              resourceType: result.object?.kind || 'kubernetes_resource',
              checkId: finding.id || 'KUBESEC',
              checkName: finding.selector,
              isPubliclyAccessible: false,
              framework: 'kubernetes',
              resourceName: result.object?.metadata?.name
            };

            exposures.push(exposure);
          }
        }
      } catch (fileError) {
        // Skip files that can't be scanned
        continue;
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning Kubernetes';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Run Trivy for IaC misconfiguration scanning (uses installed Trivy binary)
export async function scanWithTrivy(repoPath: string): Promise<MisconfigScanResult> {
  const exposures: MisconfigurationExposure[] = [];
  const trivy = '/usr/local/bin/trivy';

  try {
    // Check if Trivy is available
    try {
      await execAsync(`${trivy} --version`, { timeout: 10000 });
    } catch {
      return {
        exposures: [],
        success: false,
        error: 'Trivy not installed'
      };
    }

    console.log('Running Trivy misconfig scan...');

    // Run Trivy with misconfig scanner
    const { stdout, stderr } = await execAsync(
      `${trivy} fs --scanners misconfig --format json --quiet "${repoPath}"`,
      {
        cwd: repoPath,
        timeout: 300000, // 5 minutes
        maxBuffer: 50 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    try {
      const results = JSON.parse(stdout);

      for (const result of results.Results || []) {
        for (const misconfig of result.Misconfigurations || []) {
          const severity = mapSeverity(misconfig.Severity);
          const filePath = result.Target || 'unknown';
          const relativePath = filePath.replace(repoPath + '/', '').replace(repoPath, '').replace(/^\//, '');
          const framework = determineFramework(filePath);
          const isPublic = isPubliclyAccessible(misconfig.ID || '', misconfig.Title || '', misconfig.Description || '');

          const exposure: MisconfigurationExposure = {
            id: uuidv4(),
            type: 'misconfiguration',
            title: generateTitle(misconfig.Title || 'IaC Misconfiguration', misconfig.Type || 'unknown'),
            description: misconfig.Description || misconfig.Message || 'Infrastructure misconfiguration detected',
            severity,
            riskScore: { concert: 0, comprehensive: 0 },
            location: misconfig.CauseMetadata?.StartLine
              ? `${relativePath}:${misconfig.CauseMetadata.StartLine}`
              : relativePath,
            detectedAt: new Date().toISOString(),
            source: 'trivy',
            resourceType: misconfig.Type || 'iac_resource',
            checkId: misconfig.ID || 'TRIVY',
            checkName: misconfig.Title,
            guideline: misconfig.Resolution || misconfig.References?.join(', '),
            isPubliclyAccessible: isPublic,
            framework,
            resourceName: misconfig.CauseMetadata?.Resource,
            codeSnippet: misconfig.CauseMetadata?.Code?.Lines?.map((l: any) => l.Content).join('\n')
          };

          exposures.push(exposure);
        }
      }

      console.log(`Trivy misconfig scan found ${exposures.length} issues`);
    } catch (parseError) {
      console.error('Error parsing Trivy misconfig output:', parseError);
    }

    return { exposures, success: true };
  } catch (error: any) {
    // Trivy may exit non-zero but still produce valid output
    const output = error.stdout?.toString() || '';
    if (output && output.trim().startsWith('{')) {
      try {
        const results = JSON.parse(output);
        // Process results same as above
        for (const result of results.Results || []) {
          for (const misconfig of result.Misconfigurations || []) {
            const severity = mapSeverity(misconfig.Severity);
            const filePath = result.Target || 'unknown';
            const relativePath = filePath.replace(repoPath + '/', '');
            const framework = determineFramework(filePath);

            const exposure: MisconfigurationExposure = {
              id: uuidv4(),
              type: 'misconfiguration',
              title: generateTitle(misconfig.Title || 'IaC Misconfiguration', misconfig.Type || 'unknown'),
              description: misconfig.Description || 'Infrastructure misconfiguration detected',
              severity,
              riskScore: { concert: 0, comprehensive: 0 },
              location: misconfig.CauseMetadata?.StartLine
                ? `${relativePath}:${misconfig.CauseMetadata.StartLine}`
                : relativePath,
              detectedAt: new Date().toISOString(),
              source: 'trivy',
              resourceType: misconfig.Type || 'iac_resource',
              checkId: misconfig.ID || 'TRIVY',
              checkName: misconfig.Title,
              isPubliclyAccessible: false,
              framework
            };

            exposures.push(exposure);
          }
        }
        return { exposures, success: true };
      } catch {
        // Fall through to error
      }
    }

    const errorMessage = error instanceof Error ? error.message : 'Unknown error running Trivy misconfig scan';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Main misconfiguration scanning function
export async function runMisconfigScanning(repoPath: string): Promise<MisconfigScanResult> {
  const allExposures: MisconfigurationExposure[] = [];
  const errors: string[] = [];

  console.log('=== MISCONFIG SCANNER TOOLS ===');
  console.log('Available misconfiguration scanning tools:');
  console.log('  - Trivy (IaC scanner) - Primary');
  console.log('  - Checkov (IaC scanner) - Fallback');
  console.log('  - tfsec (Terraform) - Additional');
  console.log('  - kubesec (Kubernetes) - Additional');
  console.log('===============================');

  // Try Trivy first (already installed in container)
  console.log('[TOOL] Using Trivy for misconfiguration scanning...');
  const trivyResult = await scanWithTrivy(repoPath);
  if (trivyResult.success) {
    console.log(`[TOOL] Trivy complete: ${trivyResult.exposures.length} misconfigurations found`);
    allExposures.push(...trivyResult.exposures);
  } else {
    console.log(`[TOOL] Trivy failed: ${trivyResult.error}`);
  }
  if (trivyResult.error && !trivyResult.error.includes('not installed')) {
    errors.push(trivyResult.error);
  }

  // If Trivy found issues or succeeded, we're done
  if (trivyResult.success && trivyResult.exposures.length >= 0) {
    console.log(`[TOOL] Misconfiguration scan complete using Trivy. Total findings: ${allExposures.length}`);
    return {
      exposures: allExposures,
      success: true,
      error: errors.length > 0 ? errors.join('; ') : undefined
    };
  }

  // Fallback: Run Checkov if available (covers most IaC frameworks)
  console.log('[TOOL] Trivy unavailable, using Checkov as fallback...');
  const checkovResult = await scanWithCheckov(repoPath);
  if (checkovResult.success) {
    console.log(`[TOOL] Checkov complete: ${checkovResult.exposures.length} misconfigurations found`);
    allExposures.push(...checkovResult.exposures);
  } else {
    console.log(`[TOOL] Checkov failed: ${checkovResult.error}`);
  }
  if (checkovResult.error && !checkovResult.error.includes('not installed')) {
    errors.push(checkovResult.error);
  }

  // Run tfsec for additional Terraform coverage
  console.log('[TOOL] Running tfsec for additional Terraform coverage...');
  const tfsecResult = await scanWithTfsec(repoPath);
  if (tfsecResult.success) {
    console.log(`[TOOL] tfsec complete: ${tfsecResult.exposures.length} issues found`);
    // Deduplicate with existing results by checkId + location
    const existingKeys = new Set(allExposures.map(e => `${e.checkId}-${e.location}`));
    for (const exposure of tfsecResult.exposures) {
      const key = `${exposure.checkId}-${exposure.location}`;
      if (!existingKeys.has(key)) {
        allExposures.push(exposure);
      }
    }
  } else if (tfsecResult.error) {
    console.log(`[TOOL] tfsec not available: ${tfsecResult.error}`);
  }
  if (tfsecResult.error && !tfsecResult.error.includes('not installed')) {
    errors.push(tfsecResult.error);
  }

  // Run kubesec for Kubernetes
  console.log('[TOOL] Running kubesec for Kubernetes scanning...');
  const kubesecResult = await scanKubernetes(repoPath);
  if (kubesecResult.success) {
    console.log(`[TOOL] kubesec complete: ${kubesecResult.exposures.length} issues found`);
    const existingKeys = new Set(allExposures.map(e => `${e.checkId}-${e.location}`));
    for (const exposure of kubesecResult.exposures) {
      const key = `${exposure.checkId}-${exposure.location}`;
      if (!existingKeys.has(key)) {
        allExposures.push(exposure);
      }
    }
  } else if (kubesecResult.error) {
    console.log(`[TOOL] kubesec not available: ${kubesecResult.error}`);
  }
  if (kubesecResult.error && !kubesecResult.error.includes('not installed')) {
    errors.push(kubesecResult.error);
  }

  console.log(`[TOOL] Misconfiguration scan complete. Total findings: ${allExposures.length}`);
  return {
    exposures: allExposures,
    success: true,
    error: errors.length > 0 ? errors.join('; ') : undefined
  };
}
