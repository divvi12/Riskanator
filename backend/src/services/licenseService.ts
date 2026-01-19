import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { LicenseExposure } from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

export interface LicenseScanResult {
  exposures: LicenseExposure[];
  success: boolean;
  error?: string;
}

// License risk classification
interface LicenseInfo {
  risk: 'high' | 'medium' | 'low' | 'none';
  isCopyleft: boolean;
  requiresAttribution: boolean;
  commercialUseAllowed: boolean;
}

const LICENSE_CLASSIFICATIONS: Record<string, LicenseInfo> = {
  // High risk - strong copyleft
  'AGPL-3.0': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'AGPL-3.0-only': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'AGPL-3.0-or-later': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'GPL-3.0': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'GPL-3.0-only': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'GPL-3.0-or-later': { risk: 'high', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },

  // Medium risk - weaker copyleft
  'GPL-2.0': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'GPL-2.0-only': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'GPL-2.0-or-later': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'LGPL-3.0': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'LGPL-2.1': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'MPL-2.0': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'EPL-1.0': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },
  'EPL-2.0': { risk: 'medium', isCopyleft: true, requiresAttribution: true, commercialUseAllowed: true },

  // Low risk - permissive licenses
  'MIT': { risk: 'none', isCopyleft: false, requiresAttribution: true, commercialUseAllowed: true },
  'Apache-2.0': { risk: 'none', isCopyleft: false, requiresAttribution: true, commercialUseAllowed: true },
  'BSD-2-Clause': { risk: 'none', isCopyleft: false, requiresAttribution: true, commercialUseAllowed: true },
  'BSD-3-Clause': { risk: 'none', isCopyleft: false, requiresAttribution: true, commercialUseAllowed: true },
  'ISC': { risk: 'none', isCopyleft: false, requiresAttribution: true, commercialUseAllowed: true },
  'Unlicense': { risk: 'none', isCopyleft: false, requiresAttribution: false, commercialUseAllowed: true },
  'CC0-1.0': { risk: 'none', isCopyleft: false, requiresAttribution: false, commercialUseAllowed: true },
  '0BSD': { risk: 'none', isCopyleft: false, requiresAttribution: false, commercialUseAllowed: true },
  'WTFPL': { risk: 'none', isCopyleft: false, requiresAttribution: false, commercialUseAllowed: true },
};

// Normalize license name for lookup
function normalizeLicenseName(license: string): string {
  if (!license) return 'UNKNOWN';

  // Remove common suffixes/prefixes
  let normalized = license
    .trim()
    .replace(/^license:/i, '')
    .replace(/\s+/g, '-')
    .toUpperCase();

  // Handle common variations
  const variations: Record<string, string> = {
    'MIT LICENSE': 'MIT',
    'APACHE 2.0': 'Apache-2.0',
    'APACHE LICENSE 2.0': 'Apache-2.0',
    'BSD': 'BSD-3-Clause',
    'BSD LICENSE': 'BSD-3-Clause',
    'ISC LICENSE': 'ISC',
    'GPL': 'GPL-3.0',
    'GPL V3': 'GPL-3.0',
    'GPL V2': 'GPL-2.0',
    'LGPL': 'LGPL-3.0',
    'AGPL': 'AGPL-3.0',
    'MPL': 'MPL-2.0',
    'CC0': 'CC0-1.0',
    'UNLICENSED': 'UNKNOWN',
    'PROPRIETARY': 'PROPRIETARY',
    'COMMERCIAL': 'PROPRIETARY',
    '(MIT OR APACHE-2.0)': 'MIT', // Dual license, use permissive
  };

  return variations[normalized] || license;
}

// Get license info with fallback
function getLicenseInfo(license: string): LicenseInfo & { isUnknown: boolean } {
  const normalized = normalizeLicenseName(license);
  const info = LICENSE_CLASSIFICATIONS[normalized];

  if (info) {
    return { ...info, isUnknown: false };
  }

  // Unknown license - treat as medium risk
  return {
    risk: 'medium',
    isCopyleft: false,
    requiresAttribution: true,
    commercialUseAllowed: false, // Unknown, assume not allowed
    isUnknown: true
  };
}

// Determine severity based on license
function determineSeverity(licenseInfo: LicenseInfo & { isUnknown: boolean }): 'critical' | 'high' | 'medium' | 'low' {
  if (licenseInfo.risk === 'high') return 'high';
  if (licenseInfo.risk === 'medium' || licenseInfo.isUnknown) return 'medium';
  return 'low';
}

// Generate description based on license
function generateDescription(license: string, packageName: string, licenseInfo: LicenseInfo & { isUnknown: boolean }): string {
  if (licenseInfo.isUnknown) {
    return `Package ${packageName} has unknown or unrecognized license "${license}". Review the license terms before using in production or commercial applications.`;
  }

  if (licenseInfo.isCopyleft) {
    return `Package ${packageName} uses copyleft license ${license}. If you modify or distribute this software, you may be required to release your source code under the same license.`;
  }

  if (!licenseInfo.commercialUseAllowed) {
    return `Package ${packageName} uses license ${license} which may restrict commercial use. Review license terms before commercial deployment.`;
  }

  if (licenseInfo.requiresAttribution) {
    return `Package ${packageName} uses ${license} license which requires attribution. Ensure license notices are included in your distribution.`;
  }

  return `Package ${packageName} uses ${license} license.`;
}

// Scan npm packages for license issues
export async function scanNpmLicenses(repoPath: string): Promise<LicenseScanResult> {
  const exposures: LicenseExposure[] = [];
  const packageJsonPath = path.join(repoPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return { exposures: [], success: true };
  }

  try {
    // Install dependencies if node_modules doesn't exist
    const nodeModulesPath = path.join(repoPath, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      try {
        await execAsync('npm install --production --ignore-scripts --no-audit 2>/dev/null || true', {
          cwd: repoPath,
          timeout: 180000, // 3 minutes for npm install
          maxBuffer: 20 * 1024 * 1024
        });
      } catch {
        // Continue even if install fails - we'll try license-checker anyway
      }
    }

    // Run license-checker
    const { stdout } = await execAsync(
      'npx license-checker --json --production 2>/dev/null || true',
      {
        cwd: repoPath,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    try {
      const licenses = JSON.parse(stdout);

      for (const [packageId, info] of Object.entries(licenses)) {
        const packageInfo = info as any;
        const license = packageInfo.licenses || 'UNKNOWN';
        const licenseInfo = getLicenseInfo(license);

        // Only flag problematic licenses
        if (licenseInfo.risk !== 'none' || licenseInfo.isUnknown) {
          const [packageName, version] = packageId.split('@').filter(Boolean);
          const severity = determineSeverity(licenseInfo);

          const exposure: LicenseExposure = {
            id: uuidv4(),
            type: 'license',
            title: licenseInfo.isUnknown
              ? `Unknown License: ${packageName}`
              : `${licenseInfo.isCopyleft ? 'Copyleft' : 'License Issue'}: ${packageName}`,
            description: generateDescription(license, packageName, licenseInfo),
            severity,
            riskScore: { concert: 0, comprehensive: 0 },
            location: `package.json (${packageName})`,
            detectedAt: new Date().toISOString(),
            source: 'license-checker',
            licenseType: license,
            licenseName: normalizeLicenseName(license),
            packageName: packageName || packageId,
            packageVersion: version || 'unknown',
            isCopyleft: licenseInfo.isCopyleft,
            isUnknown: licenseInfo.isUnknown,
            requiresAttribution: licenseInfo.requiresAttribution,
            commercialUseAllowed: licenseInfo.commercialUseAllowed,
            repository: packageInfo.repository
          };

          exposures.push(exposure);
        }
      }
    } catch (parseError) {
      console.error('Error parsing license-checker output:', parseError);
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning npm licenses';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Scan Python packages for license issues
export async function scanPythonLicenses(repoPath: string): Promise<LicenseScanResult> {
  const exposures: LicenseExposure[] = [];

  // Check for Python dependency files
  const requirementsPath = path.join(repoPath, 'requirements.txt');
  const pipfilePath = path.join(repoPath, 'Pipfile');
  const pyprojectPath = path.join(repoPath, 'pyproject.toml');

  if (!fs.existsSync(requirementsPath) && !fs.existsSync(pipfilePath) && !fs.existsSync(pyprojectPath)) {
    return { exposures: [], success: true };
  }

  try {
    // Check if pip-licenses is available
    try {
      await execAsync('pip-licenses --version', { timeout: 10000 });
    } catch {
      return {
        exposures: [],
        success: true,
        error: 'pip-licenses not installed. Run: pip install pip-licenses'
      };
    }

    // Run pip-licenses
    const { stdout } = await execAsync(
      'pip-licenses --format=json 2>/dev/null || true',
      {
        cwd: repoPath,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    try {
      const licenses = JSON.parse(stdout);

      for (const pkg of licenses) {
        const license = pkg.License || 'UNKNOWN';
        const licenseInfo = getLicenseInfo(license);

        // Only flag problematic licenses
        if (licenseInfo.risk !== 'none' || licenseInfo.isUnknown) {
          const severity = determineSeverity(licenseInfo);

          const exposure: LicenseExposure = {
            id: uuidv4(),
            type: 'license',
            title: licenseInfo.isUnknown
              ? `Unknown License: ${pkg.Name}`
              : `${licenseInfo.isCopyleft ? 'Copyleft' : 'License Issue'}: ${pkg.Name}`,
            description: generateDescription(license, pkg.Name, licenseInfo),
            severity,
            riskScore: { concert: 0, comprehensive: 0 },
            location: `requirements.txt (${pkg.Name})`,
            detectedAt: new Date().toISOString(),
            source: 'pip-licenses',
            licenseType: license,
            licenseName: normalizeLicenseName(license),
            packageName: pkg.Name,
            packageVersion: pkg.Version || 'unknown',
            isCopyleft: licenseInfo.isCopyleft,
            isUnknown: licenseInfo.isUnknown,
            requiresAttribution: licenseInfo.requiresAttribution,
            commercialUseAllowed: licenseInfo.commercialUseAllowed,
            repository: pkg.URL
          };

          exposures.push(exposure);
        }
      }
    } catch (parseError) {
      console.error('Error parsing pip-licenses output:', parseError);
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning Python licenses';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Main license scanning function
export async function runLicenseScanning(repoPath: string, languages: string[]): Promise<LicenseScanResult> {
  const allExposures: LicenseExposure[] = [];
  const errors: string[] = [];

  // Scan npm licenses if JavaScript/TypeScript detected
  if (languages.includes('javascript') || languages.includes('typescript') || fs.existsSync(path.join(repoPath, 'package.json'))) {
    const npmResult = await scanNpmLicenses(repoPath);
    if (npmResult.success) {
      allExposures.push(...npmResult.exposures);
    }
    if (npmResult.error) {
      errors.push(npmResult.error);
    }
  }

  // Scan Python licenses if Python detected
  if (languages.includes('python') || fs.existsSync(path.join(repoPath, 'requirements.txt'))) {
    const pythonResult = await scanPythonLicenses(repoPath);
    if (pythonResult.success) {
      allExposures.push(...pythonResult.exposures);
    }
    if (pythonResult.error) {
      errors.push(pythonResult.error);
    }
  }

  return {
    exposures: allExposures,
    success: true,
    error: errors.length > 0 ? errors.join('; ') : undefined
  };
}
