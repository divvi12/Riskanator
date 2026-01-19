import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { SecretExposure } from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

export interface SecretScanResult {
  exposures: SecretExposure[];
  success: boolean;
  error?: string;
}

// Map TruffleHog detector names to our secret types
function mapSecretType(detectorName: string): SecretExposure['secretType'] {
  const name = detectorName.toLowerCase();

  if (name.includes('aws')) return 'aws';
  if (name.includes('private') || name.includes('rsa') || name.includes('ssh')) return 'private_key';
  if (name.includes('api') || name.includes('key')) return 'api_key';
  if (name.includes('password') || name.includes('passwd')) return 'password';
  if (name.includes('token') || name.includes('bearer') || name.includes('jwt')) return 'token';

  return 'generic';
}

// Determine severity based on secret type and verification status
function determineSeverity(secretType: SecretExposure['secretType'], verified: boolean): 'critical' | 'high' | 'medium' | 'low' {
  // All verified secrets are critical
  if (verified) return 'critical';

  // Unverified but high-risk types
  if (secretType === 'aws' || secretType === 'private_key') return 'critical';
  if (secretType === 'api_key' || secretType === 'password') return 'high';
  if (secretType === 'token') return 'high';

  return 'medium';
}

// Generate title based on secret type
function generateTitle(detectorName: string, secretType: SecretExposure['secretType']): string {
  const typeNames: Record<SecretExposure['secretType'], string> = {
    'aws': 'AWS Credentials',
    'api_key': 'API Key',
    'password': 'Password',
    'private_key': 'Private Key',
    'token': 'Authentication Token',
    'generic': 'Secret'
  };

  return `Hardcoded ${typeNames[secretType]}: ${detectorName}`;
}

// Generate description based on secret type
function generateDescription(secretType: SecretExposure['secretType'], verified: boolean, location: string): string {
  const verifiedWarning = verified ? 'This credential has been VERIFIED as active and valid. ' : '';

  const descriptions: Record<SecretExposure['secretType'], string> = {
    'aws': `${verifiedWarning}AWS credentials exposed in code at ${location}. An attacker could access your AWS account, steal data, or incur charges.`,
    'api_key': `${verifiedWarning}API key found in source code at ${location}. This could allow unauthorized access to external services.`,
    'password': `${verifiedWarning}Password found in source code at ${location}. This credential should be moved to a secrets manager.`,
    'private_key': `${verifiedWarning}Private key exposed at ${location}. This compromises any system or service using this key for authentication.`,
    'token': `${verifiedWarning}Authentication token found at ${location}. This could allow impersonation or unauthorized access.`,
    'generic': `${verifiedWarning}Potential secret or credential found at ${location}. Review and rotate if necessary.`
  };

  return descriptions[secretType];
}

// Scan using TruffleHog
export async function scanSecrets(repoPath: string): Promise<SecretScanResult> {
  const exposures: SecretExposure[] = [];

  try {
    // Check if TruffleHog is installed
    try {
      await execAsync('trufflehog --version', { timeout: 10000 });
    } catch {
      // TruffleHog not installed - return empty results with warning
      console.warn('TruffleHog not installed. Run: pip install trufflehog');
      return {
        exposures: [],
        success: true,
        error: 'TruffleHog not installed. Run: pip install trufflehog'
      };
    }

    // Run TruffleHog on the filesystem
    // Using --no-verification to avoid hitting external services
    // In production, you might want to enable verification: --only-verified
    const { stdout } = await execAsync(
      `trufflehog filesystem "${repoPath}" --json 2>/dev/null || true`,
      {
        cwd: repoPath,
        timeout: 300000, // 5 minutes
        maxBuffer: 50 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    // TruffleHog outputs one JSON object per line
    const lines = stdout.trim().split('\n');

    for (const line of lines) {
      try {
        if (!line.trim()) continue;

        const finding = JSON.parse(line);

        // Extract relevant data from TruffleHog output
        const detectorName = finding.DetectorName || finding.detector_name || 'Unknown';
        const secretType = mapSecretType(detectorName);
        const verified = finding.Verified || finding.verified || false;
        const severity = determineSeverity(secretType, verified);

        // Get file location
        const sourceMetadata = finding.SourceMetadata || finding.source_metadata || {};
        const dataPath = sourceMetadata.Data || sourceMetadata.data || {};
        const filesystem = dataPath.Filesystem || dataPath.filesystem || {};

        const filePath = filesystem.file || finding.file || 'unknown';
        const lineNumber = filesystem.line || finding.line || 0;
        const relativePath = filePath.replace(repoPath + '/', '').replace(repoPath, '');
        const location = lineNumber ? `${relativePath}:${lineNumber}` : relativePath;

        // Get entropy if available
        const entropy = finding.Raw ? calculateEntropy(finding.Raw) : undefined;

        const exposure: SecretExposure = {
          id: uuidv4(),
          type: 'secret',
          title: generateTitle(detectorName, secretType),
          description: generateDescription(secretType, verified, location),
          severity,
          riskScore: { concert: 0, comprehensive: 0 }, // Will be calculated by risk service
          location,
          detectedAt: new Date().toISOString(),
          source: 'trufflehog',
          secretType,
          detectorName,
          verified,
          entropy,
          inGitHistory: false, // TruffleHog filesystem scan only checks current files
          lineNumber: lineNumber || undefined
        };

        // Avoid duplicates by checking if we already have this exact location
        if (!exposures.find(e => e.location === exposure.location && e.secretType === exposure.secretType)) {
          exposures.push(exposure);
        }
      } catch (parseError) {
        // Skip malformed lines
        continue;
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning secrets';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Also scan git history for secrets (separate function for deeper scanning)
export async function scanSecretsInGitHistory(repoPath: string): Promise<SecretScanResult> {
  const exposures: SecretExposure[] = [];

  try {
    // Check if it's a git repository
    if (!fs.existsSync(path.join(repoPath, '.git'))) {
      return { exposures: [], success: true };
    }

    // Check if TruffleHog is installed
    try {
      await execAsync('trufflehog --version', { timeout: 10000 });
    } catch {
      return {
        exposures: [],
        success: true,
        error: 'TruffleHog not installed'
      };
    }

    // Run TruffleHog on git history
    const { stdout } = await execAsync(
      `trufflehog git "file://${repoPath}" --json --no-update 2>/dev/null || true`,
      {
        cwd: repoPath,
        timeout: 600000, // 10 minutes for git history
        maxBuffer: 100 * 1024 * 1024
      }
    );

    if (!stdout || stdout.trim() === '') {
      return { exposures: [], success: true };
    }

    const lines = stdout.trim().split('\n');

    for (const line of lines) {
      try {
        if (!line.trim()) continue;

        const finding = JSON.parse(line);

        const detectorName = finding.DetectorName || finding.detector_name || 'Unknown';
        const secretType = mapSecretType(detectorName);
        const verified = finding.Verified || finding.verified || false;
        const severity = determineSeverity(secretType, verified);

        const sourceMetadata = finding.SourceMetadata || finding.source_metadata || {};
        const dataPath = sourceMetadata.Data || sourceMetadata.data || {};
        const git = dataPath.Git || dataPath.git || {};

        const filePath = git.file || finding.file || 'unknown';
        const lineNumber = git.line || finding.line || 0;
        const commit = git.commit || finding.commit || 'unknown';
        const relativePath = filePath.replace(repoPath + '/', '').replace(repoPath, '');
        const location = lineNumber ? `${relativePath}:${lineNumber}` : relativePath;

        const exposure: SecretExposure = {
          id: uuidv4(),
          type: 'secret',
          title: generateTitle(detectorName, secretType) + ' (in git history)',
          description: generateDescription(secretType, verified, location) + ` Found in commit ${commit.substring(0, 7)}.`,
          severity,
          riskScore: { concert: 0, comprehensive: 0 },
          location: `${location} (commit: ${commit.substring(0, 7)})`,
          detectedAt: new Date().toISOString(),
          source: 'trufflehog-git',
          secretType,
          detectorName,
          verified,
          inGitHistory: true,
          lineNumber: lineNumber || undefined
        };

        if (!exposures.find(e => e.location === exposure.location && e.secretType === exposure.secretType)) {
          exposures.push(exposure);
        }
      } catch (parseError) {
        continue;
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning git history';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Calculate Shannon entropy of a string (for detecting high-entropy secrets)
function calculateEntropy(str: string): number {
  const len = str.length;
  const frequencies: Map<string, number> = new Map();

  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const freq = count / len;
    entropy -= freq * Math.log2(freq);
  }

  return Math.round(entropy * 100) / 100;
}

// Simple pattern-based secret scanner (fallback if TruffleHog not available)
export async function scanSecretsWithPatterns(repoPath: string): Promise<SecretScanResult> {
  const exposures: SecretExposure[] = [];

  const patterns = [
    { regex: /AKIA[0-9A-Z]{16}/g, type: 'aws' as const, name: 'AWS Access Key' },
    { regex: /-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----/g, type: 'private_key' as const, name: 'Private Key' },
    { regex: /sk_live_[0-9a-zA-Z]{24,}/g, type: 'api_key' as const, name: 'Stripe Secret Key' },
    { regex: /ghp_[0-9a-zA-Z]{36}/g, type: 'token' as const, name: 'GitHub Token' },
    { regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, type: 'token' as const, name: 'Slack Token' },
    { regex: /AIza[0-9A-Za-z-_]{35}/g, type: 'api_key' as const, name: 'Google API Key' },
  ];

  const extensions = ['.js', '.ts', '.py', '.env', '.json', '.yaml', '.yml', '.xml', '.conf', '.config'];

  try {
    const findFiles = async (dir: string): Promise<string[]> => {
      const files: string[] = [];
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!['node_modules', '.git', 'vendor', '__pycache__'].includes(entry.name)) {
            files.push(...await findFiles(fullPath));
          }
        } else if (entry.isFile()) {
          if (extensions.some(ext => entry.name.endsWith(ext))) {
            files.push(fullPath);
          }
        }
      }

      return files;
    };

    const files = await findFiles(repoPath);

    for (const filePath of files) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        for (const pattern of patterns) {
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const matches = line.match(pattern.regex);

            if (matches) {
              const relativePath = filePath.replace(repoPath + '/', '');
              const location = `${relativePath}:${i + 1}`;

              const exposure: SecretExposure = {
                id: uuidv4(),
                type: 'secret',
                title: `Hardcoded ${pattern.name}`,
                description: generateDescription(pattern.type, false, location),
                severity: determineSeverity(pattern.type, false),
                riskScore: { concert: 0, comprehensive: 0 },
                location,
                detectedAt: new Date().toISOString(),
                source: 'pattern-scanner',
                secretType: pattern.type,
                detectorName: pattern.name,
                verified: false,
                inGitHistory: false,
                lineNumber: i + 1
              };

              if (!exposures.find(e => e.location === exposure.location)) {
                exposures.push(exposure);
              }
            }
          }
        }
      } catch (fileError) {
        continue;
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error in pattern scanning';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Main export - runs all secret scanners
export async function runSecretScanning(repoPath: string): Promise<SecretScanResult> {
  const allExposures: SecretExposure[] = [];

  // Try TruffleHog first
  const truffleResult = await scanSecrets(repoPath);

  if (truffleResult.success && truffleResult.exposures.length > 0) {
    allExposures.push(...truffleResult.exposures);
  }

  // If TruffleHog didn't find anything or isn't available, use pattern scanner
  if (truffleResult.exposures.length === 0 || truffleResult.error) {
    const patternResult = await scanSecretsWithPatterns(repoPath);
    if (patternResult.success) {
      allExposures.push(...patternResult.exposures);
    }
  }

  // Deduplicate by location
  const uniqueExposures = allExposures.filter((exposure, index, self) =>
    index === self.findIndex(e => e.location === exposure.location)
  );

  return {
    exposures: uniqueExposures,
    success: true
  };
}
