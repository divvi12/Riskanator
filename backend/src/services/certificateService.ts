import * as fs from 'fs';
import * as path from 'path';
import forge from 'node-forge';
import { glob } from 'glob';
import { CertificateExposure, RiskScore } from '../types';
import { v4 as uuidv4 } from 'uuid';

export interface CertificateScanResult {
  exposures: CertificateExposure[];
  success: boolean;
  error?: string;
}

// Weak algorithms that should be flagged
const WEAK_ALGORITHMS = ['md5', 'sha1', 'md2', 'md4'];

// Find all certificate files in the repository
async function findCertificateFiles(repoPath: string): Promise<string[]> {
  const patterns = [
    '**/*.crt',
    '**/*.pem',
    '**/*.cer',
    '**/*.p12',
    '**/*.pfx',
    '**/*.key',
    '**/cert*',
    '**/ssl/*',
    '**/tls/*',
    '**/certs/*'
  ];

  const files: string[] = [];

  for (const pattern of patterns) {
    try {
      const matches = await glob(pattern, {
        cwd: repoPath,
        absolute: true,
        nodir: true,
        ignore: ['**/node_modules/**', '**/.git/**']
      });
      files.push(...matches);
    } catch (error) {
      // Continue with other patterns if one fails
    }
  }

  // Deduplicate
  return [...new Set(files)];
}

// Parse a PEM certificate file
function parsePemCertificate(content: string): forge.pki.Certificate | null {
  try {
    const cert = forge.pki.certificateFromPem(content);
    return cert;
  } catch (error) {
    return null;
  }
}

// Calculate days until expiration
function calculateDaysUntilExpiration(validTo: Date): number {
  const now = new Date();
  const diffTime = validTo.getTime() - now.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

// Determine severity based on days until expiration
function determineSeverity(daysUntilExpiration: number, isExpired: boolean, hasWeakAlgorithm: boolean): 'critical' | 'high' | 'medium' | 'low' {
  if (isExpired) return 'critical';
  if (hasWeakAlgorithm) return 'high';
  if (daysUntilExpiration <= 7) return 'critical';
  if (daysUntilExpiration <= 30) return 'high';
  if (daysUntilExpiration <= 90) return 'medium';
  return 'low';
}

// Check if certificate uses a weak algorithm
function hasWeakSignatureAlgorithm(cert: forge.pki.Certificate): boolean {
  const signatureOid = cert.signatureOid;
  const sigAlg = forge.pki.oids[signatureOid] || signatureOid;

  return WEAK_ALGORITHMS.some(weak =>
    sigAlg.toLowerCase().includes(weak)
  );
}

// Check if certificate is self-signed
function isSelfSigned(cert: forge.pki.Certificate): boolean {
  try {
    return cert.issuer.hash === cert.subject.hash;
  } catch {
    return false;
  }
}

// Get the common name from the certificate
function getCommonName(attributes: forge.pki.CertificateField[]): string {
  const cnAttr = attributes.find(attr => attr.shortName === 'CN' || attr.name === 'commonName');
  return cnAttr?.value as string || 'Unknown';
}

// Determine certificate type
function getCertificateType(cert: forge.pki.Certificate): 'ssl' | 'code-signing' | 'client' | 'other' {
  try {
    const extensions = cert.extensions || [];

    // Check extended key usage
    const ekuExt = extensions.find((ext: any) => ext.name === 'extKeyUsage');
    if (ekuExt) {
      if (ekuExt.serverAuth) return 'ssl';
      if (ekuExt.codeSigning) return 'code-signing';
      if (ekuExt.clientAuth) return 'client';
    }

    // Check key usage
    const kuExt = extensions.find((ext: any) => ext.name === 'keyUsage');
    if (kuExt) {
      if (kuExt.digitalSignature && kuExt.keyEncipherment) return 'ssl';
    }

    return 'other';
  } catch {
    return 'other';
  }
}

// Main scanning function
export async function scanCertificates(repoPath: string): Promise<CertificateScanResult> {
  const exposures: CertificateExposure[] = [];

  try {
    const certFiles = await findCertificateFiles(repoPath);

    for (const filePath of certFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');

        // Try to parse as PEM certificate
        const cert = parsePemCertificate(content);

        if (cert) {
          const validTo = cert.validity.notAfter;
          const validFrom = cert.validity.notBefore;
          const daysUntilExpiration = calculateDaysUntilExpiration(validTo);
          const isExpired = daysUntilExpiration <= 0;
          const weakAlgorithm = hasWeakSignatureAlgorithm(cert);
          const selfSigned = isSelfSigned(cert);

          // Only flag certificates expiring within 180 days or with issues
          if (daysUntilExpiration <= 180 || weakAlgorithm || selfSigned) {
            const domain = getCommonName(cert.subject.attributes);
            const issuer = getCommonName(cert.issuer.attributes);
            const signatureOid = cert.signatureOid;
            const algorithm = forge.pki.oids[signatureOid] || signatureOid;
            const severity = determineSeverity(daysUntilExpiration, isExpired, weakAlgorithm);

            let title = '';
            let description = '';

            if (isExpired) {
              title = `Expired Certificate: ${domain}`;
              description = `Certificate for ${domain} expired ${Math.abs(daysUntilExpiration)} days ago. This will cause service outages and browser warnings.`;
            } else if (weakAlgorithm) {
              title = `Weak Algorithm Certificate: ${domain}`;
              description = `Certificate for ${domain} uses weak signature algorithm (${algorithm}). This is vulnerable to cryptographic attacks.`;
            } else if (selfSigned) {
              title = `Self-Signed Certificate: ${domain}`;
              description = `Certificate for ${domain} is self-signed. This may cause trust issues in production environments.`;
            } else {
              title = `Expiring Certificate: ${domain}`;
              description = `Certificate for ${domain} expires in ${daysUntilExpiration} days. Renew before ${validTo.toISOString().split('T')[0]} to avoid service disruption.`;
            }

            const relativePath = filePath.replace(repoPath + '/', '');

            const exposure: CertificateExposure = {
              id: uuidv4(),
              type: 'certificate',
              title,
              description,
              severity,
              riskScore: { concert: 0, comprehensive: 0 }, // Will be calculated by risk service
              location: relativePath,
              detectedAt: new Date().toISOString(),
              source: 'certificate-scanner',
              domain,
              issuer,
              validFrom: validFrom.toISOString(),
              validTo: validTo.toISOString(),
              daysUntilExpiration,
              algorithm,
              isExpired,
              isSelfSigned: selfSigned,
              hasWeakAlgorithm: weakAlgorithm,
              certType: getCertificateType(cert)
            };

            exposures.push(exposure);
          }
        }
      } catch (fileError) {
        // Skip files that can't be parsed as certificates
        continue;
      }
    }

    return { exposures, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error scanning certificates';
    return { exposures: [], success: false, error: errorMessage };
  }
}

// Export for testing
export { findCertificateFiles, parsePemCertificate, calculateDaysUntilExpiration };
