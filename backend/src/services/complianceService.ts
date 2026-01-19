import {
  Exposure,
  CVEExposure,
  CertificateExposure,
  SecretExposure,
  MisconfigurationExposure,
  LicenseExposure,
  CodeSecurityExposure,
  ApplicationContext,
  ExtendedComplianceStatus,
  ExtendedFinancialAnalysis
} from '../types';

// ============================================================
// COMPLIANCE MAPPING SERVICE
// ============================================================

interface ComplianceMapping {
  standard: string;
  requirement: string;
  description: string;
}

// Map exposure to compliance requirements
export function mapExposureToCompliance(
  exposure: Exposure,
  context?: ApplicationContext
): string[] {
  const impacts: string[] = [];

  const hasPCI = context?.dataSensitivity.pci || false;
  const hasPHI = context?.dataSensitivity.phi || false;
  const hasPII = context?.dataSensitivity.pii || false;
  const isHighCriticality = (context?.criticality || 3) >= 4;

  switch (exposure.type) {
    case 'cve':
      // CVEs affect multiple compliance frameworks
      if (hasPCI) {
        impacts.push('PCI-DSS 6.2 - Vulnerability Management');
        if (exposure.severity === 'critical' || exposure.severity === 'high') {
          impacts.push('PCI-DSS 6.5 - Secure Coding');
        }
      }
      if (hasPHI) {
        impacts.push('HIPAA 164.308(a)(1) - Security Management Process');
      }
      if (isHighCriticality) {
        impacts.push('SOX Section 404 - IT General Controls');
      }
      if (hasPII) {
        impacts.push('GDPR Article 32 - Security of Processing');
      }
      // CISA KEV adds extra compliance urgency
      if ((exposure as CVEExposure).cisaKEV) {
        impacts.push('CISA BOD 22-01 - Known Exploited Vulnerabilities');
      }
      break;

    case 'certificate':
      if (hasPCI) {
        impacts.push('PCI-DSS 4.1 - Secure Transmissions');
      }
      if (hasPHI) {
        impacts.push('HIPAA 164.312(e)(1) - Transmission Security');
      }
      if (hasPII) {
        impacts.push('GDPR Article 32 - Encryption of Personal Data');
      }
      // Weak algorithms are especially problematic
      if ((exposure as CertificateExposure).hasWeakAlgorithm) {
        impacts.push('NIST SP 800-52 - TLS Guidelines');
      }
      break;

    case 'secret':
      // Secrets are serious compliance violations
      if (hasPCI) {
        impacts.push('PCI-DSS 3.4 - Render PAN Unreadable');
        impacts.push('PCI-DSS 8.2 - Strong Cryptography for Authentication');
      }
      if (hasPHI) {
        impacts.push('HIPAA 164.312(a)(2)(iv) - Encryption and Decryption');
        impacts.push('HIPAA 164.312(d) - Person or Entity Authentication');
      }
      if (isHighCriticality) {
        impacts.push('SOX Section 404 - Access Management Controls');
      }
      if (hasPII) {
        impacts.push('GDPR Article 32 - Security of Processing');
        impacts.push('GDPR Article 25 - Data Protection by Design');
      }
      break;

    case 'misconfiguration':
      if (hasPCI) {
        impacts.push('PCI-DSS 2.2 - Configuration Standards');
      }
      if (hasPHI) {
        impacts.push('HIPAA 164.312(a)(1) - Access Controls');
      }
      if ((exposure as MisconfigurationExposure).isPubliclyAccessible) {
        if (hasPII) {
          impacts.push('GDPR Article 32 - Security of Processing');
        }
        impacts.push('CIS Controls - Secure Configuration');
      }
      if (isHighCriticality) {
        impacts.push('SOX Section 404 - IT General Controls');
      }
      break;

    case 'license':
      // License issues are legal/compliance
      impacts.push('Legal - Intellectual Property Compliance');
      if ((exposure as LicenseExposure).isCopyleft) {
        impacts.push('Legal - Copyleft License Compliance');
      }
      if ((exposure as LicenseExposure).isUnknown) {
        impacts.push('Legal - License Risk Assessment Required');
      }
      break;

    case 'code-security':
      if (hasPCI) {
        impacts.push('PCI-DSS 6.5 - Secure Development');
      }
      // Map specific vulnerability types to OWASP
      const codeExposure = exposure as CodeSecurityExposure;
      if (codeExposure.issueType === 'sql_injection') {
        impacts.push('OWASP A03:2021 - Injection');
      } else if (codeExposure.issueType === 'xss') {
        impacts.push('OWASP A03:2021 - Injection');
      } else if (codeExposure.issueType === 'broken_auth') {
        impacts.push('OWASP A07:2021 - Identification and Authentication Failures');
      } else if (codeExposure.issueType === 'weak_cryptography' || codeExposure.issueType === 'insecure_randomness') {
        impacts.push('OWASP A02:2021 - Cryptographic Failures');
      } else if (codeExposure.issueType === 'hardcoded_secret') {
        impacts.push('OWASP A07:2021 - Identification and Authentication Failures');
      } else if (codeExposure.issueType === 'security_misconfiguration') {
        impacts.push('OWASP A05:2021 - Security Misconfiguration');
      }
      if (hasPII) {
        impacts.push('GDPR Article 32 - Security of Processing');
      }
      break;
  }

  return [...new Set(impacts)]; // Remove duplicates
}

// Generate compliance status from all exposures
export function generateComplianceStatus(
  exposures: Exposure[],
  context?: ApplicationContext
): ExtendedComplianceStatus {
  const status: ExtendedComplianceStatus = {
    pciDss: { count: 0, exposures: [] },
    hipaa: { count: 0, exposures: [] },
    sox: { count: 0, exposures: [] },
    gdpr: { count: 0, exposures: [] },
    legal: { count: 0, exposures: [] }
  };

  for (const exposure of exposures) {
    const impacts = mapExposureToCompliance(exposure, context);

    for (const impact of impacts) {
      if (impact.includes('PCI-DSS') || impact.includes('PCI')) {
        status.pciDss.count++;
        status.pciDss.exposures.push(exposure.id);
      }
      if (impact.includes('HIPAA')) {
        status.hipaa.count++;
        status.hipaa.exposures.push(exposure.id);
      }
      if (impact.includes('SOX')) {
        status.sox.count++;
        status.sox.exposures.push(exposure.id);
      }
      if (impact.includes('GDPR')) {
        status.gdpr.count++;
        status.gdpr.exposures.push(exposure.id);
      }
      if (impact.includes('Legal')) {
        status.legal.count++;
        status.legal.exposures.push(exposure.id);
      }
    }
  }

  // Deduplicate exposure IDs
  status.pciDss.exposures = [...new Set(status.pciDss.exposures)];
  status.hipaa.exposures = [...new Set(status.hipaa.exposures)];
  status.sox.exposures = [...new Set(status.sox.exposures)];
  status.gdpr.exposures = [...new Set(status.gdpr.exposures)];
  status.legal.exposures = [...new Set(status.legal.exposures)];

  // Recalculate counts based on unique exposures
  status.pciDss.count = status.pciDss.exposures.length;
  status.hipaa.count = status.hipaa.exposures.length;
  status.sox.count = status.sox.exposures.length;
  status.gdpr.count = status.gdpr.exposures.length;
  status.legal.count = status.legal.exposures.length;

  return status;
}

// ============================================================
// FINANCIAL IMPACT CALCULATOR
// ============================================================

// Average data breach cost (2024 IBM Cost of a Data Breach Report)
const AVG_BREACH_COST = 4.88; // Million USD

// Regulatory fine estimates
const REGULATORY_FINES = {
  pci: 0.5,    // $500K average PCI fine
  hipaa: 1.5,  // $1.5M average HIPAA fine
  gdpr: 2.0,   // $2M average GDPR fine
  sox: 1.0     // $1M SOX compliance failure
};

// Hourly rate for remediation
const HOURLY_RATE = 150; // USD per hour

export function calculateFinancialImpact(
  exposures: Exposure[],
  context?: ApplicationContext
): ExtendedFinancialAnalysis {
  // Initialize breakdown
  const breakdown = {
    cve: 0,
    certificate: 0,
    secret: 0,
    misconfiguration: 0,
    license: 0,
    codeSecurity: 0
  };

  // Count by type and severity
  const byType = {
    cve: { critical: 0, high: 0, medium: 0, low: 0 },
    certificate: { critical: 0, high: 0, medium: 0, low: 0 },
    secret: { critical: 0, high: 0, medium: 0, low: 0 },
    misconfiguration: { critical: 0, high: 0, medium: 0, low: 0 },
    license: { critical: 0, high: 0, medium: 0, low: 0 },
    codeSecurity: { critical: 0, high: 0, medium: 0, low: 0 }
  };

  for (const exposure of exposures) {
    const typeKey = exposure.type === 'code-security' ? 'codeSecurity' : exposure.type;
    if (byType[typeKey as keyof typeof byType]) {
      byType[typeKey as keyof typeof byType][exposure.severity]++;
    }
  }

  // CVE breach cost: Based on EPSS and severity
  // Critical CVEs with CISA KEV have ~95% breach probability
  const criticalCVEs = exposures.filter(e =>
    e.type === 'cve' &&
    (e.severity === 'critical' || (e as CVEExposure).cisaKEV)
  ).length;
  const breachCost = criticalCVEs * 0.15 * AVG_BREACH_COST; // 15% probability per critical CVE
  breakdown.cve = breachCost;

  // Secret breach cost: Verified secrets have ~95% breach probability
  const verifiedSecrets = exposures.filter(e =>
    e.type === 'secret' && (e as SecretExposure).verified
  ).length;
  const unverifiedSecrets = exposures.filter(e =>
    e.type === 'secret' && !(e as SecretExposure).verified
  ).length;
  const secretBreachCost = (verifiedSecrets * 0.95 + unverifiedSecrets * 0.30) * AVG_BREACH_COST;
  breakdown.secret = secretBreachCost;

  // Certificate downtime cost
  // Assume $10K/hour downtime for critical apps
  const hourlyDowntime = context?.criticality === 5 ? 100000 :
                         context?.criticality === 4 ? 50000 :
                         context?.criticality === 3 ? 10000 : 5000;
  const expiringCerts = exposures.filter(e =>
    e.type === 'certificate' &&
    (e as CertificateExposure).daysUntilExpiration <= 30
  ).length;
  const expiredCerts = exposures.filter(e =>
    e.type === 'certificate' &&
    (e as CertificateExposure).isExpired
  ).length;
  // Expired = 24 hours downtime, expiring soon = 10% chance of 4 hour outage
  const downtimeCost = (expiredCerts * 24 * hourlyDowntime + expiringCerts * 0.1 * 4 * hourlyDowntime) / 1000000;
  breakdown.certificate = downtimeCost;

  // Misconfiguration cost: Public exposure risk
  const publicMisconfigs = exposures.filter(e =>
    e.type === 'misconfiguration' &&
    (e as MisconfigurationExposure).isPubliclyAccessible
  ).length;
  const configurationRisk = publicMisconfigs * 0.30 * AVG_BREACH_COST;
  breakdown.misconfiguration = configurationRisk;

  // License legal fees
  const copyleftViolations = exposures.filter(e =>
    e.type === 'license' && (e as LicenseExposure).isCopyleft
  ).length;
  const unknownLicenses = exposures.filter(e =>
    e.type === 'license' && (e as LicenseExposure).isUnknown
  ).length;
  const legalFees = (copyleftViolations * 0.5 + unknownLicenses * 0.1); // $500K per copyleft, $100K per unknown
  breakdown.license = legalFees;

  // Code security issues
  const criticalCodeIssues = exposures.filter(e =>
    e.type === 'code-security' &&
    (e.severity === 'critical' || e.severity === 'high')
  ).length;
  breakdown.codeSecurity = criticalCodeIssues * 0.10 * AVG_BREACH_COST;

  // Regulatory fines based on context
  let regulatoryFines = 0;
  if (context?.dataSensitivity.pci && byType.cve.critical + byType.secret.critical > 0) {
    regulatoryFines += REGULATORY_FINES.pci;
  }
  if (context?.dataSensitivity.phi && byType.secret.critical > 0) {
    regulatoryFines += REGULATORY_FINES.hipaa;
  }
  if (context?.dataSensitivity.pii && exposures.filter(e => e.severity === 'critical').length > 5) {
    regulatoryFines += REGULATORY_FINES.gdpr;
  }
  if ((context?.criticality || 0) >= 4) {
    regulatoryFines += REGULATORY_FINES.sox * 0.5; // Partial SOX exposure
  }

  // Remediation cost calculation
  const effortHours = calculateRemediationEffort(exposures);
  const remediationCost = (effortHours * HOURLY_RATE) / 1000000; // Convert to millions

  // Total risk
  const totalRisk = breachCost + secretBreachCost + downtimeCost + configurationRisk + legalFees + regulatoryFines + breakdown.codeSecurity;

  // ROI
  const roi = remediationCost > 0 ? Math.round(totalRisk / remediationCost) : 0;

  return {
    breachCost: Math.round(breachCost * 100) / 100,
    secretBreachCost: Math.round(secretBreachCost * 100) / 100,
    downtimeCost: Math.round(downtimeCost * 100) / 100,
    configurationRisk: Math.round(configurationRisk * 100) / 100,
    legalFees: Math.round(legalFees * 100) / 100,
    regulatoryFines: Math.round(regulatoryFines * 100) / 100,
    totalRisk: Math.round(totalRisk * 100) / 100,
    remediationCost: Math.round(remediationCost * 1000) / 1000,
    roi,
    breakdown: {
      cve: Math.round(breakdown.cve * 100) / 100,
      certificate: Math.round(breakdown.certificate * 100) / 100,
      secret: Math.round(breakdown.secret * 100) / 100,
      misconfiguration: Math.round(breakdown.misconfiguration * 100) / 100,
      license: Math.round(breakdown.license * 100) / 100,
      codeSecurity: Math.round(breakdown.codeSecurity * 100) / 100
    }
  };
}

// Calculate total remediation effort in hours
function calculateRemediationEffort(exposures: Exposure[]): number {
  let totalHours = 0;

  for (const exposure of exposures) {
    switch (exposure.type) {
      case 'cve':
        totalHours += 2; // Average 2 hours per CVE fix
        break;
      case 'certificate':
        totalHours += 0.5; // 30 minutes per cert renewal
        break;
      case 'secret':
        totalHours += 2; // 2 hours per secret (rotation + code change)
        break;
      case 'misconfiguration':
        totalHours += 1; // 1 hour per config fix
        break;
      case 'license':
        totalHours += 4; // 4 hours per license resolution
        break;
      case 'code-security':
        totalHours += 1.5; // 1.5 hours per code fix
        break;
    }
  }

  return totalHours;
}

// Apply compliance impact to exposures
export function applyComplianceToExposures(
  exposures: Exposure[],
  context?: ApplicationContext
): Exposure[] {
  return exposures.map(exposure => ({
    ...exposure,
    complianceImpact: mapExposureToCompliance(exposure, context)
  }));
}
