import { Modal, CodeSnippet, Tag } from '@carbon/react';

export type ScoreType =
  | 'exposure-score'
  | 'concert-score'
  | 'detailed-score'
  | 'total-exposures'
  | 'critical-high'
  | 'cisa-kev'
  | 'sla-compliance'
  | 'cve-score'
  | 'secret-score'
  | 'certificate-score'
  | 'misconfiguration-score'
  | 'license-score'
  | 'code-security-score'
  | 'aggregate-score';

interface ScoreInfoModalProps {
  open: boolean;
  onClose: () => void;
  scoreType: ScoreType;
}

const scoreInfo: Record<ScoreType, {
  title: string;
  description: string;
  formula?: string;
  factors?: { name: string; description: string; values?: string }[];
  scale?: string;
  examples?: { scenario: string; calculation: string; result: string }[];
  sources?: string[];
}> = {
  'exposure-score': {
    title: 'Unified Exposure Risk Score',
    description: 'The main risk indicator combining all exposure types into a single 0-10 score using weighted maximum aggregation. This score represents your application\'s overall security posture.',
    formula: `Overall = (
  MaxScore × 0.4 +
  AvgTop5Critical × 0.3 +
  AvgTop10High × 0.2 +
  log₁₀(totalExposures) × 2
) ÷ 10`,
    factors: [
      { name: 'Highest Critical', description: 'The worst single exposure score', values: '40% weight' },
      { name: 'Avg Top 5 Critical', description: 'Average of top 5 critical exposures (score ≥90)', values: '30% weight' },
      { name: 'Avg Top 10 High', description: 'Average of top 10 high exposures (score 70-89)', values: '20% weight' },
      { name: 'Volume Penalty', description: 'Logarithmic penalty for total exposure count', values: 'log₁₀(n) × 2' }
    ],
    scale: '0-10 (Low: <4, Medium: 4-6.9, High: 7-8.9, Critical: ≥9)',
    examples: [
      { scenario: '75 exposures (21 Critical, 49 High)', calculation: '100×0.4 + 97×0.3 + 75×0.2 + 3.75', result: '8.8/10' }
    ],
    sources: [
      'Tenable VPR (Vulnerability Priority Rating)',
      'Qualys TruRisk',
      'IBM Concert',
      'Cyentia Institute "Prioritization to Prediction"',
      'Kenna Security Risk Scoring Research',
      'MAGERIT Bayesian Aggregation'
    ]
  },

  'concert-score': {
    title: 'Concert Score (Executive Summary)',
    description: 'A quick-glance risk score optimized for executive reporting. Uses weighted maximum aggregation to ensure the worst findings drive the score while accounting for volume.',
    formula: `Concert = (
  MaxScore × 0.4 +
  AvgTop5Critical × 0.3 +
  AvgTop10High × 0.2 +
  log₁₀(n) × 2
) ÷ 10`,
    factors: [
      { name: 'Highest Score', description: 'The single worst exposure drives 40%', values: '40% weight' },
      { name: 'Top 5 Critical', description: 'Average of top 5 critical exposures (≥90)', values: '30% weight' },
      { name: 'Top 10 High', description: 'Average of top 10 high exposures (70-89)', values: '20% weight' },
      { name: 'Volume Penalty', description: 'More exposures = higher risk (diminishing)', values: 'log₁₀(n) × 2' }
    ],
    scale: '0-10 scale for executive dashboards',
    examples: [
      { scenario: '75 exposures (21 Critical, 49 High)', calculation: '(100×0.4 + 97×0.3 + 75×0.2 + 3.75) ÷ 10', result: '8.8/10' },
      { scenario: '5 medium exposures only', calculation: '(55×0.4 + 0×0.3 + 0×0.2 + 1.4) ÷ 10', result: '2.3/10' }
    ],
    sources: [
      'IBM Concert Methodology',
      'Tenable VPR (Vulnerability Priority Rating)',
      'Qualys TruRisk',
      'FIRST CVSS Special Interest Group'
    ]
  },

  'detailed-score': {
    title: 'Operational Risk Score',
    description: 'A nuanced risk score that builds on the Concert Score by adding factors for real-world exploitability, attack surface diversity, SLA compliance urgency, and severity concentration. This score better reflects operational risk and is designed for security operations teams.',
    formula: `Operational = Concert Score
  + EPSS Factor (exploitation probability)
  + KEV Factor (actively exploited CVEs)
  + Diversity Penalty (exposure type breadth)
  + SLA Factor (overdue items urgency)
  + Critical Concentration (severity distribution)

Capped at 10`,
    factors: [
      { name: 'EPSS Factor', description: 'High exploitation probability (>10%) weighted ×1.5, else ×0.5', values: 'avgEPSS × 0.5-1.5' },
      { name: 'KEV Factor', description: 'Proportion of CVEs actively exploited', values: '(kevCount/cves) × 2' },
      { name: 'Diversity Penalty', description: 'Broader attack surface = more risk', values: '(types-1) × 0.2' },
      { name: 'SLA Factor', description: 'Overdue items increase urgency', values: '(overdue/total) × 1.5' },
      { name: 'Critical Concentration', description: 'High proportion of critical = more risk', values: '(critical/total) × 0.5' }
    ],
    scale: '0-10 (typically 0.5-2.0 points higher than Concert Score)',
    examples: [
      { scenario: 'High EPSS (30%), 2 KEVs in 10 CVEs, 3 types, 10% overdue, 20% critical', calculation: 'Concert + 0.45 + 0.4 + 0.4 + 0.15 + 0.1', result: '+1.5 over Concert' },
      { scenario: 'Low EPSS (1%), no KEVs, 1 type, on track, no criticals', calculation: 'Concert + 0.01 + 0 + 0 + 0 + 0', result: '~Same as Concert' }
    ],
    sources: [
      'FIRST EPSS (Exploit Prediction Scoring System)',
      'CISA Known Exploited Vulnerabilities',
      'NIST SP 800-30 Risk Management Guide',
      'OWASP Risk Rating Methodology',
      'ISO 27005 Information Security Risk Management',
      'CISA Stakeholder-Specific Vulnerability Categorization (SSVC)'
    ]
  },

  'total-exposures': {
    title: 'Total Exposures',
    description: 'The count of all security findings across 6 categories detected during the scan.',
    factors: [
      { name: 'CVEs', description: 'Known vulnerabilities from npm audit, pip-audit, Trivy, Semgrep' },
      { name: 'Secrets', description: 'Hardcoded credentials detected by TruffleHog' },
      { name: 'Certificates', description: 'Expiring, weak, or self-signed certificates' },
      { name: 'Misconfigurations', description: 'IaC issues from Checkov (Terraform, K8s, CloudFormation)' },
      { name: 'Licenses', description: 'Copyleft or unknown license compliance issues' },
      { name: 'Code Security', description: 'SAST findings (SQL injection, XSS, etc.)' }
    ],
    sources: [
      'Trivy (Aqua Security)',
      'TruffleHog (Truffle Security)',
      'Checkov (Prisma Cloud)',
      'Semgrep (R2C)',
      'npm audit / pip-audit',
      'Synopsys Black Duck'
    ]
  },

  'critical-high': {
    title: 'Critical + High Severity',
    description: 'Exposures requiring immediate attention based on the new 0-100 scoring scale.',
    factors: [
      { name: 'Critical (≥90)', description: 'CISA KEV CVEs, verified active secrets, expired certs, public S3 with PII' },
      { name: 'High (70-89)', description: 'High CVSS + EPSS CVEs, unverified secrets, certs expiring <30d, AGPL licenses' }
    ],
    scale: 'Critical: Score ≥90, High: Score 70-89',
    sources: [
      'CVSS v3.1 Severity Ratings (FIRST)',
      'Tenable VPR Severity Thresholds',
      'Qualys TruRisk Criticality Bands',
      'PCI DSS Vulnerability Severity Levels'
    ]
  },

  'cisa-kev': {
    title: 'CISA Known Exploited Vulnerabilities',
    description: 'CVEs listed in CISA\'s Known Exploited Vulnerabilities catalog. These are confirmed to be actively exploited in the wild and require immediate remediation.',
    factors: [
      { name: 'Automatic Critical', description: 'Any KEV CVE automatically scores 100/100' },
      { name: 'Immediate SLA', description: 'KEV entries have 24-48 hour remediation SLAs' },
      { name: 'Federal Mandate', description: 'US federal agencies must remediate within specified timeframes' }
    ],
    sources: [
      'CISA Known Exploited Vulnerabilities Catalog',
      'BOD 22-01 Reducing Exploitation Risk',
      'FIRST EPSS Exploit Prediction',
      'Mandiant Threat Intelligence',
      'Verizon DBIR Exploitation Metrics'
    ]
  },

  'sla-compliance': {
    title: 'SLA Compliance Rate',
    description: 'Percentage of exposures being remediated within their Service Level Agreement deadlines.',
    formula: 'Compliance = (Total - Overdue) ÷ Total × 100',
    factors: [
      { name: 'Critical SLA', description: 'Score ≥90: 24h (Tier 5) to 14d (Tier 1-2)' },
      { name: 'High SLA', description: 'Score 70-89: 7d (Tier 5) to 30d (Tier 1-2)' },
      { name: 'Medium SLA', description: 'Score 40-69: 30d (Tier 5) to 90d (Tier 1-2)' },
      { name: 'Low SLA', description: 'Score <40: 60-90 days' },
      { name: 'Secrets', description: 'Always immediate (0 hours)' },
      { name: 'Certificates', description: 'Based on days until expiration' }
    ],
    scale: '100% = All exposures on track, <80% = Action needed',
    sources: [
      'PCI DSS Vulnerability Management Requirements',
      'NIST Cybersecurity Framework',
      'CIS Controls v8 (Control 7)',
      'SOC 2 Remediation Timeframes',
      'FedRAMP Vulnerability Scanning Requirements'
    ]
  },

  'cve-score': {
    title: 'Concert CVE Risk Score (Formula 1)',
    description: 'IBM Concert methodology for CVE scoring using equilibrium-based EPSS where 0.1 (10%) is the neutral point. Values above 0.1 increase risk, below 0.1 decrease it. Score is capped at 10.',
    formula: `Concert CVE Score = Severity × Exploitability Factor × Environmental Factor

Where:
• Severity: CVSS score (0-10), with fallback for missing CVSS
• Exploitability: EPSS-based factor (0.5-1.25), equilibrium at EPSS=0.1
• Environmental: Context-based factor (0.25-1.25)`,
    factors: [
      { name: 'CVSS (Severity)', description: 'Base technical severity from NVD', values: '0.1-10.0' },
      { name: 'EPSS 0.0001-0.001', description: 'Very low exploitation probability', values: '× 0.5 (-50%)' },
      { name: 'EPSS 0.001-0.02', description: 'Low exploitation probability', values: '× 0.6 (-40%)' },
      { name: 'EPSS 0.1-0.2', description: 'Equilibrium (neutral effect)', values: '× 1.0 (neutral)' },
      { name: 'EPSS 0.4-0.6', description: 'High exploitation probability', values: '× 1.2 (+20%)' },
      { name: 'EPSS 0.9-1.0', description: 'Very high exploitation probability', values: '× 1.25 (+25%)' },
      { name: 'App Criticality', description: 'Tier 1-5 business importance', values: '0.20-1.25' },
      { name: 'Data Sensitivity', description: 'Level 1-5 data classification', values: '0.20-1.25' },
      { name: 'Access Points', description: 'Public (1-16+) or Private (1-4)', values: '0.25-1.25' }
    ],
    scale: '0.1-10.0 (Low: <4, Medium: 4-6.9, High: 7-8.9, Critical: ≥9)',
    examples: [
      { scenario: 'Critical CVE (CVSS 9.1, EPSS 0.45, Level 5 app)', calculation: '9.1 × 1.2 × 1.21', result: '10.0 (capped)' },
      { scenario: 'Medium CVE (CVSS 6, EPSS 0.15, Level 3 app)', calculation: '6.0 × 1.0 × 0.85', result: '5.1' },
      { scenario: 'Low CVE (CVSS 4, EPSS 0.005, Level 2 app)', calculation: '4.0 × 0.6 × 0.45', result: '1.08' }
    ],
    sources: [
      'IBM Concert Risk Methodology',
      'NIST NVD (National Vulnerability Database)',
      'FIRST CVSS v3.1 Specification',
      'FIRST EPSS (Exploit Prediction Scoring System)',
      'CISA Known Exploited Vulnerabilities',
      'Cyentia Institute EPSS Research',
      'Tenable VPR Formula Research'
    ]
  },

  'secret-score': {
    title: 'Secret Risk Score',
    description: 'Scoring for hardcoded credentials based on type, verification status, and context.',
    formula: 'Secret_Score = BaseType × Validity × Context × GitHistory',
    factors: [
      { name: 'AWS/Azure/GCP', description: 'Cloud credentials', values: '95 base' },
      { name: 'Private Keys', description: 'Cryptographic keys', values: '95 base' },
      { name: 'DB Passwords', description: 'Database credentials', values: '90 base' },
      { name: 'API Keys', description: 'Third-party API keys', values: '85 base' },
      { name: 'OAuth Tokens', description: 'Authentication tokens', values: '80 base' },
      { name: 'Generic', description: 'Other credentials', values: '70 base' },
      { name: 'Verified Active', description: 'Confirmed working', values: '× 1.0' },
      { name: 'Unverified', description: 'Status unknown', values: '× 0.7' },
      { name: 'Production Context', description: 'In prod files', values: '× 1.2' },
      { name: 'Git History', description: 'Exposed in commits', values: '× 1.3' }
    ],
    scale: '0-100 (capped)',
    examples: [
      { scenario: 'AWS key, verified, prod, in git', calculation: '95 × 1.0 × 1.2 × 1.3', result: '100 (capped)' },
      { scenario: 'Test API key, unverified', calculation: '85 × 0.7 × 0.5', result: '29.75' }
    ],
    sources: [
      'GitGuardian State of Secrets Sprawl Report',
      'TruffleHog Detection Methodology',
      'GitHub Secret Scanning',
      'AWS Security Best Practices',
      'OWASP Secrets Management Cheat Sheet',
      'Verizon DBIR Credential Theft Statistics',
      'IBM Cost of Data Breach Report'
    ]
  },

  'certificate-score': {
    title: 'Certificate Risk Score',
    description: 'Scoring based on days until expiration, algorithm strength, and certificate type.',
    formula: 'Cert_Score = max(0, 100 - days/1.8) × AlgoMod × TypeMod',
    factors: [
      { name: 'Expiration', description: '0 days = 100, 180+ days = 0', values: '100 - (days ÷ 1.8)' },
      { name: 'SHA-1/RSA-1024', description: 'Weak algorithms', values: '× 1.2' },
      { name: 'Customer-facing', description: 'Public SSL/TLS', values: '× 1.3' },
      { name: 'Code Signing', description: 'Software signing certs', values: '× 1.1' },
      { name: 'Internal/Dev', description: 'Non-production', values: '× 0.7-1.0' }
    ],
    scale: '0-100',
    examples: [
      { scenario: 'Public cert, 15 days left', calculation: '(100-15/1.8) × 1.0 × 1.3', result: '100 (capped)' },
      { scenario: 'Internal cert, 60 days', calculation: '(100-60/1.8) × 1.0 × 1.0', result: '66.67' }
    ],
    sources: [
      'Let\'s Encrypt Certificate Transparency',
      'Ponemon Institute PKI Survey',
      'SSL Labs Grading Criteria',
      'Mozilla SSL Configuration Generator',
      'NIST SP 800-52 TLS Guidelines',
      'PCI DSS Certificate Requirements',
      'CA/Browser Forum Baseline Requirements'
    ]
  },

  'misconfiguration-score': {
    title: 'Misconfiguration Risk Score',
    description: 'IaC security issues scored by severity, exposure level, and data sensitivity.',
    formula: 'Misconfig_Score = ScannerSeverity × ExposureMod × DataMod',
    factors: [
      { name: 'Critical Severity', description: 'From Checkov/CIS', values: '90-100 base' },
      { name: 'High Severity', description: 'Significant issues', values: '70-89 base' },
      { name: 'Internet-facing', description: 'Public exposure', values: '× 1.5' },
      { name: 'DMZ/Firewalled', description: 'Partially exposed', values: '× 1.2' },
      { name: 'PII/PHI/PCI Data', description: 'Sensitive data present', values: '× 1.4' },
      { name: 'Business Confidential', description: 'Sensitive business data', values: '× 1.2' }
    ],
    scale: '0-100',
    examples: [
      { scenario: 'Public S3 with customer data', calculation: '85 × 1.5 × 1.4', result: '100 (capped)' }
    ],
    sources: [
      'CIS Benchmarks (AWS, Azure, GCP, Kubernetes)',
      'Checkov Policy Library',
      'Wiz Security Graph Methodology',
      'Orca Security Side-Scanning',
      'AWS Well-Architected Framework',
      'NIST SP 800-190 Container Security',
      'Bridgecrew Infrastructure Security'
    ]
  },

  'license-score': {
    title: 'License Risk Score',
    description: 'Open source license compliance scoring based on copyleft strength and distribution model.',
    formula: 'License_Score = RiskTier × DistributionMod × ModificationFactor',
    factors: [
      { name: 'AGPL-3.0', description: 'Strongest copyleft (SaaS triggers)', values: '90 base' },
      { name: 'GPL-3.0/2.0', description: 'Strong copyleft', values: '75 base' },
      { name: 'LGPL/MPL', description: 'Weak copyleft', values: '50 base' },
      { name: 'Unknown', description: 'No license specified', values: '70 base' },
      { name: 'MIT/BSD/Apache', description: 'Permissive licenses', values: '10 base' },
      { name: 'SaaS Distribution', description: 'Network service', values: '× 1.3' },
      { name: 'Commercial', description: 'Sold product', values: '× 1.2' },
      { name: 'Internal Only', description: 'Not distributed', values: '× 0.8' }
    ],
    scale: '0-100',
    examples: [
      { scenario: 'AGPL in SaaS product', calculation: '90 × 1.3', result: '100 (capped)' }
    ],
    sources: [
      'Synopsys OSSRA (Open Source Security and Risk Analysis)',
      'Black Duck License Compliance',
      'SPDX License List',
      'OSI (Open Source Initiative) License Standards',
      'FSF Free Software Licensing',
      'FOSSA License Scanning',
      'WhiteSource (Mend) License Detection'
    ]
  },

  'code-security-score': {
    title: 'Concert Exposure Risk Score (Formula 2)',
    description: 'SAST/DAST findings scored using IBM Concert methodology. Score = Severity × Environmental Factor. No EPSS factor as these are code-level findings without CVE identifiers.',
    formula: `Concert Exposure Score = Severity × Environmental Factor

SAST Severity (5-tier scale):
• Blocker/Critical: 10.0
• High: 7.5
• Medium: 5.0
• Low: 2.5
• Info: 1.0

DAST Severity (15-tier with confidence):
• High (High): 9.18
• High: 6.84
• Medium: 3.80
• Low: 0.76`,
    factors: [
      { name: 'SAST Blocker/Critical', description: 'Definite security issue', values: '10.0' },
      { name: 'SAST High', description: 'Significant security issue', values: '7.5' },
      { name: 'SAST Medium', description: 'Moderate security issue', values: '5.0' },
      { name: 'DAST High (High)', description: 'High severity with high confidence', values: '9.18' },
      { name: 'DAST Medium (Medium)', description: 'Medium severity with medium confidence', values: '5.32' },
      { name: 'App Criticality', description: 'Tier 1-5 business importance', values: '0.20-1.25' },
      { name: 'Data Sensitivity', description: 'Level 1-5 data classification', values: '0.20-1.25' },
      { name: 'Access Points', description: 'Public or Private access', values: '0.25-1.25' }
    ],
    scale: '1-10 (SAST findings have coarser granularity, DAST finer)',
    examples: [
      { scenario: 'SAST High in Level 5 app, 2 public', calculation: '7.5 × 1.13', result: '8.5' },
      { scenario: 'DAST High (High) in Level 3 app', calculation: '9.18 × 0.85', result: '7.8' },
      { scenario: 'SAST Medium in Level 2 app', calculation: '5.0 × 0.45', result: '2.25' }
    ],
    sources: [
      'IBM Concert Risk Methodology',
      'OWASP Top 10 (2021)',
      'CWE Top 25 Most Dangerous Software Weaknesses',
      'Semgrep Rule Registry',
      'SonarQube Security Rules',
      'Checkmarx CxSAST Severity Model',
      'Veracode Severity Ratings',
      'OWASP ZAP DAST Findings'
    ]
  },

  'aggregate-score': {
    title: 'Unified Exposure Risk Score (Formula 3)',
    description: 'Comprehensive scoring for all exposure types (CVEs, Secrets, Certs, Misconfigs, Licenses, Code) on a unified 0-100 scale. Uses weighted maximum aggregation with environmental multiplier.',
    formula: `Unified Score = Base_Score × Environmental_Multiplier

Base Score by Type:
• CVE: (CVSS × 2.5) + (EPSS × 35) + (KEV ? 40 : 0)
• Secret: Type × Validity × Context
• Certificate: max(0, 100 - days/1.8) × AlgoMod × TypeMod
• Misconfiguration: Severity × Exposure × Data
• License: RiskTier × Distribution
• Code Security: CWE × Confidence × Reachability

Application Risk Aggregation:
  Highest × 0.4 + AvgTop5Critical × 0.3 +
  AvgTop10High × 0.2 + log₁₀(n) × 2`,
    factors: [
      { name: 'Environmental Multiplier', description: 'Cube root prevents single factor dominance', values: '∛(Asset × Data × Network)' },
      { name: 'Asset Criticality', description: 'Mission-Critical to Non-Critical', values: '0.6 - 1.5' },
      { name: 'Data Sensitivity', description: 'Public to Restricted (PII/PHI/PCI)', values: '0.7 - 1.4' },
      { name: 'Network Exposure', description: 'Air-gapped to Internet-facing', values: '0.6 - 1.5' },
      { name: 'Weighted Maximum', description: 'Highest exposure dominates', values: '40% weight' },
      { name: 'Volume Penalty', description: 'More exposures = higher risk', values: 'log₁₀(n) × 2' }
    ],
    scale: '0-100 (Critical: ≥90, High: 70-89, Medium: 40-69, Low: <40)',
    examples: [
      { scenario: 'Log4Shell KEV', calculation: 'Auto 100 (KEV)', result: '100' },
      { scenario: 'Medium CVE (CVSS 6, EPSS 0.05)', calculation: '6×2.5 + 0.05×35', result: '16.75' },
      { scenario: 'AWS key, verified, prod', calculation: '95 × 1.0 × 1.2', result: '100 (capped)' }
    ],
    sources: [
      'IBM Concert Unified Exposure Methodology',
      'Tenable VPR (Vulnerability Priority Rating)',
      'Qualys TruRisk Scoring',
      'MAGERIT Bayesian Aggregation Model',
      'Cyentia Institute Research',
      'FAIR (Factor Analysis of Information Risk)',
      'NIST SP 800-30 Risk Aggregation'
    ]
  }
};

export function ScoreInfoModal({ open, onClose, scoreType }: ScoreInfoModalProps) {
  const info = scoreInfo[scoreType];

  if (!info) return null;

  return (
    <Modal
      open={open}
      onRequestClose={onClose}
      modalHeading={info.title}
      passiveModal
      size="md"
    >
      <div style={{ padding: '1rem 0' }}>
        <p style={{ marginBottom: '1.5rem', lineHeight: 1.6, color: 'var(--cds-text-secondary)' }}>
          {info.description}
        </p>

        {info.formula && (
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem' }}>Formula</h4>
            <CodeSnippet type="multi" feedback="Copied!">
              {info.formula}
            </CodeSnippet>
          </div>
        )}

        {info.factors && (
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem' }}>Factors</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {info.factors.map((factor, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    padding: '0.5rem 0.75rem',
                    backgroundColor: '#262626',
                    borderRadius: '4px'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 500, fontSize: '0.875rem' }}>{factor.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--cds-text-secondary)' }}>
                      {factor.description}
                    </div>
                  </div>
                  {factor.values && (
                    <Tag type="blue" size="sm" style={{ flexShrink: 0, marginLeft: '1rem' }}>
                      {factor.values}
                    </Tag>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {info.scale && (
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem' }}>Scale</h4>
            <p style={{ fontSize: '0.875rem', color: 'var(--cds-text-secondary)' }}>{info.scale}</p>
          </div>
        )}

        {info.examples && info.examples.length > 0 && (
          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem' }}>Examples</h4>
            {info.examples.map((example, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.75rem',
                  backgroundColor: '#1a1a1a',
                  borderRadius: '4px',
                  marginBottom: '0.5rem',
                  border: '1px solid #393939'
                }}
              >
                <div style={{ fontWeight: 500, marginBottom: '0.25rem', fontSize: '0.875rem' }}>
                  {example.scenario}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--cds-text-secondary)', fontFamily: 'monospace' }}>
                  {example.calculation} = <span style={{ color: '#42be65', fontWeight: 600 }}>{example.result}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {info.sources && info.sources.length > 0 && (
          <div>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.5rem' }}>Based On</h4>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {info.sources.map((source, idx) => (
                <Tag key={idx} type="gray" size="sm">{source}</Tag>
              ))}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

export default ScoreInfoModal;
