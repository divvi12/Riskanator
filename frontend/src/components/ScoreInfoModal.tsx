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
    title: 'Overall Exposure Score',
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
    description: 'A quick-glance risk score optimized for executive reporting. Uses weighted aggregation prioritizing the most dangerous exposure types.',
    formula: `Concert = (
  MaxCritical × 0.4 +
  AvgTop5Critical × 0.3 +
  AvgTop10High × 0.2 +
  log₁₀(n) × 2
) ÷ 10`,
    factors: [
      { name: 'Secrets', description: 'Hardcoded credentials (highest risk)', values: '3.0× weight' },
      { name: 'CVEs', description: 'Known vulnerabilities', values: '2.0× weight' },
      { name: 'Certificates', description: 'Expiring/weak certificates', values: '1.5× weight' },
      { name: 'Misconfigurations', description: 'IaC security issues', values: '1.5× weight' },
      { name: 'Code Security', description: 'SAST findings', values: '1.2× weight' },
      { name: 'Licenses', description: 'Legal/compliance issues', values: '0.8× weight' },
      { name: 'CISA KEV Boost', description: 'Known exploited vulnerabilities', values: '+50% weight' },
      { name: 'Verified Secrets Boost', description: 'Confirmed active credentials', values: '+30% weight' }
    ],
    scale: '0-10 scale for executive dashboards',
    sources: [
      'IBM Concert Methodology',
      'Snyk Risk Score',
      'Rapid7 Active Risk',
      'FIRST CVSS Special Interest Group'
    ]
  },

  'detailed-score': {
    title: 'Detailed Score (Comprehensive Analysis)',
    description: 'An in-depth risk score considering multiple factors including exploitability, attack surface diversity, SLA urgency, and compliance impact.',
    formula: `Detailed = Average of:
  • Severity Distribution (0-10)
  • Attack Surface Diversity (0-10)
  • Exploitability via EPSS (0-10)
  • SLA Urgency (0-10)
  • Secrets Exposure (0-10)
  • Certificate Health (0-10)`,
    factors: [
      { name: 'Severity Distribution', description: 'Weighted count: Critical×2.5 + High×1.5 + Medium×0.5', values: '0-10' },
      { name: 'Attack Surface Diversity', description: 'Number of exposure types × 1.5', values: '0-10' },
      { name: 'EPSS Exploitability', description: 'Average EPSS × 10 + KEV count × 2', values: '0-10' },
      { name: 'SLA Urgency', description: '(Overdue × 3 + DueSoon × 1) / total × 10', values: '0-10' },
      { name: 'Secrets Risk', description: 'Secrets × 2 + Verified × 3', values: '0-10' },
      { name: 'Certificate Health', description: 'Expired × 5 + Expiring30d × 2', values: '0-10' }
    ],
    scale: '0-10 (multiply by 100 for 0-1000 display)',
    sources: [
      'NIST SP 800-30 Risk Management Guide',
      'OWASP Risk Rating Methodology',
      'ISO 27005 Information Security Risk Management',
      'FAIR (Factor Analysis of Information Risk)',
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
    title: 'CVE Risk Score',
    description: 'Individual CVE scoring based on CVSS, EPSS exploit probability, and CISA KEV status.',
    formula: `CVE_Score = (CVSS × 2.5) + (EPSS × 35) + (KEV ? 40 : 0)

If KEV = true: Score = 100 (automatic Critical)`,
    factors: [
      { name: 'CVSS', description: 'Base severity 0-10 → 0-25 points', values: '× 2.5' },
      { name: 'EPSS', description: 'Exploit probability 0-1 → 0-35 points', values: '× 35' },
      { name: 'CISA KEV', description: 'Known exploited = automatic 100', values: '+40 or auto-100' }
    ],
    scale: '0-100',
    examples: [
      { scenario: 'Log4Shell (CVSS 10, EPSS 0.89, KEV)', calculation: 'Auto KEV', result: '100 (Critical)' },
      { scenario: 'Medium CVE (CVSS 6, EPSS 0.05)', calculation: '6×2.5 + 0.05×35', result: '16.75 (Low)' }
    ],
    sources: [
      'NIST NVD (National Vulnerability Database)',
      'FIRST CVSS v3.1 Specification',
      'FIRST EPSS (Exploit Prediction Scoring System)',
      'CISA Known Exploited Vulnerabilities',
      'Tenable VPR Formula Research',
      'Cyentia Institute EPSS Analysis',
      'Kenna Security Risk-Based Prioritization'
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
    title: 'Code Security Risk Score',
    description: 'SAST findings scored by CWE severity, detection confidence, and code reachability.',
    formula: 'CodeSec_Score = CWESeverity × Confidence × Reachability',
    factors: [
      { name: 'SQL Injection', description: 'CWE-89', values: '90 base' },
      { name: 'Command Injection', description: 'CWE-78', values: '90 base' },
      { name: 'XSS', description: 'CWE-79', values: '85 base' },
      { name: 'Path Traversal', description: 'CWE-22', values: '75 base' },
      { name: 'Weak Crypto', description: 'CWE-327', values: '60 base' },
      { name: 'High Confidence', description: 'Definite finding', values: '× 1.0' },
      { name: 'Medium Confidence', description: 'Likely finding', values: '× 0.8' },
      { name: 'Low Confidence', description: 'Possible finding', values: '× 0.5' },
      { name: 'Public Endpoint', description: 'User-facing code', values: '× 1.3' },
      { name: 'Dead Code', description: 'Unreachable code', values: '× 0.3' }
    ],
    scale: '0-100',
    examples: [
      { scenario: 'SQLi in login API, high confidence', calculation: '90 × 1.0 × 1.3', result: '100 (capped)' }
    ],
    sources: [
      'OWASP Top 10 (2021)',
      'CWE Top 25 Most Dangerous Software Weaknesses',
      'SANS Top 25 Software Errors',
      'SonarQube Security Rules',
      'Checkmarx CxSAST Severity Model',
      'Veracode Severity Ratings',
      'Semgrep Rule Registry',
      'CodeQL Security Queries'
    ]
  },

  'aggregate-score': {
    title: 'Aggregate Application Risk Score',
    description: 'The unified score combining all exposures using weighted maximum with diminishing returns.',
    formula: `ApplicationRisk = min(100,
  Highest × 0.4 +
  AvgTop5Critical × 0.3 +
  AvgTop10High × 0.2 +
  log₁₀(total + 1) × 2
)`,
    factors: [
      { name: 'Environmental Multiplier', description: 'Applied to each exposure', values: '∛(Asset × Data × Network)' },
      { name: 'Asset Criticality', description: 'Tier 1-5 business importance', values: '0.6 - 1.5' },
      { name: 'Data Sensitivity', description: 'Public to Restricted (PII/PHI)', values: '0.7 - 1.4' },
      { name: 'Network Exposure', description: 'Air-gapped to Internet-facing', values: '0.6 - 1.5' }
    ],
    scale: '0-100',
    sources: [
      'Tenable VPR (Vulnerability Priority Rating)',
      'Qualys TruRisk Scoring',
      'MAGERIT Bayesian Aggregation Model',
      'Cyentia Institute Research',
      'Kenna Security Risk Meter',
      'FAIR (Factor Analysis of Information Risk)',
      'NIST SP 800-30 Risk Aggregation',
      'RiskLens Quantitative Cyber Risk'
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
