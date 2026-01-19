# IBM Concert-Style Exposure Management Platform - Design Document

## Executive Summary

A localhost web application that provides **comprehensive exposure management** across your application security posture. Goes beyond traditional CVE scanning to identify certificates, secrets, misconfigurations, license violations, and code security issues - all with contextualized risk scoring and AI-powered remediation guidance.

**Core Capabilities:**
- **6 Exposure Types**: CVEs, Certificates, Secrets, Misconfigurations, Licenses, Code Security
- **Dual Risk Scoring**: Concert formula + Comprehensive Framework
- **AI-Powered Insights**: Gemini-powered explanations and remediation plans
- **ServiceNow Integration**: Automated incident creation
- **Smart Grouping**: Remediation actions grouped by fix
- **Compliance Mapping**: PCI, HIPAA, SOX, GDPR
- **Financial Impact**: ROI calculations and breach cost analysis
- **Demo Mode**: Instant results for presentations

**Tech Stack:** React + Vite + Carbon Design System | Node.js + Express | Gemini AI

---

## What is Exposure Management?

**Traditional Approach (CVE-Only):**
```
Scan code → Find CVE vulnerabilities → Patch → Done
```
**Problem:** Misses 60%+ of security risks that aren't CVEs

**Exposure Management Approach:**
```
Scan everything → Find ALL security/compliance weaknesses → Prioritize by risk → Fix
```
**Result:** Complete visibility across your security posture

### The 6 Exposure Categories

```
┌─────────────────────────────────────────────────────────────┐
│                    EXPOSURE LANDSCAPE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  🔒 CVEs                     📜 Certificates                │
│  Known vulnerabilities       Expiring/expired certs        │
│  in dependencies             Weak algorithms               │
│  Example: Log4Shell          Example: Cert expires in 15d  │
│                                                             │
│  🔑 Secrets                  ⚙️ Misconfigurations          │
│  Hardcoded credentials       Insecure cloud settings       │
│  API keys in code            Example: Public S3 bucket     │
│  Example: AWS key in git                                   │
│                                                             │
│  ⚖️ License Issues           💻 Code Security              │
│  GPL in proprietary code     SQL injection, XSS            │
│  Unknown licenses            Insecure patterns             │
│  Example: GPL-3.0 violation  Example: Unsanitized input    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Architecture Overview

### System Architecture
```
┌────────────────────────────────────────────────────────┐
│              FRONTEND (Port 5173)                      │
│        React + Vite + Carbon Design System             │
│                                                        │
│  Pages:                                                │
│  • Exposure Dashboard (unified view)                  │
│  • Scan Setup Wizard (6-step)                         │
│  • Exposure List (filterable by type)                 │
│  • Exposure Detail (type-specific modals)             │
│  • Remediation Groups (action-based)                  │
│  • Settings (ServiceNow, preferences)                 │
└────────────────────────┬───────────────────────────────┘
                         │ HTTP/REST API
                         ↓
┌────────────────────────────────────────────────────────┐
│              BACKEND (Port 3001)                       │
│                Node.js + Express                       │
│                                                        │
│  Scanners:                                             │
│  • CVE: npm audit, pip-audit, Trivy                   │
│  • Certificates: X.509 parser                         │
│  • Secrets: TruffleHog                                │
│  • Misconfigurations: Checkov, tfsec, kubesec         │
│  • Licenses: license-checker, pip-licenses            │
│  • Code Security: Semgrep (enhanced rules)            │
│                                                        │
│  Services:                                             │
│  • Risk scoring (per exposure type)                   │
│  • CVE enrichment (NVD, EPSS, CISA KEV)              │
│  • Remediation grouping                                │
│  • Gemini AI integration                               │
│  • ServiceNow API client                               │
└────────────────────────┬───────────────────────────────┘
                         │
                         ↓
┌────────────────────────────────────────────────────────┐
│              EXTERNAL SERVICES                         │
│                                                        │
│  • NVD, EPSS, CISA KEV (CVE data)                    │
│  • Google Gemini (AI explanations)                    │
│  • ServiceNow (incident management)                   │
└────────────────────────────────────────────────────────┘
```

---

## Exposure Types & Scanning

### 1. 🔒 CVEs (Common Vulnerabilities & Exposures)

**What:** Known security vulnerabilities in software dependencies
**Tools:** npm audit, pip-audit, Maven, Trivy, Bundler
**Example:** CVE-2021-44228 (Log4Shell) in log4j-core 2.14.1

**Risk Factors:**
- CVSS score (technical severity)
- EPSS score (exploitation probability)
- CISA KEV status (actively exploited)
- Application criticality
- Data sensitivity
- Network exposure

**Risk Formula (Concert):**
```
Risk = CVSS × Exploitability(EPSS) × Environmental(Context)
```

---

### 2. 📜 Certificates

**What:** SSL/TLS certificates, code signing certificates
**Tools:** Custom X.509 parser (node-forge)
**Example:** api.example.com certificate expires in 15 days

**Issues Detected:**
- ❌ Expired certificates
- ⚠️ Expiring soon (0-30 days = Critical, 31-90 = High, 91-180 = Medium)
- 🔓 Self-signed certificates (production)
- 🚨 Weak algorithms (MD5, SHA-1)
- 📛 Invalid certificate chains

**Risk Formula:**
```typescript
// Base severity from expiration
if (daysUntilExpiration <= 0) severity = 10.0;      // Expired
else if (daysUntilExpiration <= 7) severity = 9.0;   // 1 week
else if (daysUntilExpiration <= 30) severity = 8.0;  // 1 month
else if (daysUntilExpiration <= 90) severity = 6.0;  // 3 months

// Apply environmental context
envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;

// Public-facing certs are higher risk
exposureFactor = isPublicFacing ? 1.1 : 1.0;

risk = severity × envFactor × exposureFactor;
```

**Scanning Logic:**
```typescript
// Find all certificate files
const certFiles = await findFiles(repoPath, /\.(crt|pem|p12|pfx|cer)$/);

for (const file of certFiles) {
  const cert = x509.parseCert(await fs.readFile(file));
  
  const daysUntilExpiration = daysBetween(new Date(), cert.notAfter);
  
  if (daysUntilExpiration < 180) { // Only flag if expires within 6 months
    exposures.push({
      type: 'certificate',
      title: `Certificate: ${cert.subject.commonName}`,
      severity: daysUntilExpiration <= 30 ? 'Critical' : 'High',
      expiresAt: cert.notAfter,
      daysUntilExpiration,
      issuer: cert.issuer.commonName,
      algorithm: cert.signatureAlgorithm,
      location: file
    });
  }
}
```

---

### 3. 🔑 Secrets (Hardcoded Credentials)

**What:** API keys, passwords, tokens committed to code
**Tools:** TruffleHog, git-secrets
**Example:** AWS access key hardcoded in config.js

**Issues Detected:**
- 🔴 AWS access keys
- 🔴 API keys (Stripe, SendGrid, etc.)
- 🔴 Database passwords
- 🔴 Private keys
- 🔴 OAuth tokens
- 🔴 Generic secrets (high entropy strings)

**Risk Formula:**
```typescript
// Secrets are ALWAYS high risk
const baseSeverity = {
  'AWS': 9.5,
  'Private Key': 9.5,
  'API Key': 9.0,
  'Password': 8.5,
  'Token': 8.0,
  'Generic Secret': 7.5
}[secretType];

// Secrets are immediately exploitable
const exploitabilityFactor = 1.25; // Maximum

// Apply environmental context
const envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;

// If secret is in git history (not just working tree), higher risk
const gitHistoryFactor = inGitHistory ? 1.2 : 1.0;

risk = baseSeverity × exploitabilityFactor × envFactor × gitHistoryFactor;
```

**Scanning Logic:**
```bash
# Run TruffleHog
trufflehog filesystem /path/to/repo --json --only-verified
```

```typescript
// Parse TruffleHog output
const secrets = truffleOutput.map(finding => ({
  type: 'secret',
  title: `Hardcoded ${finding.DetectorName}`,
  severity: 'Critical',
  secretType: finding.DetectorName,
  location: `${finding.SourceMetadata.File}:${finding.SourceMetadata.Line}`,
  verified: finding.Verified,
  entropy: finding.Entropy
}));
```

---

### 4. ⚙️ Misconfigurations

**What:** Insecure infrastructure or cloud configurations
**Tools:** Checkov (IaC), tfsec (Terraform), kubesec (Kubernetes)
**Example:** S3 bucket with public read access

**Issues Detected:**
- ☁️ Public S3 buckets
- 🔓 Overly permissive security groups (0.0.0.0/0)
- 🔑 Disabled encryption at rest
- 🚪 Open database ports
- 👤 Weak IAM policies
- 🌐 Missing HTTPS enforcement

**Risk Formula:**
```typescript
// Use scanner's severity rating
const baseSeverity = scannerSeverity; // From Checkov/tfsec

// Publicly accessible resources are higher risk
const exploitabilityFactor = isPubliclyAccessible ? 1.25 : 1.0;

// Apply environmental context
const envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;

// Production resources are higher risk
const environmentFactor = environment === 'production' ? 1.2 : 0.8;

risk = baseSeverity × exploitabilityFactor × envFactor × environmentFactor;
```

**Scanning Logic:**
```bash
# Run Checkov on IaC files
checkov -d /path/to/repo --output json

# Run tfsec on Terraform
tfsec /path/to/terraform --format json

# Run kubesec on Kubernetes manifests
kubesec scan /path/to/k8s/*.yaml --json
```

---

### 5. ⚖️ License Violations

**What:** Software licenses incompatible with your usage
**Tools:** license-checker (npm), pip-licenses (Python)
**Example:** GPL-3.0 library in proprietary software

**Issues Detected:**
- ⚠️ GPL/AGPL in proprietary code (copyleft issues)
- ❓ Unknown/missing licenses
- 💰 Proprietary licenses requiring payment
- 📜 License version conflicts

**Risk Formula:**
```typescript
// Base severity from license type
const baseSeverity = {
  'AGPL-3.0': 8.0,      // Strongest copyleft
  'GPL-3.0': 7.0,       // Strong copyleft
  'GPL-2.0': 6.5,
  'Unknown': 6.0,       // Unknown is risky
  'Proprietary': 5.0,   // Cost/compliance risk
  'MIT': 1.0,           // Permissive, low risk
  'Apache-2.0': 1.0,
  'BSD-3-Clause': 1.0
}[licenseType] || 5.0;

// Commercial use increases legal risk
const commercialFactor = isCommercialUse ? 1.2 : 0.8;

// Application criticality affects legal exposure
const criticalityFactor = appCriticality / 5.0;

risk = baseSeverity × commercialFactor × criticalityFactor;
```

**Scanning Logic:**
```bash
# Scan npm packages
license-checker --json --production

# Scan Python packages
pip-licenses --format=json
```

---

### 6. 💻 Code Security Issues

**What:** SAST findings that aren't CVEs (code vulnerabilities)
**Tools:** Semgrep (open source)
**Example:** SQL injection in user input handler

**Issues Detected:**
- 🚨 SQL Injection
- 🚨 Cross-Site Scripting (XSS)
- 🚨 Command Injection
- 🔓 Insecure cryptography
- 🔐 Broken authentication
- 📂 Path traversal
- 🐛 Code smells (security-relevant)

**Risk Formula:**
```typescript
// Use SAST tool severity
const baseSeverity = sastSeverity;

// Different vulnerability types have different exploitability
const exploitabilityFactor = {
  'SQL Injection': 1.25,
  'Command Injection': 1.25,
  'XSS': 1.15,
  'Path Traversal': 1.1,
  'Insecure Crypto': 0.9,
  'Code Smell': 0.5
}[issueType] || 1.0;

// Apply environmental context
const envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;

// Public-facing endpoints are higher risk
const locationFactor = isPublicEndpoint ? 1.2 : 1.0;

risk = baseSeverity × exploitabilityFactor × envFactor × locationFactor;
```

**Scanning Logic:**
```bash
# Run Semgrep with security rules
semgrep --config=auto --json /path/to/repo
```

---

## User Interface Design

### Design Philosophy

**Principles:**
1. **Clarity First**: Every exposure type gets distinct visual identity
2. **Progressive Disclosure**: Show summary first, details on demand
3. **Context Everywhere**: Always show "why this matters to YOUR app"
4. **Action-Oriented**: Every screen leads to clear next steps
5. **Beautiful Data**: Use color, icons, and spacing intentionally

**IBM Carbon Design System:**
- Theme: g100 (dark mode for professional feel)
- Typography: IBM Plex Sans
- Color coding: Semantic colors for exposure types
- Components: Tiles, DataTables, Modals, ProgressIndicator

---

### Landing Page (New Design)

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     IBM Concert-Style                       │
│                EXPOSURE MANAGEMENT PLATFORM                 │
│                                                             │
│              Comprehensive Security Posture                 │
│           Beyond CVEs: Complete Visibility                  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────┐  ┌──────────────────────┐  │
│  │                          │  │                      │  │
│  │    [📊 Dashboard Icon]   │  │  [🔍 Scan Icon]     │  │
│  │                          │  │                      │  │
│  │    Try Demo Mode         │  │  Scan Repository    │  │
│  │                          │  │                      │  │
│  │  Explore pre-loaded      │  │  Scan your code for │  │
│  │  results from a sample   │  │  exposures across   │  │
│  │  financial services      │  │  6 categories       │  │
│  │  application             │  │                      │  │
│  │                          │  │                      │  │
│  │  • 243 exposures found   │  │  Connect via:       │  │
│  │  • $12.1M risk avoided   │  │  • GitHub           │  │
│  │  • ROI: 237:1            │  │  • GitLab           │  │
│  │                          │  │  • Bitbucket        │  │
│  │  [Try Demo Mode →]       │  │  • Any Git URL      │  │
│  │                          │  │                      │  │
│  │                          │  │  [Start Scan →]     │  │
│  │                          │  │                      │  │
│  └──────────────────────────┘  └──────────────────────┘  │
│                                                             │
│                                                             │
│  What gets scanned:                                         │
│                                                             │
│  🔒 CVEs            📜 Certificates      🔑 Secrets        │
│  ⚙️ Misconfigs      ⚖️ Licenses         💻 Code Security  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### Dashboard (Main View)

```
┌────────────────────────────────────────────────────────────────────┐
│ [☰] Exposure Management Platform │ IBM        [🔍] [🔔] [👤]     │
├──┬─────────────────────────────────────────────────────────────────┤
│🏠│ Payment Processing API                    [New Scan →]          │
│  │ Last scanned: 2 hours ago                                       │
│  │                                                                  │
│📊├──────────────────────────────────────────────────────────────────┤
│  │                                                                  │
│🔧│  SECURITY POSTURE OVERVIEW                                      │
│  │                                                                  │
│⚙️│  ┌────────────────────────┐  ┌──────────────────────────────┐ │
│  │  │                        │  │  Overall Risk Score      ⓘ  │ │
│  │  │   [Risk Radial Chart]  │  │  76.3/100           ↑ 5.2   │ │
│  │  │                        │  │                              │ │
│  │  │   Security Dimensions: │  │  🔴 High Risk               │ │
│  │  │   • CVEs              │  │  Requires immediate action   │ │
│  │  │   • Certificates      │  │                              │ │
│  │  │   • Secrets           │  │  Priority Actions:           │ │
│  │  │   • Configurations    │  │  • 2 secrets in code        │ │
│  │  │   • Licenses          │  │  • 3 certs expire <30d      │ │
│  │  │   • Code Security     │  │  • 8 critical CVEs          │ │
│  │  │                        │  │                              │ │
│  │  │  Red = Attention       │  └──────────────────────────────┘ │
│  │  └────────────────────────┘                                    │
│  │                                                                  │
│  │  EXPOSURE BREAKDOWN                                             │
│  │                                                                  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐│
│  │  │ Total Exposures  │  │ CISA KEV     ⓘ  │  │ SLA Status ⓘ││
│  │  │                  │  │                  │  │              ││
│  │  │      243         │  │       8          │  │ 🔴 5 Overdue ││
│  │  │                  │  │                  │  │ 🟠 12 Due    ││
│  │  │ 🔒 CVEs: 167     │  │ Actively         │  │    Soon      ││
│  │  │ 📜 Certs: 8      │  │ exploited        │  │ 🟢 226 OK    ││
│  │  │ 🔑 Secrets: 4    │  │ in the wild      │  │              ││
│  │  │ ⚙️ Configs: 42   │  │                  │  │ Compliance:  ││
│  │  │ ⚖️ Licenses: 15  │  │ [View All →]     │  │ 85%          ││
│  │  │ 💻 Code: 7       │  │                  │  │              ││
│  │  │              →  │  └──────────────────┘  └──────────────┘│
│  │  └──────────────────┘                                          │
│  │                                                                  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐│
│  │  │ Financial     ⓘ  │  │ Compliance   ⓘ  │  │ Remediation ⓘ││
│  │  │ Impact            │  │ Impact           │  │ Groups       ││
│  │  │                  │  │                  │  │              ││
│  │  │ Potential Risk:  │  │ 🏛️ PCI: 12      │  │ 18 actions   ││
│  │  │ $12.1M           │  │ 🏥 HIPAA: 0     │  │ grouped      ││
│  │  │                  │  │ 📊 SOX: 8       │  │              ││
│  │  │ Remediation:     │  │ 🇪🇺 GDPR: 23    │  │ Est. effort: ││
│  │  │ $51K             │  │                  │  │ 68 hours     ││
│  │  │                  │  │ Highest impact: │  │              ││
│  │  │ ROI: 237:1 📈    │  │ PCI-DSS         │  │ [View All →] ││
│  │  │              →  │  │              →  │  │              ││
│  │  └──────────────────┘  └──────────────────┘  └──────────────┘│
│  │                                                                  │
│  │  EXPOSURE SEVERITY DISTRIBUTION                                 │
│  │                                                                  │
│  │  ┌──────────────────────────────────────────────────────────┐  │
│  │  │                                                          │  │
│  │  │  Critical (18) ████████████▌                   37%      │  │
│  │  │  High (67)     ██████████████████████████▎     28%      │  │
│  │  │  Medium (124)  ████████████████████████████████████  51%│  │
│  │  │  Low (34)      ███████▏                        14%      │  │
│  │  │                                                          │  │
│  │  └──────────────────────────────────────────────────────────┘  │
│  │                                                                  │
└──┴──────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- **Radial chart** shows 6 dimensions (each exposure type)
- **Red segments** indicate high-risk areas
- **Metric tiles** use Carbon design with hover tooltips
- **Bar chart** shows severity distribution visually
- **One-click navigation** to detailed views

---

### Exposure List Page (Enhanced)

```
┌──────────────────────────────────────────────────────────────────┐
│ All Exposures (243)                    [View: Security Team ▼]  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ┌─ FILTERS ────────────────────────────────────────────────┐   │
│ │                                                           │   │
│ │ Exposure Type:          Severity:          Status:       │   │
│ │ [All Types        ▼]   [All         ▼]   [All      ▼]  │   │
│ │                                                           │   │
│ │ Quick Filters:                                            │   │
│ │ [✓] CISA KEV Only   [✓] Overdue SLA   [ ] Has Fix       │   │
│ │                                                           │   │
│ │ Search: [_______________________________________] 🔍      │   │
│ │                                                           │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│ Showing 243 exposures                  [Export: CSV | PDF]     │
│                                                                  │
├──────┬──────────┬─────────────────────────┬─────────┬──────────┤
│ Risk │ Type     │ Title                   │Severity │ Details  │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 9.8  │ 🔒 CVE   │ CVE-2021-44228         │🔴Critical│ log4j-   │
│      │          │ (Log4Shell) 🚨         │         │ core     │
│      │          │ CISA KEV: Exploited    │         │ 2.14.1   │
│      │          │                         │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 9.5  │ 🔑 Secret│ Hardcoded AWS Access   │🔴Critical│ config/  │
│      │          │ Key                     │         │ aws.js   │
│      │          │ Verified: Yes ⚠️        │         │ :12      │
│      │          │                         │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 8.7  │ ⚙️ Config│ Public S3 Bucket        │🟠 High  │ s3.tf    │
│      │          │ Allows read access      │         │ :15      │
│      │          │                         │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 8.2  │ 📜 Cert  │ api.example.com         │🟠 High  │ certs/   │
│      │          │ Expires in 15 days      │         │ api.crt  │
│      │          │ Due: Jan 31, 2026       │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 8.1  │ 💻 Code  │ SQL Injection           │🟠 High  │ api/     │
│      │          │ User input not sanitized│         │ users.js │
│      │          │                         │         │ :45      │
│      │          │                         │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┼──────────┼─────────────────────────┼─────────┼──────────┤
│      │          │                         │         │          │
│ 6.5  │ ⚖️ License│ GPL-3.0 Violation      │🟡 Medium│ some-gpl │
│      │          │ Incompatible license    │         │ -library │
│      │          │                         │         │ @1.2.3   │
│      │          │                         │         │ [AI ✨]  │
│      │          │                         │         │          │
├──────┴──────────┴─────────────────────────┴─────────┴──────────┤
│                                                                  │
│ [Show 20 per page]                         [◄ 1 2 3 4 5 6 ►]   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

Legend:
🚨 = CISA KEV (Actively Exploited)
⚠️ = Verified Secret (Confirmed valid)
🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low
```

**Type Filter Dropdown:**
```
┌──────────────────────────┐
│ All Types           ▼   │
├──────────────────────────┤
│ ✓ All Types             │
│ ─────────────────────── │
│ 🔒 CVEs (167)           │
│ 📜 Certificates (8)     │
│ 🔑 Secrets (4)          │
│ ⚙️ Misconfigurations(42)│
│ ⚖️ License Issues (15)  │
│ 💻 Code Security (7)    │
└──────────────────────────┘
```

---

### Exposure Detail Modals (Type-Specific)

#### CVE Exposure Modal

```
┌────────────────────────────────────────────────────────┐
│ 🔒 CVE-2021-44228 (Log4Shell)                    [✕] │
├────────────────────────────────────────────────────────┤
│                                                        │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Risk: 9.8 │ │CVSS: 10.0│ │EPSS: 89% │ │🚨 CISA  │ │
│ │🔴        │ │          │ │          │ │   KEV    │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                        │
│ ⚠️ CRITICAL: Actively exploited in the wild          │
│                                                        │
│ Description:                                           │
│ Apache Log4j2 JNDI features used in configuration,    │
│ log messages, and parameters do not protect against   │
│ attacker-controlled LDAP and other JNDI related      │
│ endpoints. Remote code execution is possible.         │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Affects Your Application:                             │
│ • Component: log4j-core@2.14.1                       │
│ • Location: package.json                              │
│ • Application: Payment Processing API                 │
│ • Criticality: Business-Critical (Tier 4)            │
│ • Data: Processes PCI + PII data                     │
│ • Exposure: 2 public access points                    │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Why This Matters:                                     │
│ Your business-critical payment API processes          │
│ sensitive cardholder data. This actively exploited    │
│ vulnerability allows attackers to execute arbitrary   │
│ code, potentially stealing payment information or     │
│ disrupting payment processing.                        │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Compliance Impact:                                     │
│ 🏛️ PCI-DSS Requirement 6.2                           │
│    Ensure all system components are protected from    │
│    known vulnerabilities                              │
│                                                        │
│ 📊 SOX Section 404                                    │
│    IT General Controls - Change Management            │
│                                                        │
│ 🇪🇺 GDPR Article 32                                   │
│    Security of Processing                             │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Remediation:                                           │
│ Update to log4j-core@2.17.1 or later                 │
│                                                        │
│ SLA Deadline: Jan 18, 2026 (48 hours)                │
│ Status: 🔴 OVERDUE by 2 days                         │
│                                                        │
│ Financial Impact:                                      │
│ • Potential breach cost: $732K (15% × $4.88M)        │
│ • Remediation effort: 2 hours ($300)                 │
│ • ROI: 2,440:1                                        │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ References:                                            │
│ • NVD: nvd.nist.gov/vuln/detail/CVE-2021-44228      │
│ • CISA: cisa.gov/known-exploited-vulnerabilities     │
│ • Apache: logging.apache.org/log4j/2.x/security.html │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ [✨ Get AI Remediation Plan (~$0.03)]                 │
│                                                        │
│ [🎫 Create ServiceNow Incident] [📋 Copy Details]    │
│                                                        │
└────────────────────────────────────────────────────────┘
```

#### Certificate Exposure Modal

```
┌────────────────────────────────────────────────────────┐
│ 📜 Expiring Certificate: api.example.com         [✕] │
├────────────────────────────────────────────────────────┤
│                                                        │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Risk: 8.2 │ │Expires:  │ │Days:     │ │Type:     │ │
│ │🟠 High   │ │Jan 31    │ │15        │ │SSL/TLS   │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                        │
│ ⚠️ Certificate expires in 15 days                     │
│                                                        │
│ Certificate Details:                                   │
│ • Domain: api.example.com                             │
│ • Issuer: Let's Encrypt (R3)                          │
│ • Valid From: Aug 1, 2025                             │
│ • Valid To: Jan 31, 2026                              │
│ • Serial: 04:3f:2a:...                                │
│ • Algorithm: RSA-2048 with SHA-256                    │
│ • Location: certs/api.example.com.crt                 │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Affects Your Application:                             │
│ • Application: Payment Processing API                 │
│ • Criticality: Business-Critical (Tier 4)            │
│ • Usage: Secures public API endpoints                │
│ • Traffic: ~10,000 requests/day                       │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Impact if Expired:                                    │
│ Your public-facing payment API will become            │
│ inaccessible. Browsers will show "Your connection    │
│ is not secure" warnings. All payment processing       │
│ will stop, causing immediate revenue loss estimated   │
│ at $87,500/hour.                                       │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Compliance Impact:                                     │
│ 🏛️ PCI-DSS Requirement 4.1                           │
│    Use strong cryptography for transmission           │
│    of cardholder data                                 │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Remediation:                                           │
│ Renew certificate from Let's Encrypt                  │
│                                                        │
│ SLA Deadline: Jan 25, 2026 (9 days)                  │
│ Status: 🟠 Due soon                                   │
│                                                        │
│ Recommended Actions:                                   │
│ 1. Renew certificate now (don't wait)                │
│ 2. Set up automated renewal (certbot)                │
│ 3. Configure monitoring alerts (30-day warning)      │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ [✨ Get AI Renewal Instructions (~$0.02)]             │
│                                                        │
│ [🎫 Create ServiceNow Incident] [📋 Copy Details]    │
│                                                        │
└────────────────────────────────────────────────────────┘
```

#### Secret Exposure Modal

```
┌────────────────────────────────────────────────────────┐
│ 🔑 Hardcoded AWS Access Key                      [✕] │
├────────────────────────────────────────────────────────┤
│                                                        │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Risk: 9.5 │ │Type:     │ │Verified: │ │Entropy:  │ │
│ │🔴Critical│ │API Key   │ │✓ Yes ⚠️  │ │High      │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                        │
│ 🚨 CRITICAL: Valid AWS credentials exposed in code   │
│                                                        │
│ Secret Details:                                        │
│ • Type: AWS Access Key ID                             │
│ • Location: src/config/aws.js:12                      │
│ • Detector: TruffleHog (AWS Scanner)                  │
│ • Status: Verified (key is VALID)                     │
│ • In Git History: Yes (committed 3 months ago)        │
│                                                        │
│ Code Context:                                          │
│ ```javascript                                          │
│ 10 | const config = {                                 │
│ 11 |   region: 'us-east-1',                          │
│ 12 |   accessKeyId: 'AKIA...REDACTED',               │
│ 13 |   secretAccessKey: 'wJalr...REDACTED',          │
│ 14 | };                                               │
│ ```                                                    │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Affects Your Application:                             │
│ • Application: Payment Processing API                 │
│ • Criticality: Business-Critical (Tier 4)            │
│ • Data: Processes PCI + PII data                     │
│ • AWS Account: Production (payment-processing-prod)   │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Immediate Risk:                                        │
│ These credentials provide access to your production   │
│ AWS account containing customer payment data. An      │
│ attacker could:                                       │
│ • Access S3 buckets with payment information          │
│ • Spin up expensive EC2 instances ($$$)               │
│ • Delete production databases                         │
│ • Exfiltrate customer PII                             │
│                                                        │
│ The key is in git history, meaning it's permanently   │
│ exposed even if removed from current code.            │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Compliance Impact:                                     │
│ 🏛️ PCI-DSS Requirement 3.4                           │
│    Render PAN unreadable anywhere it is stored        │
│                                                        │
│ 📊 SOX Section 404                                    │
│    IT General Controls - Access Management            │
│                                                        │
│ 🇪🇺 GDPR Article 32                                   │
│    Security of Processing - Implement appropriate     │
│    technical and organizational measures              │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ Remediation (URGENT):                                  │
│ 1. Rotate AWS credentials IMMEDIATELY                 │
│ 2. Audit AWS CloudTrail for unauthorized access      │
│ 3. Move to AWS Secrets Manager                       │
│ 4. Remove from git history (git filter-branch)       │
│                                                        │
│ SLA Deadline: OVERDUE (0 days - immediate action)    │
│ Status: 🔴 CRITICAL - Act NOW                        │
│                                                        │
│ Financial Impact:                                      │
│ • Potential breach cost: $4.6M (95% × $4.88M)        │
│ • Unauthorized AWS charges: Unknown                   │
│ • Remediation effort: 4 hours ($600)                 │
│                                                        │
│ ─────────────────────────────────────────────────────│
│                                                        │
│ [✨ Get Emergency Response Plan (~$0.03)]             │
│                                                        │
│ [🎫 Create URGENT Incident] [📋 Copy Details]        │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

### Remediation Groups Page (Action-Based)

```
┌────────────────────────────────────────────────────────────┐
│ Remediation Groups (18 actions)                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ Group by: ● Fixes  ○ Business Impact  ○ Type              │
│ Sort by: [Risk Reduction ▼]                               │
│                                                            │
│ ServiceNow: ✓ Connected to dev12345.service-now.com [⚙️] │
│                                                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌────────────────────────────────────────────────────────┐│
││ 🔑 PRIORITY 1: Remove Hardcoded Secrets    [Expand ▼] ││
│├────────────────────────────────────────────────────────┤│
││                                                        ││
││ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│││ Exposures: 4 ││ │ Risk: -38pts ││ │ Effort: Med  ││   ││
│││              ││ │              ││ │ 8 hours      ││   ││
│││ 4 Secrets    ││ │              ││ │              ││   ││
││└──────────────┘ └──────────────┘ └──────────────┘   ││
││                                                        ││
││ 🔴 CRITICAL: Valid production credentials exposed     ││
││ ⚠️  SLA: All overdue (immediate action required)      ││
││ 🏛️ Compliance: PCI-DSS 3.4, SOX 404, GDPR Art 32     ││
││                                                        ││
││ Affected Locations:                                    ││
││ • config/aws.js (AWS Access Key)                      ││
││ • config/stripe.js (Stripe API Key)                   ││
││ • .env.example (DB Password)                          ││
││ • scripts/deploy.sh (SSH Private Key)                 ││
││                                                        ││
││ Recommended Actions:                                   ││
││ 1. Rotate all credentials immediately                 ││
││ 2. Move to AWS Secrets Manager / HashiCorp Vault     ││
││ 3. Audit access logs for unauthorized use             ││
││ 4. Remove from git history                            ││
││                                                        ││
││ [🤖 Get AI Emergency Plan] [🎫 Create URGENT Ticket]  ││
││                             [📋 Copy Commands]         ││
│└────────────────────────────────────────────────────────┘│
│                                                            │
│ ┌────────────────────────────────────────────────────────┐│
││ 📜 PRIORITY 2: Renew Expiring Certificates [Expand ▼] ││
│├────────────────────────────────────────────────────────┤│
││                                                        ││
││ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│││ Exposures: 8 ││ │ Risk: -67pts ││ │ Effort: Low  ││   ││
│││              ││ │              ││ │ 4 hours      ││   ││
│││ 8 Certs      ││ │              ││ │              ││   ││
││└──────────────┘ └──────────────┘ └──────────────┘   ││
││                                                        ││
││ ⚠️  SLA: 3 certificates expire within 30 days         ││
││ 🏛️ Compliance: PCI-DSS 4.1                            ││
││                                                        ││
││ Certificates:                                          ││
││ • api.example.com (expires in 15 days) 🔴            ││
││ • admin.example.com (expires in 23 days) 🟠          ││
││ • webhooks.example.com (expires in 45 days)          ││
││ • ...and 5 more                                       ││
││                                                        ││
││ [🤖 Get AI Renewal Guide] [🎫 Create Incident]        ││
││                            [📋 Copy Cert List]         ││
│└────────────────────────────────────────────────────────┘│
│                                                            │
│ ┌────────────────────────────────────────────────────────┐│
││ 🔒 PRIORITY 3: Update log4j to 2.17.1      [Expand ▼] ││
│├────────────────────────────────────────────────────────┤│
││                                                        ││
││ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│││ Exposures: 8 ││ │ Risk: -42pts ││ │ Effort: Low  ││   ││
│││              ││ │              ││ │ 2 hours      ││   ││
│││ 8 CVEs       ││ │              ││ │              ││   ││
││└──────────────┘ └──────────────┘ └──────────────┘   ││
││                                                        ││
││ 🚨 4 CVEs in CISA KEV (actively exploited)           ││
││ ⚠️  SLA: 2 overdue, 3 due within 48 hours            ││
││ 🏛️ Compliance: PCI-DSS 6.2, SOX 404, GDPR Art 32     ││
││                                                        ││
││ Affected Components:                                   ││
││ • backend-service                                     ││
││ • logging-service                                     ││
││ • admin-dashboard                                     ││
││                                                        ││
││ [🤖 Get AI Plan] [🎫 Create Incident] [📋 Copy Cmd]   ││
│└────────────────────────────────────────────────────────┘│
│                                                            │
│ ┌────────────────────────────────────────────────────────┐│
││ ⚙️ PRIORITY 4: Secure S3 Bucket Config    [Expand ▼] ││
│├────────────────────────────────────────────────────────┤│
││                                                        ││
││ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│││ Exposures:15 ││ │ Risk: -89pts ││ │ Effort: Low  ││   ││
│││              ││ │              ││ │ 7 hours      ││   ││
│││ 15 Configs   ││ │              ││ │              ││   ││
││└──────────────┘ └──────────────┘ └──────────────┘   ││
││                                                        ││
││ 🟠 High: 5 S3 buckets have public read access        ││
││ 🏛️ Compliance: GDPR Art 32, PCI-DSS 3.4              ││
││                                                        ││
││ Affected Resources:                                    ││
││ • payment-data-backup (public read) 🔴               ││
││ • customer-uploads (public list) 🔴                  ││
││ • application-logs (no encryption) 🟠                ││
││ • ...and 12 more                                      ││
││                                                        ││
││ [🤖 Get AI Fix] [🎫 Create Incident] [📋 Copy TF]     ││
│└────────────────────────────────────────────────────────┘│
│                                                            │
│ ┌────────────────────────────────────────────────────────┐│
││ ⚖️ PRIORITY 5: Resolve License Issues     [Expand ▼] ││
│├────────────────────────────────────────────────────────┤│
││                                                        ││
││ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│││ Exposures:15 ││ │ Risk: -23pts ││ │ Effort: High ││   ││
│││              ││ │              ││ │ 60 hours     ││   ││
│││ 15 Licenses  ││ │              ││ │              ││   ││
││└──────────────┘ └──────────────┘ └──────────────┘   ││
││                                                        ││
││ 🟡 Medium: GPL/AGPL licenses in proprietary code     ││
││ 🏛️ Compliance: Legal - IP Compliance                  ││
││                                                        ││
││ Issues:                                                ││
││ • 3 GPL-3.0 libraries (must remove or open-source)   ││
││ • 2 AGPL-3.0 (network copyleft - critical)           ││
││ • 10 Unknown licenses (legal risk)                    ││
││                                                        ││
││ [🤖 Get Alternatives] [🎫 Create Incident]            ││
│└────────────────────────────────────────────────────────┘│
│                                                            │
│ ... (13 more groups)                                       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Key Features:**
- **Priority ordering** (secrets always first)
- **Visual hierarchy** with consistent card design
- **Exposure counts** by type in each group
- **Risk reduction** shows value of fixing
- **Effort estimates** help with planning
- **SLA urgency** highlighted
- **Expandable cards** show detailed exposure list
- **One-click actions** for AI plans and tickets

---

### Settings Page (ServiceNow Configuration)

```
┌─────────────────────────────────────────────────────┐
│ Settings                                            │
├─────────────────────────────────────────────────────┤
│                                                     │
│ ┌─ RISK SCORING ───────────────────────────────┐  │
│ │                                               │  │
│ │ Default Risk Formula:                         │  │
│ │ ● Concert Formula (Equilibrium-based)         │  │
│ │ ○ Comprehensive Framework (Impact-based)      │  │
│ │                                               │  │
│ │ EPSS Threshold:                               │  │
│ │ [0.1         ](Equilibrium point)            │  │
│ │                                               │  │
│ └───────────────────────────────────────────────┘  │
│                                                     │
│ ┌─ SERVICENOW INTEGRATION ──────────────────────┐  │
│ │                                               │  │
│ │ Status: ✓ Connected to dev12345.service-now  │  │
│ │         .com                                  │  │
│ │                                               │  │
│ │ Instance URL:                                 │  │
│ │ [https://dev12345.service-now.com        ]   │  │
│ │                                               │  │
│ │ Authentication Method:                        │  │
│ │ ● OAuth 2.0  ○ Basic Auth  ○ API Token       │  │
│ │                                               │  │
│ │ Client ID:                                    │  │
│ │ [•••••••••••••••••••••]                      │  │
│ │                                               │  │
│ │ Client Secret:                                │  │
│ │ [••••••••••••••••••••••••]                   │  │
│ │                                               │  │
│ │ Username:                                     │  │
│ │ [concert_integration]                         │  │
│ │                                               │  │
│ │ Password:                                     │  │
│ │ [••••••••••••]                                │  │
│ │                                               │  │
│ │ [Test Connection]         Status: ✓ Success  │  │
│ │                                               │  │
│ │ Default Assignment Group:                     │  │
│ │ [Security Operations           ▼]            │  │
│ │                                               │  │
│ │ Default Category:                             │  │
│ │ [Software                      ▼]            │  │
│ │                                               │  │
│ │ Subcategory:                                  │  │
│ │ [Security Vulnerability        ▼]            │  │
│ │                                               │  │
│ │ Auto-assign Priority:                         │  │
│ │ ✓ Risk 9-10 → Priority 1 (Critical)          │  │
│ │ ✓ Risk 7-8.9 → Priority 2 (High)             │  │
│ │ ✓ Risk 4-6.9 → Priority 3 (Medium)           │  │
│ │ ✓ Risk 0-3.9 → Priority 4 (Low)              │  │
│ │                                               │  │
│ └───────────────────────────────────────────────┘  │
│                                                     │
│ ┌─ SCAN PREFERENCES ────────────────────────────┐  │
│ │                                               │  │
│ │ Auto-scan on push: ○ Enabled  ● Disabled     │  │
│ │ Scan frequency:    [Weekly        ▼]         │  │
│ │ Notify on:         ✓ Critical  ✓ High        │  │
│ │                    □ Medium    □ Low          │  │
│ │                                               │  │
│ └───────────────────────────────────────────────┘  │
│                                                     │
│ [Save Changes]  [Cancel]                            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Core Exposure Scanning (Week 1)

**Goal:** Scan repository and detect all 6 exposure types

**Deliverables:**
- React + Vite + Carbon frontend
- Express backend with TypeScript
- Git clone (public + private repos)
- Language detection
- **CVE scanning:** npm audit, pip-audit
- **Certificate scanning:** X.509 parser
- **Secret scanning:** TruffleHog
- **Misconfiguration scanning:** Checkov (already have)
- **License scanning:** license-checker, pip-licenses
- **Code security:** Semgrep with security rules
- Basic unified exposure list

**Claude Prompt:**

```
Phase 1: Build exposure scanning platform foundation.

ARCHITECTURE:
- Frontend: React + Vite + TypeScript + Carbon Design g100
- Backend: Node.js + Express + TypeScript
- Localhost: Frontend :5173, Backend :3001

CORE REQUIREMENT: Scan for 6 exposure types

1. Frontend Setup:
   - React + Vite project
   - Install @carbon/react, @carbon/icons-react
   - Routes: / (landing), /dashboard, /scan, /exposures, /remediation, /settings
   - Left sidebar navigation with exposure type icons
   - Vite proxy /api → localhost:3001

2. Backend Setup:
   - Express server with TypeScript
   - Routes:
     • POST /api/scan
     • GET /api/scan/:id/status
     • GET /api/scan/:id/results
   
3. Unified Exposure Model:
   ```typescript
   interface Exposure {
     id: string;
     type: 'cve' | 'certificate' | 'secret' | 'misconfiguration' | 'license' | 'code-security';
     title: string;
     description: string;
     severity: 'Critical' | 'High' | 'Medium' | 'Low';
     riskScore: number;
     location: string;
     // Type-specific fields
     cvss?: number;
     epss?: number;
     cisaKEV?: boolean;
     expiresAt?: Date;
     daysUntilExpiration?: number;
     secretType?: string;
     licenseType?: string;
   }
   ```

4. Scanning Pipeline:
   - Clone repo with simple-git
   - Detect languages
   - Run parallel scans:
   
   A) CVE Scanning (existing):
      npm audit, pip-audit → parse JSON
   
   B) Certificate Scanning (NEW):
      - Find files: *.crt, *.pem, *.p12, *.pfx
      - Parse with node-forge (X.509)
      - Calculate days until expiration
      - Flag if <180 days
   
   C) Secret Scanning (NEW):
      - Run: trufflehog filesystem /repo --json --only-verified
      - Parse JSON output
      - Map to exposure model
   
   D) Misconfiguration (enhance Checkov):
      - Run: checkov -d /repo --output json
      - Categorize as "misconfiguration" exposure
   
   E) License Scanning (NEW):
      - Run: license-checker --json --production (npm)
      - Run: pip-licenses --format=json (Python)
      - Flag GPL/AGPL/Unknown licenses
   
   F) Code Security (enhance Semgrep):
      - Run: semgrep --config=auto --json /repo
      - Filter for security findings
      - Categorize as "code-security" exposure

5. Scan Page (6-step wizard):
   Step 1: Repository (URL, public/private, PAT, branch)
   Step 2: Basic Info (name, industry, purpose)
   Step 3: Criticality (1-5 with examples)
   Step 4: Data Sensitivity (PII/PHI/PCI checkboxes → auto-suggest)
   Step 5: Access & Controls (public/private counts, exposure, controls)
   Step 6: Formula (Concert / Comprehensive)
   
   Submit → POST /api/scan → Loading → Navigate to /dashboard

6. Exposure List Page:
   - Carbon DataTable
   - Columns: Risk, Type (with icon), Title, Severity, Location
   - Type filter dropdown with counts
   - Severity filter
   - Click row → Modal with type-specific details

INSTALL:
Backend: simple-git, bottleneck, node-forge, axios
Frontend: @carbon/react, react-router-dom

Provide:
1. Complete directory structure
2. All package.json files
3. Full implementation
4. .env.example
5. Run instructions

Focus on unified exposure model - all scanners output to same interface.
```

---

### Phase 2: Risk Scoring & Dashboard (Week 2)

**Goal:** Calculate type-specific risk scores and build intuitive dashboard

**Deliverables:**
- Type-specific risk formulas
- CVE enrichment (NVD, EPSS, KEV)
- Dashboard with 6-dimension radial chart
- Exposure type breakdown
- Metric tiles with hover tooltips
- Exposure detail modals (type-specific)

**Claude Prompt:**

```
Phase 2: Risk scoring and visualization dashboard.

CONTEXT: Phase 1 complete - have unified exposure scanning.

REQUIREMENTS:

1. Risk Scoring Service (/backend/src/services/riskScoring.ts):
   
   Main function:
   ```typescript
   export function calculateExposureRisk(
     exposure: Exposure,
     context: ApplicationContext
   ): number {
     switch (exposure.type) {
       case 'cve':
         return calculateCVERisk(exposure, context);
       case 'certificate':
         return calculateCertificateRisk(exposure, context);
       case 'secret':
         return calculateSecretRisk(exposure, context);
       case 'misconfiguration':
         return calculateMisconfigurationRisk(exposure, context);
       case 'license':
         return calculateLicenseRisk(exposure, context);
       case 'code-security':
         return calculateCodeSecurityRisk(exposure, context);
     }
   }
   ```
   
   A) CVE Risk (Concert formula):
      - Query NVD for CVSS
      - Query EPSS for exploitation probability
      - Check CISA KEV
      - Formula: CVSS × Exploitability(EPSS) × Environmental
   
   B) Certificate Risk:
      ```typescript
      let severity = daysUntilExpiration <= 0 ? 10.0 :
                     daysUntilExpiration <= 7 ? 9.0 :
                     daysUntilExpiration <= 30 ? 8.0 :
                     daysUntilExpiration <= 90 ? 6.0 : 3.0;
      
      envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;
      publicFactor = isPublicFacing ? 1.1 : 1.0;
      
      return severity × envFactor × publicFactor;
      ```
   
   C) Secret Risk:
      ```typescript
      severity = { 'AWS': 9.5, 'API Key': 9.0, 'Password': 8.5 }[type];
      exploitability = 1.25; // Always max
      envFactor = (appCriticality + dataSensitivity + accessPoints) / 3;
      gitFactor = inGitHistory ? 1.2 : 1.0;
      
      return severity × exploitability × envFactor × gitFactor;
      ```
   
   D) Misconfiguration Risk:
      Use scanner severity + environment factor + public accessibility
   
   E) License Risk:
      { 'GPL-3.0': 7.0, 'MIT': 1.0 }[type] × commercialUse factor
   
   F) Code Security Risk:
      Use SAST severity + exploitability by type + location factor

2. Dashboard Visualization:
   
   Use @carbon/charts-react or recharts
   
   A) Radial Chart (6 dimensions):
      - Center: Overall risk score (76.3/100)
      - Segments: CVEs, Certificates, Secrets, Configs, Licenses, Code
      - Color: Green → Yellow → Red gradient
      - Red outline if segment avg risk > 7.0
   
   B) Exposure Breakdown Tile:
      ```
      Total Exposures: 243
      🔒 CVEs: 167
      📜 Certificates: 8
      🔑 Secrets: 4
      ⚙️ Misconfigurations: 42
      ⚖️ Licenses: 15
      💻 Code Security: 7
      ```
   
   C) Severity Distribution (horizontal bar chart):
      Critical (18) | High (67) | Medium (124) | Low (34)
   
   D) CISA KEV Tile:
      "8 actively exploited vulnerabilities"
   
   E) SLA Status Tile:
      🔴 5 Overdue | 🟠 12 Due Soon | 🟢 226 On Track

3. Exposure Detail Modals:
   
   Create 6 modal variants with shared structure:
   - Top row: 4 metric cards (risk, type-specific metrics)
   - Description
   - Application context section
   - Compliance impact
   - Remediation guidance
   - SLA deadline
   - [Get AI Explanation] button (placeholder for Phase 3)
   
   Type-specific sections:
   - CVE: CVSS, EPSS, KEV badge, references
   - Certificate: Expires, issuer, algorithm, domain
   - Secret: Secret type, location, verified status
   - Misconfiguration: Resource type, public accessibility
   - License: License type, package, legal implications
   - Code: Issue type, code snippet, file location

4. Exposure List Enhancements:
   - Add Type column with icons
   - Type filter dropdown with counts per type
   - Search across title + description
   - Sort by risk score (default)
   - Click row → Open type-specific modal

OUTPUT FORMAT:
Backend returns:
```json
{
  scanId,
  metadata: { repo, branch, context },
  summary: {
    totalExposures, critical, high, medium, low,
    overallRisk: 76.3,
    byType: {
      cve: 167, certificate: 8, secret: 4,
      misconfiguration: 42, license: 15, codeSecurity: 7
    },
    cisaKEVCount: 8
  },
  exposures: [
    {
      id, type, title, severity, riskScore,
      location, description, remediation,
      // type-specific fields
    }
  ]
}
```

TECH:
- Backend: Add bottleneck (rate limiting), axios
- Frontend: Add @carbon/charts-react or recharts
- Use Carbon Tile, Modal, DataTable components

Provide complete implementation with beautiful dashboard.
```

---

### Phase 3: AI & ServiceNow (Week 3)

**Goal:** Gemini explanations, remediation grouping, ServiceNow integration

**Deliverables:**
- Type-specific AI prompts for all 6 exposure types
- Remediation grouping (mixed exposure types)
- ServiceNow configuration UI
- Incident creation

**Claude Prompt:**

```
Phase 3: AI integration and remediation automation.

CONTEXT: Phase 2 complete - have risk scoring and dashboard.

REQUIREMENTS:

1. Gemini Integration for All Exposure Types:
   
   Backend: POST /api/ai/explain
   
   Request:
   ```typescript
   {
     exposureId: string,
     exposureData: Exposure,
     applicationContext: ApplicationContext,
     codeSnippet?: string
   }
   ```
   
   Build type-specific prompts:
   
   A) CVE Prompt (existing - enhance):
      Include EPSS, KEV status, application context
   
   B) Certificate Prompt:
      ```
      You are helping with certificate management.
      
      CERTIFICATE:
      - Domain: ${domain}
      - Expires: ${expiresAt}
      - Days Remaining: ${days}
      - Application: ${criticality} ${industry}
      
      Provide:
      1. Impact if expired (2-3 sentences for THIS app)
      2. Step-by-step renewal (Let's Encrypt / commercial CA)
      3. Installation instructions
      4. Verification steps
      5. Automation setup (certbot, cert-manager)
      
      Format: markdown with code snippets
      ```
   
   C) Secret Prompt:
      ```
      CRITICAL: Hardcoded credential removal.
      
      SECRET:
      - Type: ${secretType}
      - Location: ${location}
      - Verified: ${verified}
      - In Git History: ${inGitHistory}
      
      IMMEDIATE STEPS:
      1. Rotate credential NOW (specific service)
      2. Audit access logs
      3. Move to secure storage (AWS Secrets Manager, Vault)
      4. Remove from git history (git filter-branch commands)
      5. Prevent future occurrences (pre-commit hooks)
      
      Include actual commands.
      ```
   
   D) Misconfiguration Prompt:
      ```
      Infrastructure security issue.
      
      MISCONFIGURATION:
      - Resource: ${resourceType}
      - Issue: ${description}
      - Public: ${isPublic}
      
      Provide:
      1. Security implications
      2. Terraform/CloudFormation fix
      3. Verification commands
      4. Best practices to prevent
      ```
   
   E) License Prompt:
      ```
      License compliance issue.
      
      LICENSE:
      - Package: ${package}
      - License: ${licenseType}
      - Usage: ${commercialUse ? 'Commercial' : 'Internal'}
      
      Provide:
      1. Legal implications
      2. Compatible alternatives (with similar functionality)
      3. Migration guide if needed
      4. License audit process
      ```
   
   F) Code Security Prompt:
      ```
      Code vulnerability detected.
      
      ISSUE:
      - Type: ${issueType} (e.g., SQL Injection)
      - Location: ${location}
      - Code: ${codeSnippet}
      
      Provide:
      1. Vulnerability explanation
      2. Exploit scenario
      3. Fixed code (secure version)
      4. Testing approach
      5. Similar patterns to check
      ```

2. Remediation Grouping (Mixed Exposure Types):
   
   Create /backend/src/services/exposureGrouper.ts
   
   ```typescript
   export function groupExposures(exposures: Exposure[]): RemediationGroup[] {
     const groups = [];
     
     // Group 1: PRIORITY - Secrets (always first)
     const secrets = exposures.filter(e => e.type === 'secret');
     if (secrets.length > 0) {
       groups.push({
         id: 'secrets-removal',
         type: 'secret',
         priority: 100, // Highest
         title: 'Remove Hardcoded Secrets',
         exposuresFixed: secrets.length,
         riskReduction: sum(secrets, 'riskScore'),
         effort: 'Medium',
         effortHours: secrets.length * 2,
         slaStatus: { overdue: secrets.length, dueSoon: 0, onTrack: 0 },
         exposures: secrets
       });
     }
     
     // Group 2: Certificates by renewal
     const certs = exposures.filter(e => e.type === 'certificate');
     if (certs.length > 0) {
       groups.push({
         type: 'certificate',
         title: 'Renew Expiring Certificates',
         exposuresFixed: certs.length,
         effort: 'Low',
         effortHours: certs.length * 0.5
       });
     }
     
     // Group 3: CVEs by package update
     const cveGroups = groupCVEsByPackage(exposures.filter(e => e.type === 'cve'));
     groups.push(...cveGroups);
     
     // Group 4: Misconfigurations by resource type
     const configGroups = groupByResourceType(exposures.filter(e => e.type === 'misconfiguration'));
     groups.push(...configGroups);
     
     // Group 5: Licenses
     const licenses = exposures.filter(e => e.type === 'license');
     if (licenses.length > 0) {
       groups.push({
         type: 'license',
         title: 'Resolve License Compliance Issues',
         effort: 'High',
         effortHours: licenses.length * 4
       });
     }
     
     // Group 6: Code security by file
     const codeGroups = groupCodeIssuesByFile(exposures.filter(e => e.type === 'code-security'));
     groups.push(...codeGroups);
     
     return groups.sort((a, b) => b.priority - a.priority);
   }
   ```

3. Remediation Tab UI:
   - Priority 1 cards always show secrets first (red border)
   - Each card shows exposure type mix
   - Example: "Update log4j (8 CVEs)" separate from "Renew certificates (8 certs)"
   - Expandable to show individual exposures
   - Buttons: [🤖 AI Plan] [🎫 Incident] [📋 Copy]

4. ServiceNow Integration:
   - Settings page (from previous design)
   - Test connection
   - Create incident with exposure group details
   - Include all exposure types in description

TECH:
- Install: @google/generative-ai, crypto-js, react-markdown, react-syntax-highlighter
- Environment: GEMINI_API_KEY

Provide complete implementation for all exposure types.
```

---

### Phase 4: Compliance, Financial, SLA (Week 4)

**Goal:** Enterprise features across all exposure types

**Deliverables:**
- Compliance mapping (exposures → standards)
- Financial impact calculator
- SLA tracking per exposure type
- Dashboard widgets

**Claude Prompt:**

```
Phase 4: Enterprise features - compliance, financial, SLA.

CONTEXT: Phase 3 complete - have AI and ServiceNow.

REQUIREMENTS:

1. Compliance Mapping (All Exposure Types):
   
   Create /backend/src/services/complianceMapper.ts
   
   ```typescript
   export function mapExposureToCompliance(
     exposure: Exposure,
     context: ApplicationContext
   ): string[] {
     const impacts = [];
     
     // PCI-DSS mapping
     if (context.dataSensitivity.includesPCI) {
       if (exposure.type === 'cve') {
         impacts.push('PCI-DSS 6.2 - Vulnerability Management');
       }
       if (exposure.type === 'certificate') {
         impacts.push('PCI-DSS 4.1 - Secure Transmissions');
       }
       if (exposure.type === 'secret') {
         impacts.push('PCI-DSS 3.4 - Render PAN Unreadable');
       }
       if (exposure.type === 'misconfiguration') {
         impacts.push('PCI-DSS 2.2 - Secure Configurations');
       }
     }
     
     // HIPAA mapping
     if (context.dataSensitivity.includesPHI) {
       if (exposure.type === 'secret' || exposure.type === 'misconfiguration') {
         impacts.push('HIPAA 164.312(a)(2)(iv) - Encryption');
       }
     }
     
     // SOX mapping
     if (context.isPubliclyTraded) {
       impacts.push('SOX Section 404 - IT General Controls');
     }
     
     // GDPR mapping
     if (context.dataSensitivity.includesPII) {
       impacts.push('GDPR Article 32 - Security of Processing');
     }
     
     // License-specific
     if (exposure.type === 'license') {
       impacts.push('Legal - Intellectual Property Compliance');
     }
     
     return impacts;
   }
   ```
   
   Dashboard compliance widget shows counts per standard

2. Financial Impact Calculator:
   
   ```typescript
   export function calculateFinancialImpact(
     exposures: Exposure[],
     context: ApplicationContext
   ): FinancialImpact {
     // Different calculations per exposure type
     
     // CVEs: Traditional breach cost
     const cves = exposures.filter(e => e.type === 'cve');
     const criticalCVEs = cves.filter(e => e.riskScore >= 9.0).length;
     const breachCost = criticalCVEs * 0.15 * 4.88; // Million USD
     
     // Certificates: Downtime cost
     const certs = exposures.filter(e => e.type === 'certificate');
     const expiringCerts = certs.filter(c => c.daysUntilExpiration <= 30).length;
     const downtimeCost = expiringCerts * hourlyRevenue * 24 * 0.10;
     
     // Secrets: High breach probability
     const secrets = exposures.filter(e => e.type === 'secret');
     const secretBreachCost = secrets.length * 0.95 * 4.88; // 95% breach chance
     
     // Misconfigurations: Data exposure cost
     const configs = exposures.filter(e => e.type === 'misconfiguration');
     const publicConfigs = configs.filter(c => c.isPubliclyAccessible).length;
     const configCost = publicConfigs * 0.30 * 4.88;
     
     // Licenses: Legal fees
     const licenses = exposures.filter(e => e.type === 'license');
     const gplViolations = licenses.filter(l => l.licenseType.includes('GPL')).length;
     const legalCost = gplViolations * 0.5; // $500K per violation
     
     // Regulatory fines
     let regulatoryFines = 0;
     if (context.hasPCI) regulatoryFines += 0.5;
     if (context.hasPHI) regulatoryFines += 1.5;
     if (context.hasGDPR) regulatoryFines += 2.0;
     
     // Remediation cost
     const totalEffort = calculateTotalEffortHours(exposures);
     const remediationCost = (totalEffort * 150) / 1000000;
     
     const totalRisk = breachCost + downtimeCost + secretBreachCost + 
                       configCost + legalCost + regulatoryFines;
     
     return {
       potentialBreachCost: breachCost.toFixed(1),
       downtimeCost: downtimeCost.toFixed(1),
       secretBreachCost: secretBreachCost.toFixed(1),
       configurationRisk: configCost.toFixed(1),
       legalFees: legalCost.toFixed(1),
       regulatoryFineRisk: regulatoryFines.toFixed(1),
       totalRisk: totalRisk.toFixed(1),
       remediationCost: remediationCost.toFixed(2),
       roi: (totalRisk / remediationCost).toFixed(0)
     };
   }
   ```

3. SLA Tracking (Per Exposure Type):
   
   ```typescript
   export function calculateSLADeadline(
     exposure: Exposure,
     context: ApplicationContext
   ): Date {
     // Different SLA matrices per type
     
     if (exposure.type === 'secret') {
       // Secrets are ALWAYS immediate
       return new Date(); // 0 days
     }
     
     if (exposure.type === 'certificate') {
       // Based on days until expiration
       if (exposure.daysUntilExpiration <= 7) return addDays(new Date(), 1);
       if (exposure.daysUntilExpiration <= 30) return addDays(new Date(), 7);
       return addDays(new Date(), 30);
     }
     
     // For CVEs, misconfigs, code issues: Use risk-based SLA matrix
     const tier = context.criticality;
     const riskScore = exposure.riskScore;
     
     let days;
     if (riskScore >= 9.0) {
       days = tier <= 2 ? 2 : tier === 3 ? 7 : 14;
     } else if (riskScore >= 7.0) {
       days = tier <= 2 ? 7 : tier === 3 ? 14 : 30;
     } else if (riskScore >= 4.0) {
       days = tier <= 2 ? 30 : tier === 3 ? 45 : 60;
     } else {
       days = tier <= 2 ? 60 : 90;
     }
     
     // Licenses: Longer timeline (legal process)
     if (exposure.type === 'license') {
       days = riskScore >= 7.0 ? 60 : 90;
     }
     
     return addDays(exposure.detectedAt, days);
   }
   ```

4. Dashboard Integration:
   - Compliance widget shows exposure counts per standard
   - Financial widget breaks down by exposure type
   - SLA widget groups by exposure type

Provide complete implementation.
```

---

### Phase 5: Demo Mode & Polish (Week 5)

**Goal:** Demo mode with realistic multi-type exposures, final UI polish

**Deliverables:**
- Demo data with all 6 exposure types
- Error handling
- Loading states
- UI polish
- README

**Claude Prompt:**

```
Phase 5: Demo mode and final polish.

REQUIREMENTS:

1. Demo Data (/frontend/src/data/demoData.ts):
   
   Pre-load realistic exposures:
   ```typescript
   export const DEMO_DATA = {
     metadata: {
       scanId: 'demo-001',
       repository: 'acme-corp/payment-processing-api',
       applicationContext: {
         name: 'Payment Processing API',
         industry: 'Financial Services',
         criticality: 4,
         dataSensitivity: 4,
         hasPCI: true
       }
     },
     summary: {
       totalExposures: 243,
       critical: 18,
       high: 67,
       medium: 124,
       low: 34,
       overallRisk: 76.3,
       byType: {
         cve: 167,
         certificate: 8,
         secret: 4,
         misconfiguration: 42,
         license: 15,
         codeSecurity: 7
       },
       cisaKEVCount: 8
     },
     exposures: [
       // 8 critical CVEs (4 with CISA KEV)
       {
         type: 'cve',
         title: 'CVE-2021-44228 (Log4Shell)',
         severity: 'Critical',
         riskScore: 9.8,
         cvss: 10.0,
         epss: 0.892,
         cisaKEV: true,
         component: 'log4j-core@2.14.1'
       },
       // 4 secrets (all critical)
       {
         type: 'secret',
         title: 'Hardcoded AWS Access Key',
         severity: 'Critical',
         riskScore: 9.5,
         secretType: 'AWS',
         verified: true,
         location: 'config/aws.js:12'
       },
       // 8 certificates (3 expire soon)
       {
         type: 'certificate',
         title: 'api.example.com',
         severity: 'High',
         riskScore: 8.2,
         daysUntilExpiration: 15,
         expiresAt: '2026-01-31'
       },
       // 42 misconfigurations
       {
         type: 'misconfiguration',
         title: 'Public S3 Bucket',
         severity: 'High',
         riskScore: 8.7,
         resourceType: 'S3 Bucket',
         location: 'terraform/s3.tf:15'
       },
       // 15 license issues
       {
         type: 'license',
         title: 'GPL-3.0 Violation',
         severity: 'Medium',
         riskScore: 6.5,
         licenseType: 'GPL-3.0',
         packageName: 'some-gpl-library@1.2.3'
       },
       // 7 code security issues
       {
         type: 'code-security',
         title: 'SQL Injection',
         severity: 'High',
         riskScore: 8.1,
         location: 'api/users.js:45'
       }
       // ... total 243 exposures
     ],
     remediationGroups: [
       {
         title: 'Remove Hardcoded Secrets',
         type: 'secret',
         exposuresFixed: 4,
         riskReduction: 38.0,
         effort: 'Medium',
         priority: 100
       },
       {
         title: 'Renew Expiring Certificates',
         type: 'certificate',
         exposuresFixed: 8,
         riskReduction: 67.0,
         effort: 'Low'
       },
       {
         title: 'Update log4j to 2.17.1',
         type: 'cve',
         exposuresFixed: 8,
         riskReduction: 42.1,
         effort: 'Low'
       }
       // ... 18 total groups
     ],
     financialImpact: {
       totalRisk: 12.1,
       breachCost: 8.8,
       downtimeCost: 2.1,
       secretRisk: 4.6,
       regulatoryFines: 1.2,
       remediationCost: 0.051,
       roi: 237
     }
   };
   ```

2. Landing Page Enhancement:
   - Two large tiles: [Try Demo Mode] [Scan Repository]
   - Show demo stats
   - Icon grid for 6 exposure types
   - Professional hero section

3. Error Handling:
   - Git clone failures (auth, network)
   - Scanner failures (missing tools)
   - API rate limits
   - Gemini errors
   - ServiceNow errors
   - Use Carbon ToastNotification

4. Loading States:
   - Multi-step progress: "Cloning..." → "Scanning CVEs..." → "Scanning Secrets..." → etc.
   - Skeleton loaders in tables
   - Spinners in modals
   - Use Carbon Loading components

5. UI Polish:
   - Consistent spacing (Carbon tokens)
   - Hover states on all cards/buttons
   - Smooth transitions
   - Empty states with helpful messages
   - Tooltips on all info icons
   - Color-coded by exposure type
   - Responsive at 1280px+

6. README.md:
   Complete setup guide with:
   - Feature list (6 exposure types)
   - Prerequisites (Node, Python, scanning tools)
   - Installation steps
   - Run instructions
   - Tool installation (TruffleHog, etc.)
   - Troubleshooting

7. Test Repository:
   Create "vulnerable-test-app" with:
   - Vulnerable dependencies (log4j, etc.)
   - Expired certificate file
   - Hardcoded AWS key in code
   - Public S3 bucket in Terraform
   - GPL library in package.json
   - SQL injection in code

Provide complete implementation. Ensure demo-ready POC.
```

---

## Technical Specifications

### Frontend Dependencies

```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.1",
    "@carbon/react": "^1.46.0",
    "@carbon/icons-react": "^11.30.0",
    "@carbon/charts-react": "^1.15.4",
    "axios": "^1.6.2",
    "crypto-js": "^4.2.0",
    "recharts": "^2.10.3",
    "react-markdown": "^9.0.1",
    "react-syntax-highlighter": "^15.5.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "typescript": "^5.3.3",
    "vite": "^5.0.8"
  }
}
```

### Backend Dependencies

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "axios": "^1.6.2",
    "bottleneck": "^2.19.5",
    "@google/generative-ai": "^0.1.1",
    "simple-git": "^3.21.0",
    "node-forge": "^1.3.1",
    "x509": "^1.0.0"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/node": "^20.10.5",
    "typescript": "^5.3.3",
    "tsx": "^4.7.0",
    "nodemon": "^3.0.2"
  }
}
```

### External Scanning Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **npm / pip** | Package managers | Included |
| **npm audit** | JavaScript CVEs | Built-in |
| **pip-audit** | Python CVEs | `pip install pip-audit` |
| **Semgrep** | SAST | `pip install semgrep` |
| **TruffleHog** | Secret scanning | `pip install trufflehog` |
| **Checkov** | IaC scanning | `pip install checkov` |
| **tfsec** | Terraform scanning | https://github.com/aquasecurity/tfsec |
| **kubesec** | Kubernetes scanning | https://github.com/controlplaneio/kubesec |
| **Trivy** | Container scanning | https://aquasecurity.github.io/trivy/ |
| **license-checker** | npm licenses | `npm install -g license-checker` |
| **pip-licenses** | Python licenses | `pip install pip-licenses` |

---

## Summary

**Timeline:** 5 weeks (50-60 hours)

**Result:** Production-quality Exposure Management Platform with:
- ✅ 6 exposure types (CVEs, Certificates, Secrets, Misconfigurations, Licenses, Code Security)
- ✅ Unified risk scoring across all types
- ✅ Beautiful, intuitive Carbon Design UI
- ✅ Type-specific AI explanations
- ✅ Smart remediation grouping
- ✅ ServiceNow integration
- ✅ Compliance mapping
- ✅ Financial impact analysis
- ✅ SLA tracking
- ✅ Demo mode

**Key Differentiators from CVE-Only:**
- **Comprehensive Coverage**: Finds 60%+ more security issues than CVE scanning alone
- **Prioritized by Type**: Secrets always surface first (critical), then certificates (downtime), then CVEs
- **Unified View**: One dashboard for all security/compliance exposures
- **Context-Aware**: Different risk formulas optimized per exposure type
- **Action-Oriented**: Groups mixed exposure types into coherent remediation actions

This is true **Exposure Management** - exactly what IBM Concert delivers.
