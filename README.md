# Riskanator

**CVE Prioritization & Remediation Platform**

A localhost web application that scans git repositories for vulnerabilities, applies contextualized risk scoring, and provides actionable remediation guidance.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Risk Scoring](#risk-scoring)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Demo Mode](#demo-mode)
- [Testing](#testing)
- [Roadmap](#roadmap)

---

## Overview

Riskanator is a security vulnerability management platform that goes beyond simple CVE detection. It combines multiple scanning technologies with business context to provide **prioritized, actionable vulnerability intelligence**.

### The Problem

Traditional vulnerability scanners produce overwhelming lists of CVEs without context. Security teams struggle to answer:
- Which vulnerabilities should we fix first?
- What's the actual risk to our specific application?
- How do these CVEs impact our compliance requirements?
- What's the business cost of not fixing these?

### The Solution

Riskanator addresses these challenges by:
1. **Contextualizing risk** - Applying business context (criticality, data sensitivity, exposure) to raw CVE data
2. **Enriching data** - Augmenting findings with EPSS exploitation probability and CISA KEV status
3. **Prioritizing intelligently** - Using dual risk scoring formulas to rank vulnerabilities
4. **Grouping remediation** - Clustering CVEs by common fixes to maximize efficiency
5. **Tracking compliance** - Mapping vulnerabilities to PCI-DSS, HIPAA, SOX, and GDPR requirements

---

## Key Features

### Multi-Language Vulnerability Scanning

| Scan Type | Tool | Coverage |
|-----------|------|----------|
| **SCA** (Dependencies) | npm audit, pip-audit | JavaScript, Python, Java, Ruby, Go, .NET |
| **SAST** (Code) | Semgrep | Multi-language static analysis |
| **Container** | Trivy | Docker images and filesystems |
| **IaC** | Checkov, tfsec | Terraform, CloudFormation, Kubernetes |

### Dual Risk Scoring

**Concert Formula** (Scale: 0-10)
```
Risk = CVSS × Exploitability(EPSS) × Environmental(Context)
```

**Comprehensive Formula** (Scale: 0-1000)
```
Risk = Likelihood × Impact × Exposure × (1-Controls) × 1000
```

### CVE Enrichment

- **NVD** - CVSS scores, descriptions, references
- **FIRST.org EPSS** - Exploitation probability percentages
- **CISA KEV** - Known Exploited Vulnerabilities catalog

### Business Intelligence

- **Compliance Mapping** - Auto-maps CVEs to PCI-DSS, HIPAA, SOX, GDPR
- **Financial Impact** - Calculates breach costs, downtime, regulatory fines, ROI
- **SLA Tracking** - Risk-based remediation deadlines with compliance monitoring

### Remediation Grouping

Groups vulnerabilities by common fix to maximize efficiency:
- Dependency updates (e.g., "Update lodash to 4.17.21" fixes 5 CVEs)
- Code fixes grouped by file and vulnerability type
- Container base image updates
- IaC configuration changes

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (Port 5173)                      │
│              React + Vite + Carbon Design System             │
│                                                              │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│   │ Dashboard│ │Scan Setup│ │ CVE List │ │Remediate │      │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP/REST
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (Port 3001)                       │
│                    Node.js + Express                         │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    API Routes                        │   │
│   │  POST /api/scan    GET /api/scan/:id/status         │   │
│   │  GET /api/scan/:id/results    GET /api/scans        │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    Services                          │   │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│   │  │   Git   │ │ Scanner │ │Enricher │ │  Risk   │   │   │
│   │  │ Service │ │ Service │ │ Service │ │ Calc    │   │   │
│   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   EXTERNAL SERVICES                          │
│                                                              │
│   ┌─────┐ ┌──────┐ ┌──────────┐ ┌────────┐ ┌─────────┐    │
│   │ NVD │ │ EPSS │ │ CISA KEV │ │ GitHub │ │ GitLab  │    │
│   └─────┘ └──────┘ └──────────┘ └────────┘ └─────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
1. User submits repository URL + application context
2. Backend clones repository (supports public + private with PAT)
3. Language detection identifies project technologies
4. Parallel scanning with npm audit, pip-audit, Semgrep, Trivy
5. CVE enrichment from NVD, EPSS, CISA KEV
6. Risk calculation using selected formula + context
7. SLA assignment based on risk score + asset criticality
8. Remediation grouping by common fix
9. Results displayed in dashboard with charts and tables
```

---

## Tech Stack

### Frontend
- **React 18** - UI framework
- **Vite 5** - Build tool and dev server
- **TypeScript** - Type safety
- **Carbon Design System** - IBM's design system (g100 dark theme)
- **Recharts** - Data visualization
- **React Router** - Client-side routing
- **Axios** - HTTP client

### Backend
- **Node.js** - Runtime
- **Express 4** - Web framework
- **TypeScript** - Type safety
- **simple-git** - Git operations
- **Bottleneck** - Rate limiting for external APIs
- **Axios** - HTTP client for API calls

### External Tools (Optional)
- **npm** - JavaScript dependency scanning (included with Node.js)
- **pip-audit** - Python dependency scanning
- **Semgrep** - Static code analysis
- **Trivy** - Container vulnerability scanning

---

## Installation

### Prerequisites

- Node.js 18+
- npm or yarn
- Git

### Optional (for full scanning capabilities)
```bash
# Python dependency scanning
pip install pip-audit

# Static code analysis
pip install semgrep

# Container scanning (see https://aquasecurity.github.io/trivy/)
brew install trivy  # macOS
```

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/divvi12/Riskanator.git
cd Riskanator
```

2. **Install backend dependencies**
```bash
cd backend
npm install
cp .env.example .env
```

3. **Install frontend dependencies**
```bash
cd ../frontend
npm install
```

4. **Start the application**

Terminal 1 (Backend):
```bash
cd backend
npm run dev
```

Terminal 2 (Frontend):
```bash
cd frontend
npm run dev
```

5. **Open the application**
```
http://localhost:5173
```

---

## Usage

### Quick Start - Demo Mode

1. Open http://localhost:5173
2. Click **"Try Demo Mode"**
3. Explore the dashboard with pre-loaded data:
   - 167 CVEs (12 critical, 45 high, 87 medium, 23 low)
   - 8 CISA KEV vulnerabilities
   - Financial impact analysis
   - Compliance mapping
   - SLA tracking

### Scanning a Repository

1. Click **"Scan Repository"**
2. Complete the 6-step wizard:

| Step | Information |
|------|-------------|
| 1. Repository | URL, public/private, PAT (if private), branch |
| 2. Basic Info | Application name, industry, purpose |
| 3. Criticality | Business tier (1-5 scale) |
| 4. Data Sensitivity | PII, PHI, PCI, Trade Secrets |
| 5. Access & Controls | Endpoints, network exposure, security controls |
| 6. Formula | Concert (0-10) or Comprehensive (0-1000) |

3. Wait for scan to complete
4. Review results on the dashboard

### Understanding Results

**Dashboard**
- Severity distribution chart
- Risk score (Concert or Comprehensive)
- CISA KEV count (known exploited vulnerabilities)
- Financial impact (if in demo mode)
- SLA status overview

**CVE List**
- Filter by severity, source type, KEV status
- Search by CVE ID, component, or description
- Click any row for detailed view with fix information

**Remediation**
- Groups sorted by risk reduction potential
- Effort estimates (Low/Medium/High)
- SLA status per group
- Copy fix commands directly

---

## Risk Scoring

### Concert Formula

Designed for quick prioritization on a familiar 0-10 scale.

```
Risk = CVSS × Exploitability × Environmental
```

**Components:**
- **CVSS** - Base vulnerability score (0-10)
- **Exploitability** - Based on EPSS probability + KEV status (1.0-2.0)
- **Environmental** - Based on criticality, data sensitivity, exposure, controls (0.5-1.5)

**Example:**
```
CVE-2021-44228 (Log4Shell)
- CVSS: 10.0
- EPSS: 97.5% → Exploitability: 1.975
- Tier 5 app, PCI data, public → Environmental: 1.4
- Risk = 10.0 × (1.975/2) × 1.4 = 9.83
```

### Comprehensive Formula

Designed for detailed analysis on a 0-1000 scale.

```
Risk = Likelihood × Impact × Exposure × (1-Controls) × 1000
```

**Components:**
- **Likelihood** - EPSS-based probability + KEV boost (0.1-1.0)
- **Impact** - CVSS-derived business impact (0.1-1.0)
- **Exposure** - Criticality + network exposure + data sensitivity (0.1-1.0)
- **Controls** - Reduction from security measures (0.2-1.0)

---

## Project Structure

```
Riskanator/
├── backend/
│   ├── src/
│   │   ├── index.ts              # Express server entry point
│   │   ├── routes/
│   │   │   └── scanRoutes.ts     # API route handlers
│   │   ├── services/
│   │   │   ├── gitService.ts     # Repository cloning
│   │   │   ├── scannerService.ts # Vulnerability scanning
│   │   │   ├── cveEnrichmentService.ts  # NVD/EPSS/KEV
│   │   │   └── riskCalculatorService.ts # Risk scoring
│   │   └── types/
│   │       └── index.ts          # TypeScript interfaces
│   ├── package.json
│   ├── tsconfig.json
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx              # React entry point
│   │   ├── App.tsx               # Root component + routing
│   │   ├── components/
│   │   │   └── Layout.tsx        # App shell with sidebar
│   │   ├── pages/
│   │   │   ├── LandingPage.tsx   # Welcome screen
│   │   │   ├── Dashboard.tsx     # Main dashboard
│   │   │   ├── ScanSetup.tsx     # 6-step wizard
│   │   │   ├── CVEList.tsx       # Vulnerability table
│   │   │   ├── Remediation.tsx   # Fix groups
│   │   │   └── Settings.tsx      # Configuration
│   │   ├── services/
│   │   │   └── api.ts            # Backend API client
│   │   ├── data/
│   │   │   └── demoData.ts       # Demo mode data
│   │   ├── types/
│   │   │   └── index.ts          # TypeScript interfaces
│   │   └── styles/
│   │       └── index.scss        # Global styles + Carbon
│   ├── package.json
│   ├── vite.config.ts
│   └── index.html
│
└── README.md
```

---

## API Reference

### Endpoints

#### POST /api/scan
Start a new vulnerability scan.

**Request:**
```json
{
  "repoUrl": "https://github.com/owner/repo",
  "isPrivate": false,
  "pat": "ghp_xxx",  // Optional, for private repos
  "branch": "main",
  "context": {
    "appName": "My Application",
    "industry": "financial",
    "purpose": "Payment processing",
    "criticality": 5,
    "dataSensitivity": {
      "pii": true,
      "phi": false,
      "pci": true,
      "tradeSecrets": false
    },
    "accessControls": {
      "publicEndpoints": 10,
      "privateEndpoints": 50,
      "networkExposure": "public",
      "controls": ["waf", "mfa", "encryption"]
    },
    "formula": "concert"
  }
}
```

**Response:**
```json
{
  "scanId": "uuid-here",
  "status": "pending"
}
```

#### GET /api/scan/:scanId/status
Check scan progress.

**Response:**
```json
{
  "scanId": "uuid-here",
  "status": "scanning",
  "progress": 45,
  "progressMessage": "Running npm audit..."
}
```

#### GET /api/scan/:scanId/results
Get complete scan results.

**Response:**
```json
{
  "scanId": "uuid-here",
  "status": "complete",
  "metadata": {
    "repoUrl": "https://github.com/owner/repo",
    "branch": "main",
    "languages": ["javascript", "python"],
    "scanTypes": ["sca", "sast"],
    "startTime": "2024-01-15T10:00:00Z",
    "endTime": "2024-01-15T10:02:30Z"
  },
  "summary": {
    "totalCVEs": 45,
    "critical": 3,
    "high": 12,
    "medium": 20,
    "low": 10,
    "riskScore": { "concert": 7.2, "comprehensive": 620 },
    "cisaKEVCount": 2
  },
  "cves": [...],
  "remediationGroups": [...]
}
```

---

## Demo Mode

Demo mode provides a fully-functional experience with realistic pre-loaded data:

**Application Profile:**
- Name: Acme Corp Payment Processing API
- Industry: Financial Services
- Criticality: Tier 5 (Mission Critical)
- Data: PII + PCI

**Vulnerability Data:**
- 167 total CVEs
- 12 Critical (including Log4Shell, Spring4Shell)
- 45 High
- 87 Medium
- 23 Low
- 8 CISA KEV vulnerabilities

**Financial Analysis:**
- Potential Breach Cost: $8.8M
- Downtime Cost: $2.1M
- Regulatory Fines: $1.2M
- Total Risk: $12.1M
- Remediation Cost: $51K
- ROI: 237:1

**SLA Status:**
- 2 Overdue
- 5 Due Soon
- 160 On Track
- Compliance Rate: 85%

---

## Testing

### Test Repository

A companion test repository with intentional vulnerabilities is available:

**Repository:** https://github.com/divvi12/testAppRisk

**Contains:**
- 25+ vulnerable npm packages
- 15+ vulnerable Python packages
- SQL injection, XSS, command injection vulnerabilities
- Insecure Docker configuration
- Misconfigured Terraform resources
- Vulnerable Kubernetes deployments

**Usage:**
1. Start Riskanator
2. Click "Scan Repository"
3. Enter: `https://github.com/divvi12/testAppRisk`
4. Complete wizard with high-criticality settings
5. View comprehensive vulnerability results

---

## Roadmap

### Phase 1 - Foundation (Complete)
- [x] React + Vite + Carbon frontend
- [x] Express + TypeScript backend
- [x] Git cloning with PAT support
- [x] npm audit, pip-audit scanning
- [x] Basic CVE list and dashboard

### Phase 2 - Risk Scoring (Complete)
- [x] 6-step context wizard
- [x] NVD, EPSS, KEV enrichment
- [x] Concert + Comprehensive formulas
- [x] Dashboard with charts
- [x] CVE detail modal

### Phase 3 - AI & Integrations (Planned)
- [ ] Gemini AI CVE explanations
- [ ] AI remediation plans
- [ ] ServiceNow incident creation
- [ ] Slack/Teams notifications

### Phase 4 - Enterprise Features (Planned)
- [ ] Enhanced compliance mapping
- [ ] Financial calculator refinements
- [ ] Custom SLA policies
- [ ] Multi-repo scanning

### Phase 5 - Polish (Planned)
- [ ] Comprehensive error handling
- [ ] Loading state improvements
- [ ] Export functionality (PDF, CSV)
- [ ] Scan history persistence

---

## Environment Variables

**Backend (.env):**
```bash
# Server
PORT=3001
NODE_ENV=development

# Scanning
REPO_TEMP_DIR=/tmp/cve-scanner/repos

# API Keys (optional)
GEMINI_API_KEY=your_key_here
NVD_API_KEY=optional_for_higher_rate_limits
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

- **IBM Carbon Design System** - UI components and theming
- **NVD (NIST)** - Vulnerability data
- **FIRST.org** - EPSS exploitation data
- **CISA** - Known Exploited Vulnerabilities catalog
- **Semgrep** - Static analysis engine
- **Trivy** - Container scanning
