# CVE Prioritization & Remediation Platform - POC Design Document

## Executive Summary

A localhost web application that scans git repositories for vulnerabilities, applies contextualized risk scoring, and provides AI-powered remediation guidance.

**Core Capabilities:**
- Multi-language vulnerability scanning (SCA, SAST, Container, IaC)
- Dual risk scoring formulas (Concert & Comprehensive Framework)
- AI-powered CVE explanations (Gemini)
- ServiceNow incident creation
- Compliance mapping (PCI, HIPAA, SOX, GDPR)
- Financial impact analysis
- SLA tracking
- Demo mode

**Tech Stack:** React + Vite + Carbon Design System | Node.js + Express | localStorage

---

## Architecture

### System Architecture
```
┌─────────────────────────────────────────────┐
│         FRONTEND (Port 5173)                │
│    React + Vite + Carbon Design             │
│                                             │
│  Pages: Dashboard, Scan Setup, CVE List,   │
│         Remediation, Settings               │
└──────────────────┬──────────────────────────┘
                   │ HTTP/REST
                   ↓
┌─────────────────────────────────────────────┐
│         BACKEND (Port 3001)                 │
│         Node.js + Express                   │
│                                             │
│  Routes: /api/scan, /api/ai/explain,       │
│          /api/servicenow/*                  │
│                                             │
│  Services: Git, Scanner, CVE enrichment,   │
│           Risk scoring, Gemini, ServiceNow  │
└──────────────────┬──────────────────────────┘
                   │
                   ↓
┌─────────────────────────────────────────────┐
│  EXTERNAL: NVD, EPSS, CISA KEV, GitHub,    │
│           Gemini API, ServiceNow API        │
└─────────────────────────────────────────────┘
```

### Data Flow
```
User → Repository URL + Context → Backend Scan → 
CVE Enrichment (NVD/EPSS/KEV) → Risk Calculation → 
Frontend Display → User clicks AI → Gemini Explanation
```

---

## Core Features

### 1. Repository Scanning

**Supported:**
- GitHub, GitLab, Bitbucket (public + private with PAT)
- Any git URL (public only)

**Scanning Types:**
| Type | Tool | Languages |
|------|------|-----------|
| SCA (Dependencies) | npm audit, pip-audit | JavaScript, Python, Java, Ruby, Go, .NET |
| SAST (Code) | Semgrep | Multi-language |
| Container | Trivy | Docker images |
| IaC | Checkov, tfsec | Terraform, CloudFormation, K8s |

### 2. Risk Scoring

**Concert Formula:**
```
Risk = CVSS × Exploitability(EPSS) × Environmental(Context)
Capped at 10.0
```

**Comprehensive Formula:**
```
Risk = Likelihood × Impact × Exposure × (1-Controls) × 1000
Capped at 1000
```

User selects formula during scan setup.

### 3. CVE Enrichment

**Data Sources:**
- **NVD**: CVSS scores, descriptions
- **FIRST.org**: EPSS exploitation probability
- **CISA KEV**: Known exploited vulnerabilities
- **GitHub Advisory**: Additional context

Rate-limited queries with bottleneck library.

### 4. Application Context

**6-Step Questionnaire:**
1. Repository (URL, public/private, branch)
2. Basic Info (name, industry, purpose)
3. Criticality (1-5 tier with industry examples)
4. Data Sensitivity (checkboxes: PII, PHI, PCI, Trade Secrets)
5. Access & Controls (public/private access points, network exposure, controls)
6. Formula Selection (Concert vs Comprehensive)

---

## Enhanced Features

### 1. Demo Mode

Pre-loaded realistic dataset:
- Application: "Acme Corp Payment Processing API"
- 167 CVEs (12 critical, 45 high, 87 medium, 23 low)
- 8 CISA KEV vulnerabilities
- Complete remediation groups
- Financial and SLA data

**Access:** Landing page button "Try Demo Mode"
**Badge:** Shows "🎭 Demo Mode" in header when active

### 2. AI Explanations (Gemini)

**CVE Detail Modal:**
- Button: "✨ Get AI Explanation (Est. cost: ~$0.03)"
- Generates contextual explanation with fix code
- Markdown rendering with syntax highlighting
- Copy buttons for code snippets

**Remediation Groups:**
- Button: "🤖 Get AI Remediation Plan"
- Step-by-step fix instructions with commands

### 3. Compliance Mapping

**Supported Standards:**
- PCI-DSS (Payment Card Industry)
- HIPAA (Healthcare)
- SOX (Financial)
- GDPR (EU Data Protection)

Auto-maps CVEs to requirements based on app context.

**Dashboard Widget:**
```
┌─────────────────────────┐
│ Compliance Risk      ⓘ │
├─────────────────────────┤
│ 🏛️ PCI-DSS: 8 CVEs     │
│ 🏥 HIPAA: 0 CVEs        │
│ 📊 SOX: 5 CVEs          │
│ 🇪🇺 GDPR: 12 CVEs       │
└─────────────────────────┘
```

### 4. Financial Impact

**Calculation:**
- Potential breach cost: Critical CVEs × 15% × $4.88M
- Downtime cost: Industry revenue × 24hrs × 10%
- Regulatory fines: Based on data types (PCI/HIPAA/GDPR)
- Remediation cost: Effort hours × $150/hr
- ROI: (Total Risk - Remediation) / Remediation

**Dashboard Widget:**
```
┌─────────────────────────────┐
│ Financial Impact         ⓘ │
├─────────────────────────────┤
│ Potential Costs:            │
│ • Breach: $8.8M            │
│ • Downtime: $2.1M          │
│ • Fines: $1.2M             │
│ Total Risk: $12.1M          │
│                             │
│ Remediation: $51K           │
│ ROI: 237:1 📈              │
└─────────────────────────────┘
```

### 5. SLA Tracking

**Matrix:**
| Risk Score | Tier 1-2 | Tier 3 | Tier 4-5 |
|------------|----------|---------|----------|
| 9.0-10.0   | 48hrs    | 7 days  | 14 days  |
| 7.0-8.9    | 7 days   | 14 days | 30 days  |
| 4.0-6.9    | 30 days  | 45 days | 60 days  |
| 0-3.9      | 60 days  | 90 days | 90 days  |

**Dashboard Widget:**
```
┌─────────────────────────┐
│ SLA Status           ⓘ │
├─────────────────────────┤
│ 🔴 OVERDUE: 2          │
│ 🟠 DUE SOON: 5         │
│ 🟢 ON TRACK: 160       │
│                         │
│ Compliance: 85%         │
└─────────────────────────┘
```

### 6. Remediation Grouping

Groups CVEs by common fix:
- Dependencies: Group by package update
- Code: Group by file + vulnerability type
- Containers: Group by base image update
- IaC: Group by resource type

Each group shows:
- CVEs fixed count
- Risk score reduction
- Effort estimate (Low/Medium/High)
- SLA status
- Compliance impact

### 7. ServiceNow Integration

**Settings Page:**
- Instance URL
- Authentication (OAuth / Basic / Token)
- Default assignment group
- Auto-priority mapping

**Incident Creation:**
- From remediation group
- Pre-filled with CVE details
- Returns incident number + link

---

## UI Design

### Carbon Design System

**Theme:** g100 (dark)
**Colors:**
- Background: #161616
- Critical: #FA4D56 (red)
- High: #FF832B (orange)
- Medium: #F1C21B (yellow)
- Low: #42BE65 (green)
- Interactive: #4589FF (IBM blue)

### Pages

#### 1. Landing Page
```
┌────────────────────────────┐
│   CVE Scanner | IBM        │
├────────────────────────────┤
│                            │
│  [📊 Try Demo Mode]       │
│                            │
│         OR                 │
│                            │
│  [🔍 Scan Repository]     │
│                            │
└────────────────────────────┘
```

#### 2. Dashboard
```
┌──────────────────────────────────────────┐
│ [☰] CVE Scanner     [🔔] [👤]          │
├──┬───────────────────────────────────────┤
│🏠│ Welcome back, user    [New Scan →]   │
│  │                                       │
│📊│ ┌──────────────┐  ┌──────────────┐  │
│🔧│ │  Radial      │  │ Risk Score   │  │
│⚙️│ │  Chart       │  │ 76.3/100     │  │
│  │ │              │  │              │  │
│  │ │ Dependencies │  │ Critical: 12 │  │
│  │ │ Code         │  │ High: 45     │  │
│  │ │ Containers   │  │ Medium: 87   │  │
│  │ │ IaC          │  │ Low: 23      │  │
│  │ └──────────────┘  └──────────────┘  │
│  │                                       │
│  │ ┌──────────┐ ┌──────────┐          │
│  │ │ KEV: 8   │ │ Risk:    │          │
│  │ │          │ │ $12.1M   │          │
│  │ └──────────┘ └──────────┘          │
│  │                                       │
│  │ ┌──────────┐ ┌──────────┐          │
│  │ │ SLA      │ │Compliance│          │
│  │ │ 2 overdue│ │ PCI: 8   │          │
│  │ └──────────┘ └──────────┘          │
└──┴───────────────────────────────────────┘
```

Radial chart shows 5 segments (Dependencies, Code, Containers, IaC, Third-Party) with red outlines for high-risk areas.

#### 3. CVE List
```
┌─────────────────────────────────────────────────┐
│ All CVEs                                        │
├─────────────────────────────────────────────────┤
│ Filters: [Severity ▼] [Source ▼] [KEV ☐]     │
│ Search: [____________] 🔍                       │
│                                                 │
│ 167 CVEs                                        │
├──────┬──────┬──────┬───────┬──────────┬────────┤
│ Risk │ CVE  │ CVSS │ EPSS  │ Component│ AI     │
├──────┼──────┼──────┼───────┼──────────┼────────┤
│ 🔴9.8│CVE-  │ 10.0 │ 89.2% │ log4j    │ ✨    │
│      │44228🚨│     │       │ 2.14.1   │        │
├──────┼──────┼──────┼───────┼──────────┼────────┤
│ ...  │      │      │       │          │        │
└──────┴──────┴──────┴───────┴──────────┴────────┘
```

Click row → CVE detail modal
Click ✨ → AI explanation inline

#### 4. CVE Detail Modal
```
┌──────────────────────────────────────┐
│ CVE-2021-44228 (Log4Shell)      [✕] │
├──────────────────────────────────────┤
│ ┌────────┐ ┌────────┐ ┌────────┐   │
│ │Risk:9.8│ │CVSS:10│ │EPSS:89%│   │
│ └────────┘ └────────┘ └────────┘   │
│                                      │
│ 🚨 CISA KEV - Actively Exploited    │
│                                      │
│ Description:                         │
│ Apache Log4j2 JNDI features...      │
│                                      │
│ Application Context:                 │
│ • Affects log4j-core 2.14.1         │
│ • Business-Critical (Tier 4)        │
│ • PCI + PII data                    │
│                                      │
│ Compliance Impact:                   │
│ 🏛️ PCI-DSS 6.2                     │
│ 📊 SOX Section 404                  │
│                                      │
│ SLA: Due Jan 18 (48 hours)          │
│                                      │
│ [✨ Get AI Explanation (~$0.03)]    │
└──────────────────────────────────────┘
```

#### 5. Remediation Tab
```
┌──────────────────────────────────────────────┐
│ Remediation Groups                           │
│                                              │
│ Group by: ● Fixes  ○ Impact  ○ Component    │
│ Sort: [Risk Reduction ▼]                    │
│                                              │
│ ServiceNow: ✓ Connected [⚙️]               │
├──────────────────────────────────────────────┤
│ ┌────────────────────────────────────────┐ │
│ │ 🔧 Update log4j to 2.17.1   [Expand ▼]│ │
│ ├────────────────────────────────────────┤ │
│ │ CVEs: 8 | Risk: -42pts | Effort: Low  │ │
│ │ 🚨 4 in KEV | ⚠️ 2 overdue            │ │
│ │ 🏛️ PCI, SOX, GDPR                     │ │
│ │                                        │ │
│ │ [🤖 AI Plan] [🎫 Incident] [📋 Copy] │ │
│ └────────────────────────────────────────┘ │
│                                              │
│ ┌────────────────────────────────────────┐ │
│ │ 🔧 Update OpenSSL to 3.0.12 [Expand ▼]│ │
│ ├────────────────────────────────────────┤ │
│ │ CVEs: 5 | Risk: -28pts | Effort: Low  │ │
│ │ 🟢 All on track                        │ │
│ │                                        │ │
│ │ [🤖 AI Plan] [🎫 Incident] [📋 Copy] │ │
│ └────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

#### 6. Settings
```
┌──────────────────────────────────────┐
│ Settings                             │
├──────────────────────────────────────┤
│ Risk Scoring                         │
│ ● Concert  ○ Comprehensive           │
│                                      │
│ ServiceNow Integration            ⓘ │
│ Instance: [https://___________]     │
│ Auth: ● OAuth ○ Basic ○ Token       │
│ [Test Connection]                    │
│                                      │
│ Default Assignment:                  │
│ [Security Operations        ▼]      │
│                                      │
│ [Save]                               │
└──────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Goal:** Working scan with basic CVE display

**Deliverables:**
- React + Vite + Carbon frontend
- Express backend
- Git clone (public + private)
- Language detection
- npm audit, pip-audit scanning
- Basic CVE table

**Claude Prompt:**
```
I'm building a CVE scanning POC. Help me set up Phase 1.

ARCHITECTURE:
- Frontend: React + Vite + TypeScript + Carbon Design System (g100 theme)
- Backend: Node.js + Express + TypeScript
- Localhost: Frontend :5173, Backend :3001

REQUIREMENTS:
1. Frontend:
   - React + Vite with TypeScript
   - Install @carbon/react, @carbon/icons-react
   - Routes: / (dashboard), /scan (new scan), /cves (list), /settings
   - Left sidebar navigation
   - Vite proxy for /api → localhost:3001

2. Backend:
   - Express server with TypeScript
   - Routes: POST /api/scan, GET /api/scan/:id/status, GET /api/scan/:id/results
   - Git cloning with simple-git
   - Language detection (package.json, requirements.txt, pom.xml)
   - Run npm audit, pip-audit
   - Return: { cves: [...], languages: [...], summary: {...} }

3. Scan Page:
   - Radio: Public / Private repo
   - If private: PAT input field
   - Git URL input
   - Branch input (default: main)
   - Submit → POST /api/scan → Loading → Navigate to /cves

4. CVE List:
   - Carbon DataTable
   - Columns: CVE ID, CVSS, Component, Version, Severity
   - Click row → Show alert with details

TECH:
- Frontend: React 18, Vite 5, @carbon/react, react-router-dom
- Backend: Express 4, simple-git, dotenv

Provide:
1. Directory structure (frontend/, backend/)
2. All package.json files
3. Full implementation
4. Run instructions
5. .env.example
```

---

### Phase 2: Risk Scoring (Week 2)

**Goal:** Context questionnaire, CVE enrichment, dashboard

**Deliverables:**
- 6-step wizard
- NVD, EPSS, KEV enrichment
- Concert + Comprehensive formulas
- Dashboard with radial chart
- CVE detail modal

**Claude Prompt:**
```
Phase 2: Add risk scoring and dashboard.

CONTEXT: Phase 1 working - basic scan returns CVEs.

REQUIREMENTS:

1. Context Questionnaire (6-step wizard with Carbon ProgressIndicator):
   Step 1: Repository (add public/private toggle)
   Step 2: Basic Info (name, industry dropdown, purpose)
   Step 3: Criticality (1-5 radio with industry-specific examples)
   Step 4: Data Sensitivity (checkboxes: PII, PHI, PCI, Trade Secrets → auto-suggest tier)
   Step 5: Access & Controls (public/private counts, network exposure, controls checkboxes)
   Step 6: Formula (Concert / Comprehensive radio)

2. CVE Enrichment (/backend/src/services/cveEnrichment.ts):
   - Query NVD: https://services.nvd.nist.gov/rest/json/cves/2.0/{cveId}
   - Query EPSS: https://api.first.org/data/v1/epss?cve={cveId}
   - Check CISA KEV: Download JSON, check if CVE exists
   - Rate limit: bottleneck (NVD: 6s between, EPSS: 100ms)

3. Risk Calculation (/backend/src/services/riskCalculator.ts):
   A) Concert: CVSS × Exploitability(EPSS) × Environmental(context) [cap 10]
   B) Comprehensive: Likelihood × Impact × Exposure × (1-Controls) × 1000 [cap 1000]

4. Dashboard:
   - Radial chart (5 segments: Dependencies, Code, Containers, IaC, Third-Party)
   - Red outline if segment avg risk > 7.0
   - Metric cards: Risk Score, CVE counts, KEV count
   - Use @carbon/charts-react or recharts

5. CVE Detail Modal:
   - Carbon Modal
   - Top cards: Risk, CVSS, EPSS, KEV status
   - Description, App Context, References
   - Placeholder "Get AI Explanation" button

OUTPUT:
{
  scanId, metadata: { repo, branch, context },
  summary: { totalCVEs, critical, high, medium, low, riskScore: {concert, comprehensive}, cisaKEVCount },
  cves: [{ id, cvss, epss, cisaKEV, riskScore: {concert, comprehensive}, component, version, source, description }]
}

Provide complete implementation with IBM Concert dark styling.
```

---

### Phase 3: AI & ServiceNow (Week 3)

**Goal:** Gemini explanations, remediation grouping, ServiceNow

**Deliverables:**
- AI CVE explanations
- AI remediation plans
- Remediation grouping
- ServiceNow setup + incident creation

**Claude Prompt:**
```
Phase 3: AI and ServiceNow integration.

CONTEXT: Phase 2 complete - have risk scoring and dashboard.

REQUIREMENTS:

1. Gemini Integration (POST /api/ai/explain):
   - Request: { cveId, cveData, applicationContext, vulnerableCode, technologyStack, component }
   - Prompt template:
     "You are a security expert. VULNERABILITY: {cveId}, CVSS {cvss}, EPSS {epss}
      APPLICATION: {industry} {criticality}, processes {dataSensitivity} data
      COMPONENT: {component} {version}
      Provide: 1) Explanation (2-3 sentences), 2) Why this matters for THIS app,
      3) Remediation steps with code, 4) Fix code snippet, 5) Verification
      Format: markdown"
   - Response: { explanation, tokenUsed, estimatedCost }

2. AI Explanation UI:
   - In CVE modal: [✨ Get AI Explanation (Est. ~$0.03)]
   - Show cost estimate BEFORE calling
   - Display with react-markdown + react-syntax-highlighter
   - Copy buttons on code blocks

3. Remediation Grouping (/services/remediationGrouper.ts):
   - Group by: (packageName, fixVersion) for dependencies
   - Group by: (file, vulnType) for SAST
   - Calculate: cvesFixed, riskReduction, effort (Low/Med/High), priority, slaStatus

4. Remediation Tab UI:
   - Group by: Fixes / Impact / Component (radio)
   - Sort: Risk Reduction / SLA / Effort (dropdown)
   - Concert-style cards with 3 metrics (CVEs/Risk/Effort)
   - Show KEV count, SLA status, compliance
   - Buttons: [🤖 AI Plan] [🎫 Incident] [📋 Copy]

5. AI Remediation Plan:
   - Button on remediation group
   - Prompt: "Remediation group: {title}, CVEs: {count}, Components: {list}
      Tech: {stack}, Deployment: {env}
      Provide: 1) Prerequisites, 2) Detailed steps with commands, 3) Testing,
      4) Rollback, 5) Downtime estimate, 6) Verification"

6. ServiceNow Settings:
   - Instance URL
   - Auth method: OAuth / Basic / Token (conditional fields)
   - Test connection button
   - Default assignment group (dropdown - fetch from ServiceNow)
   - Store encrypted in localStorage (crypto-js)

7. ServiceNow Incident (POST /api/servicenow/incident):
   - Request: { credentials, remediationGroup, priority }
   - POST to https://{instance}.service-now.com/api/now/table/incident
   - Body: short_description, description (formatted with CVEs), assignment_group, priority
   - Response: { incidentNumber, sysId, link }
   - Frontend: Modal with form, pre-filled, show success with link

TECH:
- Install: @google/generative-ai, crypto-js, react-markdown, react-syntax-highlighter
- Environment: GEMINI_API_KEY in .env

Provide complete implementation.
```

---

### Phase 4: Compliance, Financial, SLA (Week 4)

**Goal:** Enterprise features

**Deliverables:**
- Compliance mapping
- Financial calculator
- SLA tracking

**Claude Prompt:**
```
Phase 4: Add compliance, financial, SLA features.

CONTEXT: Phase 3 complete - have AI and ServiceNow working.

REQUIREMENTS:

1. Compliance Mapping (/services/complianceMapper.ts):
   - If app processes PCI → map CVEs to PCI-DSS requirements
   - If PHI → HIPAA, if financial → SOX, if EU data → GDPR
   - Mapping: { pci: {'CVE-2021-44228': 'PCI-DSS 6.2', ...}, hipaa: {...}, sox: {...}, gdpr: {...} }
   - Add complianceImpact: string[] to each CVE

2. Dashboard Compliance Widget:
   - Show CVE counts per standard
   - Format: "🏛️ PCI-DSS: 8 CVEs", "🏥 HIPAA: 0 CVEs", etc.

3. Financial Calculator (/services/financialCalculator.ts):
   - Breach cost: criticalCVEs × 0.15 × $4.88M
   - Downtime: hourlyRevenue(industry, criticality) × 24hrs × 0.10
   - Regulatory fines: PCI $500K, HIPAA $1.5M, GDPR $2M (if applicable)
   - Remediation: sum(effortHours) × $150
   - ROI: (totalRisk - remediationCost) / remediationCost
   - Industry multipliers: Financial $15K/hr, Healthcare $8K/hr, etc.

4. Dashboard Financial Widget:
   - Large metrics: Breach, Downtime, Fines, Total Risk, Remediation, ROI
   - Format: "$8.8M", "ROI: 237:1 📈"

5. SLA Calculator (/services/slaCalculator.ts):
   - Matrix: Risk score × Asset tier → days to remediate
   - For each CVE: deadline, status (overdue/due_soon/on_track), daysRemaining
   - Aggregate: complianceRate, overdueCount, dueSoonCount

6. Dashboard SLA Widget:
   - Show: Overdue count, Due soon count, On track count
   - Compliance rate %

7. CVE Detail Modal:
   - Add compliance section (which standards affected)
   - Add SLA deadline line

8. Remediation Groups:
   - Show SLA status per group
   - Format: "⚠️ SLA: 2 overdue, 3 due soon"

Provide complete implementation for all calculations.
```

---

### Phase 5: Demo & Polish (Week 5)

**Goal:** Demo mode, final polish, documentation

**Deliverables:**
- Demo mode
- Error handling
- Loading states
- README

**Claude Prompt:**
```
Phase 5: Demo mode and final polish.

CONTEXT: All features working. Need demo mode and polish for POC.

REQUIREMENTS:

1. Demo Mode (/frontend/src/data/demoData.ts):
   - Pre-load: "Acme Corp Payment Processing API", Financial Services
   - 167 CVEs: 12 critical, 45 high, 87 medium, 23 low
   - 8 CISA KEV vulnerabilities
   - Realistic components: log4j-core 2.14.1, lodash 4.17.19, etc.
   - Complete remediation groups with effort, SLA, compliance
   - Financial data: $12.1M risk, $51K remediation, ROI 237:1
   - SLA: 2 overdue, 5 due soon, 160 on track

2. Landing Page:
   - [📊 Try Demo Mode] button
   - [🔍 Scan Repository] button
   - Demo mode: Load instantly, show "🎭 Demo Mode" badge in header
   - [Exit Demo Mode] button

3. Error Handling:
   - Git clone fails: Check auth, show helpful message
   - Scanner fails: Check tools installed
   - Rate limit: Suggest NVD API key
   - Gemini error: Check API key
   - ServiceNow error: Test connection
   - Use Carbon ToastNotification

4. Loading States:
   - Scanning: Progress steps ("Cloning...", "Detecting languages...", etc.)
   - CVE enrichment: Skeleton loaders
   - AI explanation: Spinner "Generating..."
   - ServiceNow test: "Testing connection..."
   - Use Carbon Loading, SkeletonText components

5. UI Polish:
   - Consistent Carbon spacing tokens
   - Hover states on interactive elements
   - Empty states with messages
   - Tooltips on info icons
   - Color-coded severity (red/orange/yellow/green)
   - Test at 1280px, 1440px, 1920px

6. README.md:
   ```markdown
   # CVE Scanner POC
   
   ## Features
   - Multi-language scanning (SCA, SAST, Container, IaC)
   - Dual risk scoring (Concert + Comprehensive)
   - AI explanations (Gemini)
   - ServiceNow integration
   - Compliance (PCI, HIPAA, SOX, GDPR)
   - Financial analysis
   - SLA tracking
   - Demo mode
   
   ## Prerequisites
   - Node.js 18+
   - Python 3.8+ (pip-audit)
   - Git
   
   ## Installation
   1. Clone repo
   2. cd backend && npm install
   3. cd ../frontend && npm install
   4. Backend: cp .env.example .env (add GEMINI_API_KEY)
   
   ## Run
   Terminal 1: cd backend && npm run dev (port 3001)
   Terminal 2: cd frontend && npm run dev (port 5173)
   Open: http://localhost:5173
   
   ## Quick Start
   - Try Demo Mode: Instant pre-loaded results
   - Scan Repository: Follow wizard
   
   ## Tech Stack
   Frontend: React 18, Vite, Carbon Design
   Backend: Node.js, Express
   AI: Google Gemini
   Scanning: npm audit, pip-audit, Semgrep, Trivy
   Data: NVD, EPSS, CISA KEV, GitHub Advisory
   
   ## Troubleshooting
   - Clone fails: Check URL, PAT permissions
   - Rate limit: Add NVD_API_KEY to .env
   - Gemini error: Check API key
   ```

7. .env.example:
   ```
   GEMINI_API_KEY=your_key
   NVD_API_KEY=optional
   PORT=3001
   NODE_ENV=development
   REPO_TEMP_DIR=/tmp/cve-scanner/repos
   ```

8. Test Repository (separate GitHub repo: "vulnerable-test-app"):
   - package.json: log4j-core 2.14.1, lodash 4.17.19, axios 0.21.1
   - requirements.txt: Django 2.2.0, requests 2.6.0
   - Vulnerable code: SQL injection, XSS, hardcoded key
   - Dockerfile: ubuntu:18.04, root user
   - Terraform: public S3, open security group
   - README: "For testing purposes only"

Provide complete implementation. Ensure POC is demo-ready.
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
    "simple-git": "^3.21.0"
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

### External Tools
- **npm** (included with Node.js)
- **pip-audit**: `pip install pip-audit`
- **Semgrep**: `pip install semgrep`
- **Trivy**: https://aquasecurity.github.io/trivy/
- **Checkov**: `pip install checkov`

---

## Summary

**Timeline:** 5 weeks (40-50 hours)

**Phases:**
1. Week 1: Basic scanning + CVE display
2. Week 2: Risk scoring + dashboard
3. Week 3: AI + ServiceNow
4. Week 4: Compliance + Financial + SLA
5. Week 5: Demo mode + polish

**Result:** Production-quality POC ready for demonstrations

**Key Differentiators:**
- Contextualized risk scoring (not just CVSS)
- AI-powered explanations (Gemini)
- Financial impact ($12.1M vs $51K)
- Compliance mapping (PCI, HIPAA, SOX, GDPR)
- SLA tracking (85% compliance)
- Demo mode (instant results)
- Professional IBM Concert styling

**POC Focus:** 
- Single-use demonstration tool
- No unnecessary features
- No data persistence beyond localStorage
- No complex user management
- No export features
- Clean, focused implementation
