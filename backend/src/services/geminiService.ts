import { GoogleGenerativeAI } from '@google/generative-ai';
import {
  Exposure,
  CVEExposure,
  CertificateExposure,
  SecretExposure,
  MisconfigurationExposure,
  LicenseExposure,
  CodeSecurityExposure,
  ApplicationContext
} from '../types';

// ============================================================
// GEMINI AI SERVICE FOR EXPOSURE EXPLANATIONS
// ============================================================

let genAI: GoogleGenerativeAI | null = null;

// Initialize Gemini with API key
export function initializeGemini(apiKey: string): boolean {
  try {
    genAI = new GoogleGenerativeAI(apiKey);
    return true;
  } catch (error) {
    console.error('Failed to initialize Gemini:', error);
    return false;
  }
}

// Check if Gemini is initialized
export function isGeminiInitialized(): boolean {
  return genAI !== null;
}

// Generate explanation for any exposure type
export async function generateExposureExplanation(
  exposure: Exposure,
  context?: ApplicationContext,
  model: string = 'gemini-1.5-pro'
): Promise<ExposureExplanation> {
  if (!genAI) {
    throw new Error('Gemini AI not initialized. Please provide an API key.');
  }

  const geminiModel = genAI.getGenerativeModel({ model });

  const prompt = buildExplanationPrompt(exposure, context);

  try {
    const result = await geminiModel.generateContent(prompt);
    const response = await result.response;
    const text = response.text();

    return parseExplanationResponse(text, exposure);
  } catch (error) {
    console.error('Gemini API error:', error);
    throw new Error('Failed to generate AI explanation');
  }
}

// Build prompt based on exposure type
function buildExplanationPrompt(exposure: Exposure, context?: ApplicationContext): string {
  const appContext = context ? `
Application Context:
- Name: ${context.appName}
- Industry: ${context.industry}
- Purpose: ${context.purpose}
- Criticality: Tier ${context.criticality}/5
- Data Sensitivity: ${getDataSensitivitySummary(context)}
- Network Exposure: ${context.accessControls.networkExposure}
` : '';

  switch (exposure.type) {
    case 'cve':
      return buildCVEPrompt(exposure as CVEExposure, appContext);
    case 'certificate':
      return buildCertificatePrompt(exposure as CertificateExposure, appContext);
    case 'secret':
      return buildSecretPrompt(exposure as SecretExposure, appContext);
    case 'misconfiguration':
      return buildMisconfigPrompt(exposure as MisconfigurationExposure, appContext);
    case 'license':
      return buildLicensePrompt(exposure as LicenseExposure, appContext);
    case 'code-security':
      return buildCodeSecurityPrompt(exposure as CodeSecurityExposure, appContext);
    default:
      return buildGenericPrompt(exposure, appContext);
  }
}

function buildCVEPrompt(cve: CVEExposure, appContext: string): string {
  return `You are a security expert explaining a CVE vulnerability to a development team.

${appContext}

CVE Details:
- CVE ID: ${cve.cveId}
- CVSS Score: ${cve.cvss}
- EPSS Score: ${cve.epss ? (cve.epss * 100).toFixed(1) + '%' : 'N/A'} (probability of exploitation)
- CISA KEV: ${cve.cisaKEV ? 'YES - Known to be actively exploited' : 'No'}
- Severity: ${cve.severity}
- Component: ${cve.component} v${cve.version}
- Fixed Version: ${cve.fixedVersion || 'Unknown'}
- Description: ${cve.description}

Please provide:
1. A plain-language explanation of what this vulnerability means (2-3 sentences)
2. The specific risk to this application given the context
3. The potential business impact if exploited
4. Step-by-step remediation guidance
5. Priority recommendation (Immediate/High/Medium/Low) with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), priority, priorityJustification`;
}

function buildCertificatePrompt(cert: CertificateExposure, appContext: string): string {
  return `You are a security expert explaining a certificate issue to a development team.

${appContext}

Certificate Details:
- Domain: ${cert.domain}
- Status: ${cert.isExpired ? 'EXPIRED' : cert.daysUntilExpiration <= 30 ? 'EXPIRING SOON' : 'Valid'}
- Days Until Expiration: ${cert.daysUntilExpiration}
- Issuer: ${cert.issuer}
- Algorithm: ${cert.algorithm}${cert.hasWeakAlgorithm ? ' (WEAK)' : ''}
- Self-Signed: ${cert.isSelfSigned ? 'Yes' : 'No'}
- Type: ${cert.certType}
- Description: ${cert.description}

Please provide:
1. A plain-language explanation of this certificate issue (2-3 sentences)
2. The specific risk given the application context
3. The potential business impact (downtime, trust issues, etc.)
4. Step-by-step remediation guidance
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), priority, priorityJustification`;
}

function buildSecretPrompt(secret: SecretExposure, appContext: string): string {
  return `You are a security expert explaining a hardcoded secret/credential exposure to a development team.

${appContext}

Secret Details:
- Type: ${secret.secretType}
- Location: ${secret.location}
- Verified Active: ${secret.verified ? 'YES - Confirmed valid/active' : 'Unverified'}
- In Git History: ${secret.inGitHistory ? 'YES - Present in commit history' : 'No'}
- Detector: ${secret.detectorName}
- Description: ${secret.description}

Please provide:
1. A plain-language explanation of this secret exposure (2-3 sentences)
2. The specific risk given the application context
3. The potential business impact if the secret is compromised
4. Step-by-step remediation guidance (rotation, cleanup, prevention)
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), priority, priorityJustification`;
}

function buildMisconfigPrompt(misconfig: MisconfigurationExposure, appContext: string): string {
  return `You are a security expert explaining an infrastructure misconfiguration to a development team.

${appContext}

Misconfiguration Details:
- Resource Type: ${misconfig.resourceType}
- Check ID: ${misconfig.checkId}
- Check Name: ${misconfig.checkName}
- Framework: ${misconfig.framework || 'Unknown'}
- Publicly Accessible: ${misconfig.isPubliclyAccessible ? 'YES' : 'No'}
- Location: ${misconfig.location}
- Description: ${misconfig.description}
${misconfig.guideline ? `- Reference: ${misconfig.guideline}` : ''}

Please provide:
1. A plain-language explanation of this misconfiguration (2-3 sentences)
2. The specific risk given the application context
3. The potential business impact
4. Infrastructure-as-code fix (if applicable)
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), iacFix (code block if applicable), priority, priorityJustification`;
}

function buildLicensePrompt(license: LicenseExposure, appContext: string): string {
  return `You are a legal/compliance expert explaining a software license issue to a development team.

${appContext}

License Details:
- Package: ${license.packageName} v${license.packageVersion}
- License: ${license.licenseName} (${license.licenseType})
- Copyleft: ${license.isCopyleft ? 'YES - Requires source disclosure' : 'No'}
- Unknown License: ${license.isUnknown ? 'YES - License not recognized' : 'No'}
- Requires Attribution: ${license.requiresAttribution ? 'Yes' : 'No'}
- Commercial Use Allowed: ${license.commercialUseAllowed ? 'Yes' : 'No/Unknown'}
- Description: ${license.description}

Please provide:
1. A plain-language explanation of this license issue (2-3 sentences)
2. The legal/compliance risk given the application context
3. The potential business impact (litigation, source disclosure, etc.)
4. Step-by-step remediation guidance
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), priority, priorityJustification`;
}

function buildCodeSecurityPrompt(codeSec: CodeSecurityExposure, appContext: string): string {
  return `You are a security expert explaining a code security vulnerability to a development team.

${appContext}

Code Security Issue:
- Type: ${codeSec.issueType}
- Rule: ${codeSec.ruleName} (${codeSec.ruleId})
- Location: ${codeSec.location} (line ${codeSec.lineNumber})
- CWE: ${codeSec.cwe?.join(', ') || 'N/A'}
- OWASP: ${codeSec.owasp?.join(', ') || 'N/A'}
- Description: ${codeSec.description}
${codeSec.codeSnippet ? `- Code: ${codeSec.codeSnippet}` : ''}

Please provide:
1. A plain-language explanation of this vulnerability (2-3 sentences)
2. The specific attack scenario and risk
3. The potential business impact if exploited
4. Fixed code example
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), fixedCode (code block), priority, priorityJustification`;
}

function buildGenericPrompt(exposure: Exposure, appContext: string): string {
  return `You are a security expert explaining a security exposure to a development team.

${appContext}

Exposure Details:
- Type: ${exposure.type}
- Title: ${exposure.title}
- Severity: ${exposure.severity}
- Location: ${exposure.location}
- Description: ${exposure.description}

Please provide:
1. A plain-language explanation (2-3 sentences)
2. The specific risk given the application context
3. The potential business impact
4. Remediation guidance
5. Priority recommendation with justification

Format your response as JSON with these fields: summary, riskAnalysis, businessImpact, remediation (array of steps), priority, priorityJustification`;
}

function getDataSensitivitySummary(context: ApplicationContext): string {
  const types = [];
  if (context.dataSensitivity.pii) types.push('PII');
  if (context.dataSensitivity.phi) types.push('PHI');
  if (context.dataSensitivity.pci) types.push('PCI');
  if (context.dataSensitivity.tradeSecrets) types.push('Trade Secrets');
  return types.length > 0 ? types.join(', ') : 'None specified';
}

// Parse Gemini response into structured format
function parseExplanationResponse(text: string, exposure: Exposure): ExposureExplanation {
  try {
    // Try to extract JSON from the response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        exposureId: exposure.id,
        exposureType: exposure.type,
        summary: parsed.summary || 'No summary available',
        riskAnalysis: parsed.riskAnalysis || 'No risk analysis available',
        businessImpact: parsed.businessImpact || 'No business impact analysis available',
        remediation: Array.isArray(parsed.remediation) ? parsed.remediation : [parsed.remediation || 'No remediation steps available'],
        fixedCode: parsed.fixedCode || parsed.iacFix,
        priority: parsed.priority || 'Medium',
        priorityJustification: parsed.priorityJustification || 'Based on severity and context',
        generatedAt: new Date().toISOString()
      };
    }
  } catch (error) {
    console.error('Failed to parse Gemini response as JSON:', error);
  }

  // Fallback: return raw text as summary
  return {
    exposureId: exposure.id,
    exposureType: exposure.type,
    summary: text.substring(0, 500),
    riskAnalysis: 'Unable to parse structured response',
    businessImpact: 'Please review the summary above',
    remediation: ['Review the exposure details and address accordingly'],
    priority: exposure.severity === 'critical' ? 'Immediate' : exposure.severity === 'high' ? 'High' : 'Medium',
    priorityJustification: `Based on ${exposure.severity} severity`,
    generatedAt: new Date().toISOString()
  };
}

// Generate executive summary for all exposures
export async function generateExecutiveSummary(
  exposures: Exposure[],
  context?: ApplicationContext,
  model: string = 'gemini-1.5-pro'
): Promise<ExecutiveSummary> {
  if (!genAI) {
    throw new Error('Gemini AI not initialized. Please provide an API key.');
  }

  const geminiModel = genAI.getGenerativeModel({ model });

  const summaryByType = {
    cve: exposures.filter(e => e.type === 'cve').length,
    certificate: exposures.filter(e => e.type === 'certificate').length,
    secret: exposures.filter(e => e.type === 'secret').length,
    misconfiguration: exposures.filter(e => e.type === 'misconfiguration').length,
    license: exposures.filter(e => e.type === 'license').length,
    'code-security': exposures.filter(e => e.type === 'code-security').length
  };

  const criticalCount = exposures.filter(e => e.severity === 'critical').length;
  const highCount = exposures.filter(e => e.severity === 'high').length;

  const prompt = `You are a security expert preparing an executive summary for leadership.

${context ? `
Application: ${context.appName}
Industry: ${context.industry}
Criticality: Tier ${context.criticality}/5
` : ''}

Exposure Summary:
- Total Exposures: ${exposures.length}
- Critical: ${criticalCount}
- High: ${highCount}
- CVEs: ${summaryByType.cve}
- Secrets: ${summaryByType.secret}
- Certificates: ${summaryByType.certificate}
- Misconfigurations: ${summaryByType.misconfiguration}
- License Issues: ${summaryByType.license}
- Code Security: ${summaryByType['code-security']}

Top 5 Critical Issues:
${exposures
  .filter(e => e.severity === 'critical')
  .slice(0, 5)
  .map((e, i) => `${i + 1}. [${e.type.toUpperCase()}] ${e.title}`)
  .join('\n')}

Please provide an executive summary suitable for non-technical leadership that includes:
1. Overall security posture assessment (1 paragraph)
2. Key findings summary (3-5 bullet points)
3. Recommended immediate actions (3-5 prioritized items)
4. Risk level (Critical/High/Medium/Low) with justification
5. Estimated remediation effort and timeline

Format as JSON with fields: posture, keyFindings (array), immediateActions (array), riskLevel, riskJustification, estimatedEffort, timeline`;

  try {
    const result = await geminiModel.generateContent(prompt);
    const response = await result.response;
    const text = response.text();

    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        posture: parsed.posture || 'Unable to assess',
        keyFindings: parsed.keyFindings || [],
        immediateActions: parsed.immediateActions || [],
        riskLevel: parsed.riskLevel || 'Medium',
        riskJustification: parsed.riskJustification || '',
        estimatedEffort: parsed.estimatedEffort || 'Unknown',
        timeline: parsed.timeline || 'Unknown',
        generatedAt: new Date().toISOString()
      };
    }

    return {
      posture: text.substring(0, 500),
      keyFindings: [],
      immediateActions: [],
      riskLevel: criticalCount > 0 ? 'Critical' : highCount > 5 ? 'High' : 'Medium',
      riskJustification: `${criticalCount} critical and ${highCount} high severity exposures`,
      estimatedEffort: 'Unknown',
      timeline: 'Unknown',
      generatedAt: new Date().toISOString()
    };
  } catch (error) {
    console.error('Gemini API error:', error);
    throw new Error('Failed to generate executive summary');
  }
}

// Types
export interface ExposureExplanation {
  exposureId: string;
  exposureType: string;
  summary: string;
  riskAnalysis: string;
  businessImpact: string;
  remediation: string[];
  fixedCode?: string;
  priority: string;
  priorityJustification: string;
  generatedAt: string;
}

export interface ExecutiveSummary {
  posture: string;
  keyFindings: string[];
  immediateActions: string[];
  riskLevel: string;
  riskJustification: string;
  estimatedEffort: string;
  timeline: string;
  generatedAt: string;
}
