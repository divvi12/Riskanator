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

// Validate Gemini API key by making a test call
export async function validateGeminiApiKey(apiKey: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const testGenAI = new GoogleGenerativeAI(apiKey);
    const model = testGenAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

    // Make a simple test call to validate the API key
    const result = await model.generateContent('Say "API key validated" in exactly 3 words.');
    const response = await result.response;
    const text = response.text();

    // If we got a response, the key is valid
    if (text) {
      // Also initialize the main genAI instance
      genAI = testGenAI;
      return { valid: true };
    }

    return { valid: false, error: 'No response from Gemini API' };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error('Gemini API key validation failed:', message);
    return { valid: false, error: message };
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
  model: string = 'gemini-2.5-flash'
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
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('Gemini API error:', errorMessage);
    throw new Error(`Gemini API error: ${errorMessage}`);
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
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

CVE: ${cve.cveId} | CVSS: ${cve.cvss} | EPSS: ${cve.epss ? (cve.epss * 100).toFixed(1) + '%' : 'N/A'} | KEV: ${cve.cisaKEV ? 'YES' : 'No'}
Component: ${cve.component} v${cve.version} → ${cve.fixedVersion || 'Unknown'}
Description: ${cve.description}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), priority (Immediate/High/Medium/Low), priorityJustification (1 sentence)`;
}

function buildCertificatePrompt(cert: CertificateExposure, appContext: string): string {
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

Certificate: ${cert.domain} | Status: ${cert.isExpired ? 'EXPIRED' : cert.daysUntilExpiration + ' days left'}
Issuer: ${cert.issuer} | Algorithm: ${cert.algorithm}${cert.hasWeakAlgorithm ? ' (WEAK)' : ''} | Self-signed: ${cert.isSelfSigned ? 'Yes' : 'No'}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), priority, priorityJustification (1 sentence)`;
}

function buildSecretPrompt(secret: SecretExposure, appContext: string): string {
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

Secret: ${secret.secretType} at ${secret.location}
Verified: ${secret.verified ? 'YES - Active' : 'No'} | In Git History: ${secret.inGitHistory ? 'YES' : 'No'}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), priority, priorityJustification (1 sentence)`;
}

function buildMisconfigPrompt(misconfig: MisconfigurationExposure, appContext: string): string {
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

Misconfiguration: ${misconfig.checkName} (${misconfig.checkId})
Resource: ${misconfig.resourceType} at ${misconfig.location} | Public: ${misconfig.isPubliclyAccessible ? 'YES' : 'No'}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), iacFix (brief code if applicable), priority, priorityJustification (1 sentence)`;
}

function buildLicensePrompt(license: LicenseExposure, appContext: string): string {
  return `You are a compliance expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

License: ${license.packageName} v${license.packageVersion} - ${license.licenseName}
Copyleft: ${license.isCopyleft ? 'YES' : 'No'} | Unknown: ${license.isUnknown ? 'YES' : 'No'} | Commercial OK: ${license.commercialUseAllowed ? 'Yes' : 'No'}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), priority, priorityJustification (1 sentence)`;
}

function buildCodeSecurityPrompt(codeSec: CodeSecurityExposure, appContext: string): string {
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

Code Issue: ${codeSec.ruleName} (${codeSec.ruleId}) at ${codeSec.location}:${codeSec.lineNumber}
CWE: ${codeSec.cwe?.join(', ') || 'N/A'} | OWASP: ${codeSec.owasp?.join(', ') || 'N/A'}
${codeSec.codeSnippet ? `Code: ${codeSec.codeSnippet}` : ''}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), fixedCode (brief fix), priority, priorityJustification (1 sentence)`;
}

function buildGenericPrompt(exposure: Exposure, appContext: string): string {
  return `You are a security expert. Be CONCISE - each field should be 1-2 sentences max.

${appContext}

Exposure: ${exposure.type} - ${exposure.title} (${exposure.severity})
Location: ${exposure.location}

Respond with brief JSON: summary (1-2 sentences), riskAnalysis (1 sentence), businessImpact (1 sentence), remediation (3-4 short action items), priority, priorityJustification (1 sentence)`;
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
  model: string = 'gemini-2.5-flash'
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
