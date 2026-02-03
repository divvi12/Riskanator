import axios from 'axios';
import { ScanRequest, ScanResult } from '../types';
import { API_BASE_URL } from '../config';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Exposure Scan endpoints (all 6 types: CVE, secrets, certs, misconfig, license, code-security)
export async function startScan(request: ScanRequest): Promise<{ scanId: string; status: string }> {
  const response = await api.post('/exposure-scan', request);
  return response.data;
}

export async function getScanStatus(scanId: string): Promise<{
  scanId: string;
  status: string;
  progress: number;
  progressMessage: string;
  error?: string;
}> {
  const response = await api.get(`/exposure-scan/${scanId}/status`);
  return response.data;
}

export async function getScanResults(scanId: string): Promise<ScanResult> {
  const response = await api.get(`/exposure-scan/${scanId}/results`);
  return response.data;
}

export async function getAllScans(): Promise<Array<{
  scanId: string;
  status: string;
  repoUrl: string;
  startTime: string;
  totalExposures: number;
  byType: Record<string, number>;
}>> {
  const response = await api.get('/exposure-scans');
  return response.data;
}

export async function deleteScan(scanId: string): Promise<void> {
  // Try exposure-scan first, then fall back to legacy
  try {
    await api.delete(`/scan/${scanId}`);
  } catch {
    // Scan might be in the exposure-scan store
  }
}

// Health check
export async function checkHealth(): Promise<{ status: string; timestamp: string; version: string }> {
  const response = await api.get('/health');
  return response.data;
}

// Recalculate scores with new application context
export async function recalculateScores(exposures: any[], context: any): Promise<{
  exposures: any[];
  summary: any;
}> {
  const response = await api.post('/recalculate-scores', { exposures, context });
  return response.data;
}

// Poll scan status until complete
export async function pollScanStatus(
  scanId: string,
  onProgress?: (status: string, progress: number, message: string) => void,
  interval: number = 2000
): Promise<ScanResult> {
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const status = await getScanStatus(scanId);

        if (onProgress) {
          onProgress(status.status, status.progress, status.progressMessage);
        }

        if (status.status === 'complete') {
          const results = await getScanResults(scanId);
          resolve(results);
        } else if (status.status === 'error') {
          reject(new Error(status.error || 'Scan failed'));
        } else {
          setTimeout(poll, interval);
        }
      } catch (error) {
        reject(error);
      }
    };

    poll();
  });
}

// Gemini AI endpoints
export async function initializeGemini(apiKey: string, validate: boolean = false): Promise<{ success: boolean; message?: string; error?: string }> {
  const response = await api.post('/ai/initialize', { apiKey, validate });
  return response.data;
}

// Validate Gemini API key with a real API call
export async function validateGeminiApiKey(apiKey: string): Promise<{ success: boolean; message?: string; error?: string }> {
  return initializeGemini(apiKey, true);
}

export async function getGeminiStatus(): Promise<{ initialized: boolean }> {
  const response = await api.get('/ai/status');
  return response.data;
}

export async function explainExposure(
  exposure: any,
  context?: any,
  model?: string
): Promise<{
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
}> {
  const response = await api.post('/ai/explain', { exposure, context, model });
  return response.data;
}

export default api;
