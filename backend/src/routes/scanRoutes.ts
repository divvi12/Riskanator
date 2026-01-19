import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { ScanRequest, ScanResult, ExtendedScanResult, Exposure } from '../types';
import { cloneRepository, cleanupRepository, detectLanguages } from '../services/gitService';
import { scanRepository } from '../services/scannerService';
import { enrichCVEs } from '../services/cveEnrichmentService';
import { processCVEs, generateScanSummary } from '../services/riskCalculatorService';
import { generateTopology, generateRemediationGroups } from '../services/topologyService';
import { runExposureScanning } from '../services/exposureScannerService';

const router = Router();

// In-memory storage for scan results (would be database in production)
const scanResults: Map<string, ScanResult> = new Map();
const extendedScanResults: Map<string, ExtendedScanResult> = new Map();

// Start a new scan
router.post('/scan', async (req: Request, res: Response) => {
  const { repoUrl, isPrivate, pat, branch, context }: ScanRequest = req.body;

  // Validate input
  if (!repoUrl) {
    return res.status(400).json({ error: 'Repository URL is required' });
  }

  const scanId = uuidv4();
  const startTime = new Date().toISOString();

  // Initialize scan result
  const scanResult: ScanResult = {
    scanId,
    status: 'pending',
    progress: 0,
    progressMessage: 'Initializing scan...',
    metadata: {
      repoUrl,
      branch: branch || 'main',
      context,
      languages: [],
      scanTypes: [],
      startTime
    }
  };

  scanResults.set(scanId, scanResult);

  // Return immediately with scan ID
  res.json({ scanId, status: 'pending' });

  // Process scan asynchronously
  processScan(scanId, repoUrl, isPrivate || false, pat, branch || 'main', context);
});

// Get scan status
router.get('/scan/:scanId/status', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const result = scanResults.get(scanId);

  if (!result) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  res.json({
    scanId: result.scanId,
    status: result.status,
    progress: result.progress,
    progressMessage: result.progressMessage,
    error: result.error
  });
});

// Get scan results
router.get('/scan/:scanId/results', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const result = scanResults.get(scanId);

  if (!result) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  if (result.status !== 'complete' && result.status !== 'error') {
    return res.status(202).json({
      scanId: result.scanId,
      status: result.status,
      progress: result.progress,
      progressMessage: result.progressMessage
    });
  }

  res.json(result);
});

// Get all scans (for history)
router.get('/scans', (req: Request, res: Response) => {
  const scans = Array.from(scanResults.values()).map(scan => ({
    scanId: scan.scanId,
    status: scan.status,
    repoUrl: scan.metadata?.repoUrl,
    startTime: scan.metadata?.startTime,
    totalCVEs: scan.summary?.totalCVEs || 0
  }));

  res.json(scans);
});

// Delete a scan
router.delete('/scan/:scanId', (req: Request, res: Response) => {
  const { scanId } = req.params;

  if (!scanResults.has(scanId) && !extendedScanResults.has(scanId)) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  scanResults.delete(scanId);
  extendedScanResults.delete(scanId);
  res.json({ success: true });
});

// ============================================================
// EXTENDED EXPOSURE SCANNING ROUTES (NEW)
// ============================================================

// Start a new exposure scan (scans all 6 exposure types)
router.post('/exposure-scan', async (req: Request, res: Response) => {
  const { repoUrl, isPrivate, pat, branch, context }: ScanRequest = req.body;

  // Validate input
  if (!repoUrl) {
    return res.status(400).json({ error: 'Repository URL is required' });
  }

  const scanId = uuidv4();
  const startTime = new Date().toISOString();

  // Initialize extended scan result
  const scanResult: ExtendedScanResult = {
    scanId,
    status: 'pending',
    progress: 0,
    progressMessage: 'Initializing exposure scan...',
    metadata: {
      repoUrl,
      branch: branch || 'main',
      context,
      languages: [],
      scanTypes: ['cve', 'certificate', 'secret', 'misconfiguration', 'license', 'code-security'],
      startTime
    }
  };

  extendedScanResults.set(scanId, scanResult);

  // Return immediately with scan ID
  res.json({ scanId, status: 'pending' });

  // Process scan asynchronously
  processExposureScan(scanId, repoUrl, isPrivate || false, pat, branch || 'main', context);
});

// Get exposure scan status
router.get('/exposure-scan/:scanId/status', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const result = extendedScanResults.get(scanId);

  if (!result) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  res.json({
    scanId: result.scanId,
    status: result.status,
    progress: result.progress,
    progressMessage: result.progressMessage,
    error: result.error
  });
});

// Get exposure scan results
router.get('/exposure-scan/:scanId/results', (req: Request, res: Response) => {
  const { scanId } = req.params;
  const result = extendedScanResults.get(scanId);

  if (!result) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  if (result.status !== 'complete' && result.status !== 'error') {
    return res.status(202).json({
      scanId: result.scanId,
      status: result.status,
      progress: result.progress,
      progressMessage: result.progressMessage
    });
  }

  res.json(result);
});

// Get all exposure scans (for history)
router.get('/exposure-scans', (req: Request, res: Response) => {
  const scans = Array.from(extendedScanResults.values()).map(scan => ({
    scanId: scan.scanId,
    status: scan.status,
    repoUrl: scan.metadata?.repoUrl,
    startTime: scan.metadata?.startTime,
    totalExposures: scan.summary?.totalExposures || 0,
    byType: scan.summary?.byType || {}
  }));

  res.json(scans);
});

// Recalculate scores with new application context
router.post('/recalculate-scores', async (req: Request, res: Response) => {
  const { exposures, context } = req.body;

  if (!exposures || !Array.isArray(exposures)) {
    return res.status(400).json({ error: 'Exposures array is required' });
  }

  try {
    // Import the recalculation functions
    const { processExposures, applySLAToExposures, calculateOverallConcertScore, calculateOverallDetailedScore } = await import('../services/exposureRiskService');

    // Ensure all exposures have required fields
    const normalizedExposures = exposures.map(exp => ({
      ...exp,
      detectedAt: exp.detectedAt || new Date().toISOString(),
      severity: exp.severity || 'medium',
      type: exp.type || 'cve'
    }));

    // Build full ApplicationContext from frontend context
    const appContext = context ? {
      appName: 'Application',
      industry: 'Technology',
      purpose: 'General',
      criticality: context.criticality || 3,
      dataSensitivity: {
        pii: context.dataSensitivity?.pii || false,
        phi: context.dataSensitivity?.phi || false,
        pci: context.dataSensitivity?.pci || false,
        tradeSecrets: false
      },
      accessControls: {
        publicEndpoints: context.publicEndpoints || 0,
        privateEndpoints: context.privateEndpoints || 5,
        networkExposure: (context.networkExposure || 'internal') as 'internal' | 'dmz' | 'public',
        controls: context.requiresAuth !== false ? ['authentication'] : []
      },
      formula: 'concert' as const
    } : undefined;

    // Recalculate risk scores for each exposure with new context
    const recalculatedExposures = processExposures(normalizedExposures, appContext);

    // Apply SLA calculations
    const exposuresWithSLA = applySLAToExposures(recalculatedExposures, appContext);

    // Calculate overall scores
    const concertScore = calculateOverallConcertScore(exposuresWithSLA);
    const detailedScore = calculateOverallDetailedScore(exposuresWithSLA);

    // Generate updated summary
    const byType = { cve: 0, certificate: 0, secret: 0, misconfiguration: 0, license: 0, codeSecurity: 0 };
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const slaStatus = { overdue: 0, dueSoon: 0, onTrack: 0, complianceRate: 0 };

    for (const exposure of exposuresWithSLA) {
      // Count by type
      if (exposure.type === 'cve') byType.cve++;
      else if (exposure.type === 'certificate') byType.certificate++;
      else if (exposure.type === 'secret') byType.secret++;
      else if (exposure.type === 'misconfiguration') byType.misconfiguration++;
      else if (exposure.type === 'license') byType.license++;
      else if (exposure.type === 'code-security') byType.codeSecurity++;

      // Count by severity
      bySeverity[exposure.severity]++;

      // Count SLA status
      if (exposure.slaStatus === 'overdue') slaStatus.overdue++;
      else if (exposure.slaStatus === 'due_soon') slaStatus.dueSoon++;
      else slaStatus.onTrack++;
    }

    slaStatus.complianceRate = exposuresWithSLA.length > 0
      ? Math.round(((exposuresWithSLA.length - slaStatus.overdue) / exposuresWithSLA.length) * 100)
      : 100;

    res.json({
      exposures: exposuresWithSLA,
      summary: {
        totalExposures: exposuresWithSLA.length,
        critical: bySeverity.critical,
        high: bySeverity.high,
        medium: bySeverity.medium,
        low: bySeverity.low,
        riskScore: { concert: concertScore, comprehensive: detailedScore },
        byType,
        slaStatus
      }
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Recalculation failed';
    res.status(500).json({ error: errorMessage });
  }
});

// Async exposure scan processing
async function processExposureScan(
  scanId: string,
  repoUrl: string,
  isPrivate: boolean,
  pat: string | undefined,
  branch: string,
  context?: ScanRequest['context']
) {
  const updateStatus = (
    status: ExtendedScanResult['status'],
    progress: number,
    message: string,
    error?: string
  ) => {
    const result = extendedScanResults.get(scanId);
    if (result) {
      result.status = status;
      result.progress = progress;
      result.progressMessage = message;
      if (error) result.error = error;
      extendedScanResults.set(scanId, result);
    }
  };

  let localPath = '';

  try {
    // Step 1: Clone repository
    updateStatus('cloning', 10, 'Cloning repository...');
    const cloneResult = await cloneRepository(repoUrl, isPrivate, pat, branch);

    if (!cloneResult.success) {
      updateStatus('error', 0, 'Clone failed', cloneResult.error);
      return;
    }

    localPath = cloneResult.localPath;

    // Step 2: Detect languages (quick operation)
    updateStatus('detecting', 12, 'Detecting languages and technologies...');
    const languages = detectLanguages(localPath);

    const result = extendedScanResults.get(scanId);
    if (result?.metadata) {
      result.metadata.languages = languages;
      extendedScanResults.set(scanId, result);
    }

    updateStatus('scanning', 15, `Detected ${languages.length} language(s): ${languages.join(', ')}. Starting scans...`);

    // Step 3: Run comprehensive exposure scanning immediately
    const exposureResult = await runExposureScanning(
      localPath,
      languages,
      context,
      (msg) => {
        const currentResult = extendedScanResults.get(scanId);
        if (currentResult) {
          // Update progress based on scan phase - more granular
          let progress = 15;

          // Starting phases
          if (msg.includes('Starting CVE')) progress = 18;
          else if (msg.includes('npm audit')) progress = 22;
          else if (msg.includes('pip-audit')) progress = 26;
          else if (msg.includes('Trivy')) progress = 30;
          else if (msg.includes('Semgrep')) progress = 34;

          // Discovery messages
          else if (msg.includes('Found') && msg.includes('CVE')) progress = 40;
          else if (msg.includes('Enriching') && msg.includes('parallel')) progress = 42;
          else if (msg.includes('Enriching CVE data (')) {
            // Extract progress from enrichment message
            const match = msg.match(/\((\d+)\/(\d+)\)/);
            if (match) {
              const pct = parseInt(match[1]) / parseInt(match[2]);
              progress = 42 + Math.round(pct * 30); // 42-72% for enrichment
            }
          }
          else if (msg.includes('Found') && msg.includes('certificate')) progress = 45;
          else if (msg.includes('Found') && msg.includes('secret')) progress = 50;
          else if (msg.includes('Found') && msg.includes('misconfiguration')) progress = 55;
          else if (msg.includes('Found') && msg.includes('license')) progress = 60;
          else if (msg.includes('WARNING') && msg.includes('CISA')) progress = 75;
          else if (msg.includes('Scan complete')) progress = 80;

          // Post-processing
          else if (msg.includes('risk')) progress = 85;
          else if (msg.includes('SLA')) progress = 90;
          else if (msg.includes('remediation')) progress = 95;

          currentResult.progressMessage = msg;
          currentResult.progress = progress;
          extendedScanResults.set(scanId, currentResult);
        }
      }
    );

    // Step 4: Generate topology (optional)
    updateStatus('enriching', 96, 'Generating application topology...');

    // Convert exposures to CVE format for topology (if needed)
    const cveExposures = exposureResult.exposures
      .filter(e => e.type === 'cve')
      .map(e => ({
        id: (e as any).cveId,
        cvss: (e as any).cvss || 5.0,
        component: (e as any).component,
        version: (e as any).version,
        fixedVersion: (e as any).fixedVersion,
        source: e.source as any,
        sourceType: (e as any).sourceType || 'sca',
        severity: e.severity,
        description: e.description,
        cisaKEV: (e as any).cisaKEV || false
      }));

    const topology = await generateTopology(localPath, languages, cveExposures);

    // Update final result
    const finalResult = extendedScanResults.get(scanId);
    if (finalResult) {
      finalResult.status = 'complete';
      finalResult.progress = 100;
      finalResult.progressMessage = 'Exposure scan complete';
      finalResult.exposures = exposureResult.exposures;
      finalResult.summary = exposureResult.summary;
      finalResult.remediationGroups = exposureResult.remediationGroups;
      finalResult.topology = topology;

      if (finalResult.metadata) {
        finalResult.metadata.endTime = new Date().toISOString();
      }
      extendedScanResults.set(scanId, finalResult);
    }

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    updateStatus('error', 0, 'Scan failed', errorMessage);
  } finally {
    // Cleanup cloned repository
    if (localPath) {
      await cleanupRepository(localPath);
    }
  }
}

// ============================================================
// LEGACY CVE-ONLY SCANNING (BACKWARD COMPATIBILITY)
// ============================================================

// Async scan processing
async function processScan(
  scanId: string,
  repoUrl: string,
  isPrivate: boolean,
  pat: string | undefined,
  branch: string,
  context?: ScanRequest['context']
) {
  const updateStatus = (
    status: ScanResult['status'],
    progress: number,
    message: string,
    error?: string
  ) => {
    const result = scanResults.get(scanId);
    if (result) {
      result.status = status;
      result.progress = progress;
      result.progressMessage = message;
      if (error) result.error = error;
      scanResults.set(scanId, result);
    }
  };

  let localPath = '';

  try {
    // Step 1: Clone repository
    updateStatus('cloning', 10, 'Cloning repository...');
    const cloneResult = await cloneRepository(repoUrl, isPrivate, pat, branch);

    if (!cloneResult.success) {
      updateStatus('error', 0, 'Clone failed', cloneResult.error);
      return;
    }

    localPath = cloneResult.localPath;

    // Step 2: Detect languages
    updateStatus('detecting', 20, 'Detecting languages and technologies...');
    const languages = detectLanguages(localPath);

    const result = scanResults.get(scanId);
    if (result?.metadata) {
      result.metadata.languages = languages;
      scanResults.set(scanId, result);
    }

    // Step 3: Run vulnerability scans
    updateStatus('scanning', 30, 'Running vulnerability scans...');
    let cves = await scanRepository(localPath, languages, (msg) => {
      const currentResult = scanResults.get(scanId);
      if (currentResult) {
        currentResult.progressMessage = msg;
        scanResults.set(scanId, currentResult);
      }
    });

    updateStatus('scanning', 50, `Found ${cves.length} vulnerabilities, enriching data...`);

    // Step 4: Enrich CVEs with NVD/EPSS/KEV data
    updateStatus('enriching', 60, 'Enriching CVE data from NVD, EPSS, and CISA KEV...');

    // Only enrich CVEs with actual CVE IDs (not GHSA or others) to save API calls
    const cveIdsToEnrich = cves.filter(cve => cve.id.startsWith('CVE-'));
    const enrichedCves = await enrichCVEs(cveIdsToEnrich, (current, total) => {
      const progress = 60 + Math.round((current / total) * 25);
      updateStatus('enriching', progress, `Enriching CVE data (${current}/${total})...`);
    });

    // Merge enriched data back
    const enrichedMap = new Map(enrichedCves.map(cve => [cve.id, cve]));
    cves = cves.map(cve => enrichedMap.get(cve.id) || cve);

    // Step 5: Calculate risk scores and SLA
    updateStatus('enriching', 85, 'Calculating risk scores and SLA...');
    const processedCves = processCVEs(cves, context);

    // Step 6: Generate summary
    const summary = generateScanSummary(processedCves, context);

    // Step 7: Generate topology
    updateStatus('enriching', 92, 'Generating application topology...');
    const topology = await generateTopology(localPath, languages, processedCves);

    // Step 8: Generate remediation groups
    updateStatus('enriching', 96, 'Generating remediation groups...');
    const remediationGroups = generateRemediationGroups(processedCves);

    // Update final result
    const finalResult = scanResults.get(scanId);
    if (finalResult) {
      finalResult.status = 'complete';
      finalResult.progress = 100;
      finalResult.progressMessage = 'Scan complete';
      finalResult.cves = processedCves;
      finalResult.summary = summary;
      finalResult.topology = topology;
      finalResult.remediationGroups = remediationGroups;
      if (finalResult.metadata) {
        finalResult.metadata.endTime = new Date().toISOString();
        finalResult.metadata.scanTypes = [...new Set(cves.map(c => c.sourceType))];
      }
      scanResults.set(scanId, finalResult);
    }

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    updateStatus('error', 0, 'Scan failed', errorMessage);
  } finally {
    // Cleanup cloned repository
    if (localPath) {
      await cleanupRepository(localPath);
    }
  }
}

export default router;
