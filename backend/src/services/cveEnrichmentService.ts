import axios from 'axios';
import Bottleneck from 'bottleneck';
import { CVE } from '../types';

// Rate limiters for external APIs
// NVD: Without API key = 5 req/30s, With API key = 50 req/30s
const nvdLimiter = new Bottleneck({
  minTime: process.env.NVD_API_KEY ? 600 : 6000,
  maxConcurrent: process.env.NVD_API_KEY ? 2 : 1, // Allow 2 concurrent with API key
  reservoir: process.env.NVD_API_KEY ? 50 : 5,
  reservoirRefreshAmount: process.env.NVD_API_KEY ? 50 : 5,
  reservoirRefreshInterval: 30 * 1000
});

const epssLimiter = new Bottleneck({
  minTime: 100,
  maxConcurrent: 5
});

// CISA KEV cache
let kevCache: Set<string> | null = null;
let kevLastFetch: number = 0;
const KEV_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// CVE Enrichment Cache with LRU eviction
const CVE_CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours
const MAX_CACHE_SIZE = 10000;

interface CachedCVEData {
  nvdData: Partial<CVE>;
  epssData: { epss?: number; epssPercentile?: number };
  cachedAt: number;
}

class CVECache {
  private cache: Map<string, CachedCVEData> = new Map();
  private accessOrder: string[] = [];
  private hits = 0;
  private misses = 0;

  get(cveId: string): CachedCVEData | null {
    const entry = this.cache.get(cveId);
    if (!entry) {
      this.misses++;
      return null;
    }

    // Check TTL
    if (Date.now() - entry.cachedAt > CVE_CACHE_TTL) {
      this.cache.delete(cveId);
      this.misses++;
      return null;
    }

    // Update access order for LRU
    this.accessOrder = this.accessOrder.filter(id => id !== cveId);
    this.accessOrder.push(cveId);
    this.hits++;

    return entry;
  }

  set(cveId: string, data: CachedCVEData): void {
    // Evict oldest if at capacity
    while (this.cache.size >= MAX_CACHE_SIZE && this.accessOrder.length > 0) {
      const oldest = this.accessOrder.shift()!;
      this.cache.delete(oldest);
    }

    this.cache.set(cveId, data);
    this.accessOrder.push(cveId);
  }

  getStats(): { size: number; hits: number; misses: number; hitRate: number } {
    const total = this.hits + this.misses;
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? Math.round((this.hits / total) * 100) : 0
    };
  }
}

const cveCache = new CVECache();

interface NVDResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string;
      descriptions: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: {
            baseScore: number;
            vectorString: string;
          };
        }>;
        cvssMetricV30?: Array<{
          cvssData: {
            baseScore: number;
            vectorString: string;
          };
        }>;
        cvssMetricV2?: Array<{
          cvssData: {
            baseScore: number;
          };
        }>;
      };
      references?: Array<{
        url: string;
      }>;
    };
  }>;
}

interface EPSSResponse {
  data?: Array<{
    cve: string;
    epss: string;
    percentile: string;
  }>;
}

interface KEVResponse {
  vulnerabilities: Array<{
    cveID: string;
    dateAdded: string;
  }>;
}

// Fetch CISA KEV list
async function fetchKEVList(): Promise<Set<string>> {
  const now = Date.now();

  if (kevCache && now - kevLastFetch < KEV_CACHE_TTL) {
    return kevCache;
  }

  try {
    const response = await axios.get<KEVResponse>(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { timeout: 30000 }
    );

    kevCache = new Set(response.data.vulnerabilities.map(v => v.cveID));
    kevLastFetch = now;
    return kevCache;
  } catch (error) {
    console.error('Error fetching CISA KEV list:', error);
    return kevCache || new Set();
  }
}

// Fetch CVE data from NVD
async function fetchNVDData(cveId: string): Promise<Partial<CVE>> {
  return nvdLimiter.schedule(async () => {
    try {
      const headers: Record<string, string> = {};
      if (process.env.NVD_API_KEY) {
        headers['apiKey'] = process.env.NVD_API_KEY;
      }

      const response = await axios.get<NVDResponse>(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
        { headers, timeout: 30000 }
      );

      const vuln = response.data.vulnerabilities?.[0]?.cve;
      if (!vuln) {
        return {};
      }

      // Get CVSS score
      let cvss = 0;
      let cvssVector = '';

      if (vuln.metrics?.cvssMetricV31?.[0]) {
        cvss = vuln.metrics.cvssMetricV31[0].cvssData.baseScore;
        cvssVector = vuln.metrics.cvssMetricV31[0].cvssData.vectorString;
      } else if (vuln.metrics?.cvssMetricV30?.[0]) {
        cvss = vuln.metrics.cvssMetricV30[0].cvssData.baseScore;
        cvssVector = vuln.metrics.cvssMetricV30[0].cvssData.vectorString;
      } else if (vuln.metrics?.cvssMetricV2?.[0]) {
        cvss = vuln.metrics.cvssMetricV2[0].cvssData.baseScore;
      }

      // Get description
      const description = vuln.descriptions?.find(d => d.lang === 'en')?.value || '';

      // Get references
      const references = vuln.references?.map(r => r.url) || [];

      return {
        cvss,
        cvssVector,
        description: description || undefined,
        references
      };
    } catch (error) {
      console.error(`Error fetching NVD data for ${cveId}:`, error);
      return {};
    }
  });
}

// Fetch EPSS score from FIRST.org
async function fetchEPSSData(cveId: string): Promise<{ epss?: number; epssPercentile?: number }> {
  return epssLimiter.schedule(async () => {
    try {
      const response = await axios.get<EPSSResponse>(
        `https://api.first.org/data/v1/epss?cve=${cveId}`,
        { timeout: 10000 }
      );

      const data = response.data.data?.[0];
      if (!data) {
        return {};
      }

      return {
        epss: parseFloat(data.epss) * 100, // Convert to percentage
        epssPercentile: parseFloat(data.percentile) * 100
      };
    } catch (error) {
      console.error(`Error fetching EPSS data for ${cveId}:`, error);
      return {};
    }
  });
}

// Bulk fetch EPSS data for multiple CVEs (much faster than individual calls)
const EPSS_BULK_SIZE = 30; // Max CVEs per request to avoid URL length limits

async function fetchEPSSDataBulk(cveIds: string[]): Promise<Map<string, { epss?: number; epssPercentile?: number }>> {
  const results = new Map<string, { epss?: number; epssPercentile?: number }>();

  if (cveIds.length === 0) return results;

  // Process in chunks
  for (let i = 0; i < cveIds.length; i += EPSS_BULK_SIZE) {
    const chunk = cveIds.slice(i, i + EPSS_BULK_SIZE);

    await epssLimiter.schedule(async () => {
      try {
        const cveParam = chunk.join(',');
        const response = await axios.get<EPSSResponse>(
          `https://api.first.org/data/v1/epss?cve=${cveParam}`,
          { timeout: 30000 }
        );

        for (const data of response.data.data || []) {
          results.set(data.cve, {
            epss: parseFloat(data.epss) * 100,
            epssPercentile: parseFloat(data.percentile) * 100
          });
        }
      } catch (error) {
        console.error('Error fetching bulk EPSS data:', error);
        // Individual CVEs that failed will have undefined EPSS
      }
    });
  }

  return results;
}

// Check if CVE is in CISA KEV
async function checkKEV(cveId: string): Promise<{ cisaKEV: boolean; kevDateAdded?: string }> {
  const kevList = await fetchKEVList();
  return {
    cisaKEV: kevList.has(cveId)
  };
}

// Enrich a single CVE
export async function enrichCVE(cve: CVE): Promise<CVE> {
  // Only enrich CVEs with proper CVE IDs
  if (!cve.id.startsWith('CVE-')) {
    return cve;
  }

  try {
    const [nvdData, epssData, kevData] = await Promise.all([
      fetchNVDData(cve.id),
      fetchEPSSData(cve.id),
      checkKEV(cve.id)
    ]);

    return {
      ...cve,
      cvss: nvdData.cvss || cve.cvss,
      cvssVector: nvdData.cvssVector || cve.cvssVector,
      description: nvdData.description || cve.description,
      references: [...(cve.references || []), ...(nvdData.references || [])].filter((v, i, a) => a.indexOf(v) === i),
      epss: epssData.epss,
      epssPercentile: epssData.epssPercentile,
      cisaKEV: kevData.cisaKEV,
      kevDateAdded: kevData.kevDateAdded,
      severity: getSeverityFromCvss(nvdData.cvss || cve.cvss)
    };
  } catch (error) {
    console.error(`Error enriching CVE ${cve.id}:`, error);
    return cve;
  }
}

// Batch enrich CVEs with caching and bulk EPSS
export async function enrichCVEs(
  cves: CVE[],
  onProgress?: (current: number, total: number) => void
): Promise<CVE[]> {
  const cveList = cves.filter(cve => cve.id.startsWith('CVE-'));
  const total = cveList.length;

  if (total === 0) return cves;

  onProgress?.(0, total);

  // Separate cached vs uncached CVEs
  const cachedCves: CVE[] = [];
  const uncachedCves: CVE[] = [];
  const uncachedIds: string[] = [];

  for (const cve of cveList) {
    const cached = cveCache.get(cve.id);
    if (cached) {
      cachedCves.push(cve);
    } else {
      uncachedCves.push(cve);
      uncachedIds.push(cve.id);
    }
  }

  console.log(`CVE Cache: ${cachedCves.length} hits, ${uncachedCves.length} misses`);

  // Pre-fetch all EPSS data in bulk for uncached CVEs (much faster!)
  const epssDataMap = uncachedIds.length > 0
    ? await fetchEPSSDataBulk(uncachedIds)
    : new Map();

  // Pre-fetch KEV list (single call, cached)
  const kevList = await fetchKEVList();

  // Process cached CVEs quickly (no API calls needed for NVD/EPSS)
  const enrichedCves: CVE[] = [];

  for (const cve of cachedCves) {
    const cached = cveCache.get(cve.id)!;
    const cisaKEV = kevList.has(cve.id);

    enrichedCves.push({
      ...cve,
      cvss: cached.nvdData.cvss || cve.cvss,
      cvssVector: cached.nvdData.cvssVector || cve.cvssVector,
      description: cached.nvdData.description || cve.description,
      references: [...(cve.references || []), ...(cached.nvdData.references || [])].filter((v, i, a) => a.indexOf(v) === i),
      epss: cached.epssData.epss,
      epssPercentile: cached.epssData.epssPercentile,
      cisaKEV,
      severity: getSeverityFromCvss(cached.nvdData.cvss || cve.cvss)
    });
  }

  // Process uncached CVEs (need NVD API calls)
  // With API key we can process more in parallel since we have 2 concurrent + 600ms minTime
  const batchSize = process.env.NVD_API_KEY ? 10 : 5;
  let processed = cachedCves.length;

  // Count how many CVEs need NVD calls vs have good scanner data
  const needsNVD = uncachedCves.filter(cve => !(cve.cvss && cve.cvss > 0 && cve.description && cve.description.length > 20));
  const hasGoodData = uncachedCves.length - needsNVD.length;
  console.log(`Processing ${uncachedCves.length} uncached CVEs: ${hasGoodData} have scanner data, ${needsNVD.length} need NVD calls`);

  for (let i = 0; i < uncachedCves.length; i += batchSize) {
    const batch = uncachedCves.slice(i, i + batchSize);

    const enrichedBatch = await Promise.all(batch.map(async (cve) => {
      const epssData = epssDataMap.get(cve.id) || {};
      const cisaKEV = kevList.has(cve.id);

      // Skip NVD call if scanner already provided good data (CVSS and description)
      const hasGoodData = cve.cvss && cve.cvss > 0 && cve.description && cve.description.length > 20;
      const nvdData = hasGoodData ? { cvss: cve.cvss, description: cve.description } : await fetchNVDData(cve.id);

      // Cache the results for future use
      cveCache.set(cve.id, {
        nvdData,
        epssData,
        cachedAt: Date.now()
      });

      return {
        ...cve,
        cvss: nvdData.cvss || cve.cvss,
        cvssVector: nvdData.cvssVector || cve.cvssVector,
        description: nvdData.description || cve.description,
        references: [...(cve.references || []), ...(nvdData.references || [])].filter((v, i, a) => a.indexOf(v) === i),
        epss: epssData.epss,
        epssPercentile: epssData.epssPercentile,
        cisaKEV,
        severity: getSeverityFromCvss(nvdData.cvss || cve.cvss)
      };
    }));

    enrichedCves.push(...enrichedBatch);
    processed += batch.length;
    onProgress?.(processed, total);
  }

  // Merge back non-CVE entries and maintain order
  const enrichedMap = new Map(enrichedCves.map(cve => [cve.id, cve]));
  return cves.map(cve => enrichedMap.get(cve.id) || cve);
}

// Export cache stats for monitoring
export function getCacheStats() {
  return cveCache.getStats();
}

function getSeverityFromCvss(cvss: number): 'critical' | 'high' | 'medium' | 'low' {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  return 'low';
}
