import * as fs from 'fs';
import * as path from 'path';
import { CVE } from '../types';

export interface TopologyNode {
  id: string;
  name: string;
  type: 'application' | 'service' | 'database' | 'cache' | 'queue' | 'external' | 'storage' | 'container';
  technology?: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'healthy';
  cveCount: number;
  exposureCount: number;
  x?: number;
  y?: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  label?: string;
  protocol?: string;
  encrypted?: boolean;
}

export interface ApplicationTopology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

// Detect application topology from codebase
export async function generateTopology(
  repoPath: string,
  languages: string[],
  cves: CVE[]
): Promise<ApplicationTopology> {
  const nodes: TopologyNode[] = [];
  const edges: TopologyEdge[] = [];

  // Create main application node
  const appName = path.basename(repoPath);
  const mainAppNode: TopologyNode = {
    id: 'main-app',
    name: appName,
    type: 'application',
    technology: languages.join(', '),
    riskLevel: calculateNodeRiskLevel(cves),
    cveCount: cves.length,
    exposureCount: 0,
    x: 400,
    y: 300
  };
  nodes.push(mainAppNode);

  // Detect services from package.json
  const packageJsonPath = path.join(repoPath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };

      // Detect databases
      if (deps['mongodb'] || deps['mongoose']) {
        nodes.push(createDatabaseNode('mongodb', 'MongoDB', cves));
        edges.push({ source: 'main-app', target: 'mongodb', label: 'MongoDB', protocol: 'mongodb', encrypted: true });
      }
      if (deps['pg'] || deps['postgres'] || deps['postgresql']) {
        nodes.push(createDatabaseNode('postgres', 'PostgreSQL', cves));
        edges.push({ source: 'main-app', target: 'postgres', label: 'SQL', protocol: 'postgres', encrypted: true });
      }
      if (deps['mysql'] || deps['mysql2']) {
        nodes.push(createDatabaseNode('mysql', 'MySQL', cves));
        edges.push({ source: 'main-app', target: 'mysql', label: 'SQL', protocol: 'mysql', encrypted: true });
      }
      if (deps['sqlite3'] || deps['better-sqlite3']) {
        nodes.push(createDatabaseNode('sqlite', 'SQLite', cves));
        edges.push({ source: 'main-app', target: 'sqlite', label: 'File', protocol: 'file', encrypted: false });
      }

      // Detect caches
      if (deps['redis'] || deps['ioredis']) {
        nodes.push(createCacheNode('redis', 'Redis', cves));
        edges.push({ source: 'main-app', target: 'redis', label: 'Cache', protocol: 'redis', encrypted: false });
      }
      if (deps['memcached']) {
        nodes.push(createCacheNode('memcached', 'Memcached', cves));
        edges.push({ source: 'main-app', target: 'memcached', label: 'Cache', protocol: 'memcache', encrypted: false });
      }

      // Detect message queues
      if (deps['amqplib'] || deps['amqp']) {
        nodes.push(createQueueNode('rabbitmq', 'RabbitMQ', cves));
        edges.push({ source: 'main-app', target: 'rabbitmq', label: 'AMQP', protocol: 'amqp', encrypted: true });
      }
      if (deps['kafkajs'] || deps['kafka-node']) {
        nodes.push(createQueueNode('kafka', 'Kafka', cves));
        edges.push({ source: 'main-app', target: 'kafka', label: 'Kafka', protocol: 'kafka', encrypted: true });
      }
      if (deps['bull'] || deps['bullmq']) {
        // Bull uses Redis
        if (!nodes.find(n => n.id === 'redis')) {
          nodes.push(createCacheNode('redis', 'Redis (Queue)', cves));
          edges.push({ source: 'main-app', target: 'redis', label: 'Queue', protocol: 'redis', encrypted: false });
        }
      }

      // Detect external services
      if (deps['aws-sdk'] || deps['@aws-sdk/client-s3']) {
        nodes.push(createExternalNode('aws-s3', 'AWS S3', cves));
        edges.push({ source: 'main-app', target: 'aws-s3', label: 'HTTPS', protocol: 'https', encrypted: true });
      }
      if (deps['stripe']) {
        nodes.push(createExternalNode('stripe', 'Stripe API', cves));
        edges.push({ source: 'main-app', target: 'stripe', label: 'HTTPS', protocol: 'https', encrypted: true });
      }
      if (deps['twilio']) {
        nodes.push(createExternalNode('twilio', 'Twilio', cves));
        edges.push({ source: 'main-app', target: 'twilio', label: 'HTTPS', protocol: 'https', encrypted: true });
      }
      if (deps['@sendgrid/mail'] || deps['nodemailer']) {
        nodes.push(createExternalNode('email', 'Email Service', cves));
        edges.push({ source: 'main-app', target: 'email', label: 'SMTP', protocol: 'smtp', encrypted: true });
      }

      // Detect storage
      if (deps['multer'] || deps['formidable']) {
        nodes.push(createStorageNode('local-storage', 'Local Storage', cves));
        edges.push({ source: 'main-app', target: 'local-storage', label: 'File', protocol: 'file', encrypted: false });
      }
    } catch (error) {
      console.error('Error parsing package.json:', error);
    }
  }

  // Detect from docker-compose.yml
  const dockerComposePath = path.join(repoPath, 'docker-compose.yml');
  const dockerComposeAltPath = path.join(repoPath, 'docker-compose.yaml');
  const composeFile = fs.existsSync(dockerComposePath) ? dockerComposePath :
    fs.existsSync(dockerComposeAltPath) ? dockerComposeAltPath : null;

  if (composeFile) {
    try {
      const composeContent = fs.readFileSync(composeFile, 'utf-8');

      // Simple pattern matching for common services
      if (composeContent.includes('postgres') || composeContent.includes('postgresql')) {
        if (!nodes.find(n => n.id === 'postgres')) {
          nodes.push(createDatabaseNode('postgres', 'PostgreSQL', cves));
          edges.push({ source: 'main-app', target: 'postgres', label: 'SQL', protocol: 'postgres', encrypted: true });
        }
      }
      if (composeContent.includes('mysql') || composeContent.includes('mariadb')) {
        if (!nodes.find(n => n.id === 'mysql')) {
          nodes.push(createDatabaseNode('mysql', 'MySQL/MariaDB', cves));
          edges.push({ source: 'main-app', target: 'mysql', label: 'SQL', protocol: 'mysql', encrypted: true });
        }
      }
      if (composeContent.includes('mongo')) {
        if (!nodes.find(n => n.id === 'mongodb')) {
          nodes.push(createDatabaseNode('mongodb', 'MongoDB', cves));
          edges.push({ source: 'main-app', target: 'mongodb', label: 'MongoDB', protocol: 'mongodb', encrypted: true });
        }
      }
      if (composeContent.includes('redis')) {
        if (!nodes.find(n => n.id === 'redis')) {
          nodes.push(createCacheNode('redis', 'Redis', cves));
          edges.push({ source: 'main-app', target: 'redis', label: 'Cache', protocol: 'redis', encrypted: false });
        }
      }
      if (composeContent.includes('nginx') || composeContent.includes('traefik')) {
        nodes.push(createServiceNode('proxy', 'Reverse Proxy', cves));
        edges.push({ source: 'proxy', target: 'main-app', label: 'HTTP', protocol: 'http', encrypted: false });
      }
      if (composeContent.includes('elasticsearch')) {
        nodes.push(createServiceNode('elasticsearch', 'Elasticsearch', cves));
        edges.push({ source: 'main-app', target: 'elasticsearch', label: 'REST', protocol: 'http', encrypted: false });
      }
    } catch (error) {
      console.error('Error parsing docker-compose:', error);
    }
  }

  // Detect Dockerfile
  const dockerfilePath = path.join(repoPath, 'Dockerfile');
  if (fs.existsSync(dockerfilePath)) {
    // Add container node
    const containerCves = cves.filter(c => c.sourceType === 'container');
    nodes.push({
      id: 'container',
      name: 'Docker Container',
      type: 'container',
      technology: 'Docker',
      riskLevel: calculateNodeRiskLevel(containerCves),
      cveCount: containerCves.length,
      exposureCount: 0,
      x: 200,
      y: 300
    });
    edges.push({ source: 'container', target: 'main-app', label: 'Contains', protocol: 'docker', encrypted: false });
  }

  // Detect Python dependencies
  const requirementsPath = path.join(repoPath, 'requirements.txt');
  if (fs.existsSync(requirementsPath)) {
    try {
      const requirements = fs.readFileSync(requirementsPath, 'utf-8').toLowerCase();

      if (requirements.includes('psycopg') || requirements.includes('sqlalchemy')) {
        if (!nodes.find(n => n.id === 'postgres')) {
          nodes.push(createDatabaseNode('postgres', 'PostgreSQL', cves));
          edges.push({ source: 'main-app', target: 'postgres', label: 'SQL', protocol: 'postgres', encrypted: true });
        }
      }
      if (requirements.includes('pymongo')) {
        if (!nodes.find(n => n.id === 'mongodb')) {
          nodes.push(createDatabaseNode('mongodb', 'MongoDB', cves));
          edges.push({ source: 'main-app', target: 'mongodb', label: 'MongoDB', protocol: 'mongodb', encrypted: true });
        }
      }
      if (requirements.includes('redis') || requirements.includes('celery')) {
        if (!nodes.find(n => n.id === 'redis')) {
          nodes.push(createCacheNode('redis', 'Redis', cves));
          edges.push({ source: 'main-app', target: 'redis', label: 'Cache/Queue', protocol: 'redis', encrypted: false });
        }
      }
      if (requirements.includes('boto3') || requirements.includes('s3')) {
        if (!nodes.find(n => n.id === 'aws-s3')) {
          nodes.push(createExternalNode('aws-s3', 'AWS S3', cves));
          edges.push({ source: 'main-app', target: 'aws-s3', label: 'HTTPS', protocol: 'https', encrypted: true });
        }
      }
    } catch (error) {
      console.error('Error parsing requirements.txt:', error);
    }
  }

  // Position nodes in a circle around the main app
  positionNodes(nodes);

  return { nodes, edges };
}

function createDatabaseNode(id: string, name: string, cves: CVE[]): TopologyNode {
  const relatedCves = cves.filter(c =>
    c.component.toLowerCase().includes(id) ||
    c.description.toLowerCase().includes(id)
  );
  return {
    id,
    name,
    type: 'database',
    technology: name,
    riskLevel: calculateNodeRiskLevel(relatedCves),
    cveCount: relatedCves.length,
    exposureCount: 0
  };
}

function createCacheNode(id: string, name: string, cves: CVE[]): TopologyNode {
  const relatedCves = cves.filter(c =>
    c.component.toLowerCase().includes(id) ||
    c.description.toLowerCase().includes(id)
  );
  return {
    id,
    name,
    type: 'cache',
    technology: name,
    riskLevel: calculateNodeRiskLevel(relatedCves),
    cveCount: relatedCves.length,
    exposureCount: 0
  };
}

function createQueueNode(id: string, name: string, cves: CVE[]): TopologyNode {
  const relatedCves = cves.filter(c =>
    c.component.toLowerCase().includes(id) ||
    c.description.toLowerCase().includes(id)
  );
  return {
    id,
    name,
    type: 'queue',
    technology: name,
    riskLevel: calculateNodeRiskLevel(relatedCves),
    cveCount: relatedCves.length,
    exposureCount: 0
  };
}

function createExternalNode(id: string, name: string, cves: CVE[]): TopologyNode {
  return {
    id,
    name,
    type: 'external',
    technology: name,
    riskLevel: 'healthy',
    cveCount: 0,
    exposureCount: 0
  };
}

function createServiceNode(id: string, name: string, cves: CVE[]): TopologyNode {
  const relatedCves = cves.filter(c =>
    c.component.toLowerCase().includes(id) ||
    c.description.toLowerCase().includes(id)
  );
  return {
    id,
    name,
    type: 'service',
    technology: name,
    riskLevel: calculateNodeRiskLevel(relatedCves),
    cveCount: relatedCves.length,
    exposureCount: 0
  };
}

function createStorageNode(id: string, name: string, cves: CVE[]): TopologyNode {
  return {
    id,
    name,
    type: 'storage',
    technology: name,
    riskLevel: 'low',
    cveCount: 0,
    exposureCount: 0
  };
}

function calculateNodeRiskLevel(cves: CVE[]): 'critical' | 'high' | 'medium' | 'low' | 'healthy' {
  if (cves.length === 0) return 'healthy';

  const criticalCount = cves.filter(c => c.severity === 'critical').length;
  const highCount = cves.filter(c => c.severity === 'high').length;

  if (criticalCount > 0) return 'critical';
  if (highCount > 0) return 'high';
  if (cves.some(c => c.severity === 'medium')) return 'medium';
  return 'low';
}

function positionNodes(nodes: TopologyNode[]): void {
  const canvasWidth = 800;
  const canvasHeight = 600;

  // Group nodes by layer based on type
  const layers: { [key: string]: TopologyNode[] } = {
    external: [], // Top layer - external services
    proxy: [],    // Proxy/gateway layer
    app: [],      // Application layer
    service: [],  // Services layer
    data: [],     // Databases, caches, queues
    storage: []   // Bottom layer - storage, containers
  };

  for (const node of nodes) {
    switch (node.type) {
      case 'external':
        layers.external.push(node);
        break;
      case 'service':
        // Proxy goes in proxy layer, other services in service layer
        if (node.id === 'proxy' || node.name.toLowerCase().includes('proxy') || node.name.toLowerCase().includes('gateway')) {
          layers.proxy.push(node);
        } else {
          layers.service.push(node);
        }
        break;
      case 'application':
        layers.app.push(node);
        break;
      case 'database':
      case 'cache':
      case 'queue':
        layers.data.push(node);
        break;
      case 'storage':
      case 'container':
        layers.storage.push(node);
        break;
      default:
        layers.service.push(node);
    }
  }

  // Calculate Y positions for each layer (top to bottom)
  const layerOrder = ['external', 'proxy', 'app', 'service', 'data', 'storage'];
  const activeLayerYPositions: { layer: string; y: number }[] = [];
  const layerSpacing = 100;
  let currentY = 80;

  for (const layerName of layerOrder) {
    if (layers[layerName].length > 0) {
      activeLayerYPositions.push({ layer: layerName, y: currentY });
      currentY += layerSpacing;
    }
  }

  // Position nodes within each layer (horizontally distributed)
  for (const { layer, y } of activeLayerYPositions) {
    const layerNodes = layers[layer];
    const nodeCount = layerNodes.length;

    if (nodeCount === 1) {
      // Center single node
      layerNodes[0].x = canvasWidth / 2;
      layerNodes[0].y = y;
    } else {
      // Distribute multiple nodes horizontally
      const spacing = Math.min(180, (canvasWidth - 100) / (nodeCount + 1));
      const startX = (canvasWidth - (spacing * (nodeCount - 1))) / 2;

      layerNodes.forEach((node, index) => {
        node.x = Math.round(startX + (spacing * index));
        node.y = y;
      });
    }
  }
}

// Generate remediation groups from CVEs
export function generateRemediationGroups(cves: CVE[]): any[] {
  const groups: any[] = [];
  const componentMap = new Map<string, CVE[]>();

  // Group CVEs by component
  for (const cve of cves) {
    const key = cve.component;
    if (!componentMap.has(key)) {
      componentMap.set(key, []);
    }
    componentMap.get(key)!.push(cve);
  }

  // Create remediation groups for components with multiple CVEs
  let groupId = 1;
  for (const [component, componentCves] of componentMap.entries()) {
    if (componentCves.length > 0) {
      const hasCritical = componentCves.some(c => c.severity === 'critical');
      const hasHigh = componentCves.some(c => c.severity === 'high');
      const hasOverdue = componentCves.some(c => c.slaStatus === 'overdue');
      const hasDueSoon = componentCves.some(c => c.slaStatus === 'due_soon');

      // Calculate risk reduction (sum of risk scores)
      const riskReduction = componentCves.reduce((sum, c) => sum + (c.riskScore?.concert || 0), 0);

      // Determine effort based on number of CVEs and severity
      let effort: 'low' | 'medium' | 'high' = 'low';
      let effortHours = 2;
      if (componentCves.length > 5 || hasCritical) {
        effort = 'high';
        effortHours = 8;
      } else if (componentCves.length > 2 || hasHigh) {
        effort = 'medium';
        effortHours = 4;
      }

      // Get fix version if available
      const fixedVersions = [...new Set(componentCves.map(c => c.fixedVersion).filter(Boolean))];

      // Get compliance impact
      const complianceImpact = [...new Set(componentCves.flatMap(c => c.complianceImpact || []))];

      groups.push({
        id: `group-${groupId++}`,
        title: `Update ${component}`,
        type: 'dependency_update',
        cves: componentCves.map(c => c.id),
        cvesCount: componentCves.length,
        riskReduction: Math.round(riskReduction * 10) / 10,
        effort,
        effortHours,
        priority: hasCritical ? 1 : hasHigh ? 2 : 3,
        slaStatus: hasOverdue ? 'overdue' : hasDueSoon ? 'due_soon' : 'on_track',
        overdueCount: componentCves.filter(c => c.slaStatus === 'overdue').length,
        dueSoonCount: componentCves.filter(c => c.slaStatus === 'due_soon').length,
        complianceImpact,
        fixCommand: `npm update ${component}`,
        targetVersion: fixedVersions[0] || undefined
      });
    }
  }

  // Sort by priority and risk reduction
  groups.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return b.riskReduction - a.riskReduction;
  });

  return groups;
}
