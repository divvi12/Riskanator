import {
  ScanResult,
  CVE,
  RemediationGroup,
  ApplicationContext,
  NonCVEExposure,
  ApplicationTopology,
  Exposure,
  CVEExposure,
  CertificateExposure,
  SecretExposure,
  MisconfigurationExposure,
  LicenseExposure,
  CodeSecurityExposure,
  ExtendedScanResult,
  ExtendedScanSummary,
  ExtendedRemediationGroup,
  ExtendedFinancialAnalysis,
  ExtendedComplianceStatus
} from '../types';

// Demo application context
export const demoContext: ApplicationContext = {
  appName: 'Acme Corp Payment Processing API',
  industry: 'financial',
  purpose: 'Process customer payments and handle financial transactions',
  criticality: 5,
  dataSensitivity: {
    pii: true,
    phi: false,
    pci: true,
    tradeSecrets: false
  },
  accessControls: {
    publicEndpoints: 12,
    privateEndpoints: 45,
    networkExposure: 'public',
    controls: ['waf', 'mfa', 'encryption', 'tls', 'siem', 'rbac']
  },
  formula: 'concert'
};

// Generate demo CVEs
function generateDemoCVEs(): CVE[] {
  const cves: CVE[] = [];

  // Critical CVEs (12)
  const criticalCVEs: Partial<CVE>[] = [
    {
      id: 'CVE-2021-44228',
      cvss: 10.0,
      epss: 97.5,
      cisaKEV: true,
      component: 'log4j-core',
      version: '2.14.1',
      fixedVersion: '2.17.1',
      description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.',
      complianceImpact: ['PCI-DSS 6.2', 'SOX 404']
    },
    {
      id: 'CVE-2021-45046',
      cvss: 9.0,
      epss: 89.2,
      cisaKEV: true,
      component: 'log4j-core',
      version: '2.14.1',
      fixedVersion: '2.17.1',
      description: 'Apache Log4j2 Thread Context Lookup Pattern vulnerable to remote code execution in certain non-default configurations.'
    },
    {
      id: 'CVE-2022-22965',
      cvss: 9.8,
      epss: 94.1,
      cisaKEV: true,
      component: 'spring-beans',
      version: '5.3.17',
      fixedVersion: '5.3.18',
      description: 'Spring Framework RCE via Data Binding on JDK 9+',
      complianceImpact: ['PCI-DSS 6.2', 'GDPR Art. 32']
    },
    {
      id: 'CVE-2021-42013',
      cvss: 9.8,
      epss: 92.3,
      cisaKEV: true,
      component: 'httpd',
      version: '2.4.49',
      fixedVersion: '2.4.51',
      description: 'Apache HTTP Server path traversal and remote code execution.'
    },
    {
      id: 'CVE-2023-44487',
      cvss: 9.1,
      epss: 78.4,
      cisaKEV: true,
      component: 'nghttp2',
      version: '1.51.0',
      fixedVersion: '1.57.0',
      description: 'HTTP/2 Rapid Reset Attack vulnerability.'
    },
    {
      id: 'CVE-2022-3786',
      cvss: 9.8,
      epss: 67.8,
      cisaKEV: true,
      component: 'openssl',
      version: '3.0.6',
      fixedVersion: '3.0.7',
      description: 'X.509 Email Address Buffer Overflow in OpenSSL.'
    },
    {
      id: 'CVE-2023-32315',
      cvss: 9.8,
      epss: 85.2,
      cisaKEV: true,
      component: 'openfire',
      version: '4.7.4',
      fixedVersion: '4.7.5',
      description: 'Openfire Administration Console authentication bypass.'
    },
    {
      id: 'CVE-2023-20198',
      cvss: 10.0,
      epss: 95.7,
      cisaKEV: true,
      component: 'cisco-ios-xe',
      version: '16.12.1',
      fixedVersion: '17.9.4',
      description: 'Cisco IOS XE privilege escalation vulnerability.'
    },
    {
      id: 'CVE-2022-26134',
      cvss: 9.8,
      epss: 91.3,
      cisaKEV: false,
      component: 'confluence',
      version: '7.18.0',
      fixedVersion: '7.18.1',
      description: 'Atlassian Confluence Server OGNL injection vulnerability.'
    },
    {
      id: 'CVE-2023-22515',
      cvss: 10.0,
      epss: 88.9,
      cisaKEV: false,
      component: 'confluence',
      version: '8.0.0',
      fixedVersion: '8.3.3',
      description: 'Atlassian Confluence Data Center broken access control.'
    },
    {
      id: 'CVE-2021-26084',
      cvss: 9.8,
      epss: 73.5,
      cisaKEV: false,
      component: 'confluence',
      version: '7.12.4',
      fixedVersion: '7.13.0',
      description: 'Atlassian Confluence Server Webwork OGNL injection.'
    },
    {
      id: 'CVE-2022-42889',
      cvss: 9.8,
      epss: 65.4,
      cisaKEV: false,
      component: 'commons-text',
      version: '1.9',
      fixedVersion: '1.10.0',
      description: 'Apache Commons Text StringSubstitutor arbitrary code execution.'
    }
  ];

  // High CVEs (45)
  const highCVETemplates = [
    { component: 'lodash', version: '4.17.19', fixedVersion: '4.17.21', desc: 'Prototype pollution vulnerability' },
    { component: 'axios', version: '0.21.1', fixedVersion: '0.21.4', desc: 'Server-Side Request Forgery vulnerability' },
    { component: 'minimist', version: '1.2.5', fixedVersion: '1.2.6', desc: 'Prototype pollution vulnerability' },
    { component: 'node-fetch', version: '2.6.1', fixedVersion: '2.6.7', desc: 'Exposure of sensitive information' },
    { component: 'tar', version: '6.1.0', fixedVersion: '6.1.9', desc: 'Arbitrary file creation/overwrite' },
    { component: 'glob-parent', version: '5.1.1', fixedVersion: '5.1.2', desc: 'Regular Expression Denial of Service' },
    { component: 'jsonwebtoken', version: '8.5.1', fixedVersion: '9.0.0', desc: 'JWT signature verification bypass' },
    { component: 'express', version: '4.17.1', fixedVersion: '4.18.2', desc: 'Open redirect vulnerability' },
    { component: 'moment', version: '2.29.1', fixedVersion: '2.29.4', desc: 'Path traversal vulnerability' },
    { component: 'xml2js', version: '0.4.23', fixedVersion: '0.5.0', desc: 'Prototype pollution vulnerability' }
  ];

  // Add critical CVEs
  criticalCVEs.forEach((cve, index) => {
    cves.push({
      id: cve.id!,
      cvss: cve.cvss!,
      epss: cve.epss,
      cisaKEV: cve.cisaKEV!,
      component: cve.component!,
      version: cve.version!,
      fixedVersion: cve.fixedVersion,
      source: 'demo',
      sourceType: 'sca',
      severity: 'critical',
      description: cve.description!,
      complianceImpact: cve.complianceImpact || ['PCI-DSS 6.2'],
      riskScore: { concert: 9.5 + (Math.random() * 0.5), comprehensive: 900 + Math.floor(Math.random() * 100) },
      slaDeadline: new Date(Date.now() + (index < 4 ? -2 : 5) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: index < 2 ? 'overdue' : (index < 5 ? 'due_soon' : 'on_track'),
      daysRemaining: index < 2 ? -Math.floor(Math.random() * 5) : Math.floor(Math.random() * 14)
    });
  });

  // Add high CVEs
  for (let i = 0; i < 45; i++) {
    const template = highCVETemplates[i % highCVETemplates.length];
    cves.push({
      id: `CVE-2023-${30000 + i}`,
      cvss: 7.0 + Math.random() * 1.9,
      epss: 20 + Math.random() * 40,
      cisaKEV: false,
      component: template.component,
      version: template.version,
      fixedVersion: template.fixedVersion,
      source: 'demo',
      sourceType: 'sca',
      severity: 'high',
      description: template.desc,
      complianceImpact: i % 3 === 0 ? ['PCI-DSS 6.2'] : [],
      riskScore: { concert: 7.0 + Math.random() * 1.9, comprehensive: 500 + Math.floor(Math.random() * 200) },
      slaDeadline: new Date(Date.now() + (7 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: i < 5 ? 'due_soon' : 'on_track',
      daysRemaining: 7 + i
    });
  }

  // Add medium CVEs (87)
  const mediumComponents = ['webpack', 'babel-core', 'eslint', 'jest', 'react-scripts', 'postcss', 'terser', 'acorn', 'semver', 'debug'];
  for (let i = 0; i < 87; i++) {
    const comp = mediumComponents[i % mediumComponents.length];
    cves.push({
      id: `CVE-2023-${40000 + i}`,
      cvss: 4.0 + Math.random() * 2.9,
      epss: 5 + Math.random() * 15,
      cisaKEV: false,
      component: comp,
      version: '1.0.0',
      fixedVersion: '1.1.0',
      source: 'demo',
      sourceType: i % 4 === 0 ? 'sast' : 'sca',
      severity: 'medium',
      description: `Medium severity vulnerability in ${comp}`,
      riskScore: { concert: 4.0 + Math.random() * 2.9, comprehensive: 200 + Math.floor(Math.random() * 200) },
      slaDeadline: new Date(Date.now() + (30 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: 'on_track',
      daysRemaining: 30 + i
    });
  }

  // Add low CVEs (23)
  const lowComponents = ['colors', 'faker', 'chalk', 'commander', 'yargs', 'inquirer'];
  for (let i = 0; i < 23; i++) {
    const comp = lowComponents[i % lowComponents.length];
    cves.push({
      id: `CVE-2023-${50000 + i}`,
      cvss: 1.0 + Math.random() * 2.9,
      epss: 1 + Math.random() * 4,
      cisaKEV: false,
      component: comp,
      version: '1.0.0',
      fixedVersion: '1.0.1',
      source: 'demo',
      sourceType: 'sca',
      severity: 'low',
      description: `Low severity issue in ${comp}`,
      riskScore: { concert: 1.0 + Math.random() * 2.9, comprehensive: 50 + Math.floor(Math.random() * 100) },
      slaDeadline: new Date(Date.now() + (60 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: 'on_track',
      daysRemaining: 60 + i
    });
  }

  // Add Container vulnerabilities (15)
  const containerCVEs = [
    { id: 'CVE-2022-29155', cvss: 9.8, desc: 'OpenLDAP remote code execution in base image', component: 'openldap' },
    { id: 'CVE-2022-1292', cvss: 9.8, desc: 'OpenSSL command injection in container', component: 'openssl' },
    { id: 'CVE-2022-2068', cvss: 9.8, desc: 'OpenSSL c_rehash script vulnerability', component: 'openssl' },
    { id: 'CVE-2021-22946', cvss: 7.5, desc: 'curl HSTS bypass vulnerability', component: 'curl' },
    { id: 'CVE-2022-32207', cvss: 9.8, desc: 'curl credential leak in container', component: 'curl' },
    { id: 'CVE-2023-27536', cvss: 5.9, desc: 'curl SSH authentication bypass', component: 'curl' },
    { id: 'CVE-2022-29458', cvss: 7.1, desc: 'ncurses heap overflow', component: 'ncurses' },
    { id: 'CVE-2022-1586', cvss: 9.1, desc: 'pcre2 out-of-bounds read', component: 'pcre2' },
    { id: 'CVE-2023-0286', cvss: 7.4, desc: 'OpenSSL X.400 address parsing', component: 'openssl' },
  ];
  containerCVEs.forEach((cve, i) => {
    cves.push({
      id: cve.id,
      cvss: cve.cvss,
      epss: 30 + Math.random() * 50,
      cisaKEV: i < 2,
      component: cve.component,
      version: 'ubuntu:22.04',
      fixedVersion: 'ubuntu:22.04-updated',
      source: 'demo',
      sourceType: 'container',
      severity: cve.cvss >= 9 ? 'critical' : cve.cvss >= 7 ? 'high' : 'medium',
      description: cve.desc,
      complianceImpact: ['PCI-DSS 6.2'],
      riskScore: { concert: cve.cvss * 0.9, comprehensive: Math.floor(cve.cvss * 80) },
      slaDeadline: new Date(Date.now() + (14 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: i < 2 ? 'due_soon' : 'on_track',
      daysRemaining: 14 + i
    });
  });

  // Add IaC vulnerabilities (12)
  const iacCVEs = [
    { id: 'CKV-AWS-21', cvss: 8.5, desc: 'S3 bucket with public access enabled', component: 'aws_s3_bucket' },
    { id: 'CKV-AWS-19', cvss: 7.5, desc: 'S3 bucket without encryption', component: 'aws_s3_bucket' },
    { id: 'CKV-AWS-24', cvss: 9.0, desc: 'Security group allows unrestricted SSH', component: 'aws_security_group' },
    { id: 'CKV-AWS-25', cvss: 9.0, desc: 'Security group allows unrestricted RDP', component: 'aws_security_group' },
    { id: 'CKV-AWS-16', cvss: 6.5, desc: 'RDS instance without encryption', component: 'aws_db_instance' },
    { id: 'CKV-AWS-17', cvss: 8.0, desc: 'RDS instance is publicly accessible', component: 'aws_db_instance' },
    { id: 'CKV-K8S-1', cvss: 8.5, desc: 'Container running as root', component: 'kubernetes_deployment' },
    { id: 'CKV-K8S-8', cvss: 7.0, desc: 'Container allows privilege escalation', component: 'kubernetes_deployment' },
    { id: 'CKV-K8S-20', cvss: 8.0, desc: 'Container running with privileged flag', component: 'kubernetes_deployment' },
    { id: 'CKV-K8S-23', cvss: 6.0, desc: 'Container missing readOnlyRootFilesystem', component: 'kubernetes_deployment' },
    { id: 'CKV-DOCKER-1', cvss: 7.5, desc: 'Dockerfile running as root user', component: 'Dockerfile' },
    { id: 'CKV-DOCKER-7', cvss: 5.5, desc: 'Dockerfile using latest tag', component: 'Dockerfile' },
  ];
  iacCVEs.forEach((cve, i) => {
    cves.push({
      id: cve.id,
      cvss: cve.cvss,
      epss: 15 + Math.random() * 30,
      cisaKEV: false,
      component: cve.component,
      version: 'current',
      fixedVersion: 'remediated',
      source: 'demo',
      sourceType: 'iac',
      severity: cve.cvss >= 9 ? 'critical' : cve.cvss >= 7 ? 'high' : 'medium',
      description: cve.desc,
      complianceImpact: i < 4 ? ['PCI-DSS 6.2', 'SOX 404'] : ['PCI-DSS 6.2'],
      riskScore: { concert: cve.cvss * 0.85, comprehensive: Math.floor(cve.cvss * 75) },
      slaDeadline: new Date(Date.now() + (21 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: 'on_track',
      daysRemaining: 21 + i
    });
  });

  // Add SAST vulnerabilities (18)
  const sastCVEs = [
    { id: 'CWE-89', cvss: 9.8, desc: 'SQL Injection in user query handler', component: 'src/api/users.js:45' },
    { id: 'CWE-79', cvss: 6.1, desc: 'Cross-Site Scripting (XSS) in template', component: 'src/views/profile.html:120' },
    { id: 'CWE-78', cvss: 9.8, desc: 'OS Command Injection in file handler', component: 'src/utils/files.js:89' },
    { id: 'CWE-22', cvss: 7.5, desc: 'Path Traversal in file upload', component: 'src/api/upload.js:34' },
    { id: 'CWE-502', cvss: 9.8, desc: 'Deserialization of untrusted data', component: 'src/services/cache.js:67' },
    { id: 'CWE-798', cvss: 9.8, desc: 'Hardcoded credentials in config', component: 'src/config/database.js:12' },
    { id: 'CWE-327', cvss: 7.5, desc: 'Use of broken cryptographic algorithm', component: 'src/utils/crypto.js:23' },
    { id: 'CWE-611', cvss: 9.1, desc: 'XML External Entity (XXE) injection', component: 'src/services/xml.js:56' },
    { id: 'CWE-918', cvss: 9.1, desc: 'Server-Side Request Forgery (SSRF)', component: 'src/api/proxy.js:78' },
    { id: 'CWE-352', cvss: 8.0, desc: 'Cross-Site Request Forgery (CSRF)', component: 'src/middleware/auth.js:34' },
    { id: 'CWE-434', cvss: 8.8, desc: 'Unrestricted file upload', component: 'src/api/documents.js:90' },
    { id: 'CWE-601', cvss: 6.1, desc: 'Open redirect vulnerability', component: 'src/auth/callback.js:45' },
    { id: 'CWE-94', cvss: 9.8, desc: 'Code injection via eval()', component: 'src/utils/template.js:123' },
    { id: 'CWE-1236', cvss: 8.0, desc: 'CSV Injection in export function', component: 'src/reports/export.js:67' },
    { id: 'CWE-200', cvss: 5.3, desc: 'Exposure of sensitive information', component: 'src/api/error.js:23' },
    { id: 'CWE-287', cvss: 9.8, desc: 'Improper authentication', component: 'src/auth/login.js:89' },
    { id: 'CWE-306', cvss: 9.8, desc: 'Missing authentication on critical function', component: 'src/api/admin.js:12' },
    { id: 'CWE-732', cvss: 7.5, desc: 'Incorrect permission assignment', component: 'src/services/files.js:45' },
  ];
  sastCVEs.forEach((cve, i) => {
    cves.push({
      id: cve.id,
      cvss: cve.cvss,
      epss: 10 + Math.random() * 40,
      cisaKEV: false,
      component: cve.component,
      version: 'current',
      fixedVersion: 'code-fix-required',
      source: 'demo',
      sourceType: 'sast',
      severity: cve.cvss >= 9 ? 'critical' : cve.cvss >= 7 ? 'high' : 'medium',
      description: cve.desc,
      complianceImpact: cve.cvss >= 9 ? ['PCI-DSS 6.5', 'OWASP Top 10'] : ['OWASP Top 10'],
      riskScore: { concert: cve.cvss * 0.95, comprehensive: Math.floor(cve.cvss * 90) },
      slaDeadline: new Date(Date.now() + (7 + i) * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      slaStatus: i < 3 ? 'due_soon' : 'on_track',
      daysRemaining: 7 + i
    });
  });

  return cves;
}

// Generate demo remediation groups
function generateRemediationGroups(cves: CVE[]): RemediationGroup[] {
  const groups: RemediationGroup[] = [
    {
      id: 'rem-1',
      title: 'Update log4j to 2.17.1',
      type: 'dependency_update',
      cves: cves.filter(c => c.component === 'log4j-core').map(c => c.id),
      cvesCount: 2,
      riskReduction: 42,
      effort: 'low',
      effortHours: 4,
      priority: 1,
      slaStatus: 'overdue',
      overdueCount: 1,
      dueSoonCount: 1,
      complianceImpact: ['PCI-DSS 6.2', 'SOX 404'],
      fixCommand: 'npm update log4j-core@2.17.1',
      targetVersion: '2.17.1'
    },
    {
      id: 'rem-2',
      title: 'Update spring-beans to 5.3.18',
      type: 'dependency_update',
      cves: cves.filter(c => c.component === 'spring-beans').map(c => c.id),
      cvesCount: 1,
      riskReduction: 28,
      effort: 'medium',
      effortHours: 8,
      priority: 2,
      slaStatus: 'due_soon',
      overdueCount: 0,
      dueSoonCount: 1,
      complianceImpact: ['PCI-DSS 6.2', 'GDPR Art. 32'],
      fixCommand: 'mvn versions:set -DnewVersion=5.3.18',
      targetVersion: '5.3.18'
    },
    {
      id: 'rem-3',
      title: 'Update OpenSSL to 3.0.7',
      type: 'dependency_update',
      cves: cves.filter(c => c.component === 'openssl').map(c => c.id),
      cvesCount: 1,
      riskReduction: 22,
      effort: 'medium',
      effortHours: 6,
      priority: 3,
      slaStatus: 'due_soon',
      overdueCount: 0,
      dueSoonCount: 1,
      complianceImpact: ['PCI-DSS 6.2'],
      fixCommand: 'apt-get update && apt-get install openssl=3.0.7',
      targetVersion: '3.0.7'
    },
    {
      id: 'rem-4',
      title: 'Update lodash to 4.17.21',
      type: 'dependency_update',
      cves: cves.filter(c => c.component === 'lodash').map(c => c.id),
      cvesCount: 5,
      riskReduction: 18,
      effort: 'low',
      effortHours: 2,
      priority: 4,
      slaStatus: 'on_track',
      overdueCount: 0,
      dueSoonCount: 0,
      complianceImpact: [],
      fixCommand: 'npm update lodash@4.17.21',
      targetVersion: '4.17.21'
    },
    {
      id: 'rem-5',
      title: 'Update axios to 0.21.4',
      type: 'dependency_update',
      cves: cves.filter(c => c.component === 'axios').map(c => c.id),
      cvesCount: 5,
      riskReduction: 15,
      effort: 'low',
      effortHours: 2,
      priority: 5,
      slaStatus: 'on_track',
      overdueCount: 0,
      dueSoonCount: 0,
      complianceImpact: [],
      fixCommand: 'npm update axios@0.21.4',
      targetVersion: '0.21.4'
    }
  ];

  return groups;
}

// Generate Non-CVE Exposures (misconfigurations, weaknesses, code smells)
function generateNonCVEExposures(): NonCVEExposure[] {
  return [
    // Misconfigurations
    {
      id: 'MISC-001',
      type: 'misconfiguration',
      severity: 'critical',
      title: 'Database exposed to public internet',
      description: 'PostgreSQL database is configured with public IP address and accepts connections from 0.0.0.0/0',
      location: 'terraform/database.tf:45',
      category: 'Network Security',
      recommendation: 'Restrict database access to private subnet only and use VPC peering for application access',
      effort: 'medium',
      complianceImpact: ['PCI-DSS 1.3', 'SOC2 CC6.1'],
      riskScore: 9.5
    },
    {
      id: 'MISC-002',
      type: 'misconfiguration',
      severity: 'high',
      title: 'S3 bucket allows public read access',
      description: 'Customer data bucket has ACL set to public-read, exposing sensitive files',
      location: 'terraform/storage.tf:23',
      category: 'Data Security',
      recommendation: 'Set bucket ACL to private and use signed URLs for authorized access',
      effort: 'low',
      complianceImpact: ['PCI-DSS 3.4', 'GDPR Art. 32'],
      riskScore: 8.5
    },
    {
      id: 'MISC-003',
      type: 'misconfiguration',
      severity: 'high',
      title: 'Missing TLS for internal API communication',
      description: 'Service-to-service communication uses HTTP instead of HTTPS within the cluster',
      location: 'kubernetes/services.yaml:89',
      category: 'Encryption',
      recommendation: 'Enable mutual TLS (mTLS) using service mesh or certificate-based authentication',
      effort: 'high',
      complianceImpact: ['PCI-DSS 4.1'],
      riskScore: 7.8
    },
    {
      id: 'MISC-004',
      type: 'misconfiguration',
      severity: 'medium',
      title: 'Container running without resource limits',
      description: 'Payment service container has no CPU/memory limits, risking resource exhaustion attacks',
      location: 'kubernetes/payment-deployment.yaml:34',
      category: 'Resource Management',
      recommendation: 'Set appropriate CPU and memory limits based on service requirements',
      effort: 'low',
      riskScore: 6.0
    },
    {
      id: 'MISC-005',
      type: 'misconfiguration',
      severity: 'medium',
      title: 'Debug mode enabled in production',
      description: 'Flask application has DEBUG=True in production environment',
      location: 'src/app/config.py:12',
      category: 'Security Hardening',
      recommendation: 'Disable debug mode in production using environment-specific configuration',
      effort: 'low',
      riskScore: 5.5
    },

    // Security Weaknesses (CWEs not tied to specific CVEs)
    {
      id: 'WEAK-001',
      type: 'weakness',
      severity: 'critical',
      title: 'Insufficient input validation on payment amount',
      description: 'Payment amount field accepts negative values and extremely large numbers without validation',
      location: 'src/api/payments.js:156',
      category: 'Input Validation',
      recommendation: 'Add strict validation: positive numbers only, max amount limits, decimal precision checks',
      effort: 'low',
      complianceImpact: ['PCI-DSS 6.5.1'],
      riskScore: 9.0
    },
    {
      id: 'WEAK-002',
      type: 'weakness',
      severity: 'high',
      title: 'Missing rate limiting on authentication endpoint',
      description: 'Login endpoint has no rate limiting, enabling brute force attacks',
      location: 'src/api/auth.js:45',
      category: 'Authentication',
      recommendation: 'Implement rate limiting with exponential backoff and account lockout after failed attempts',
      effort: 'medium',
      complianceImpact: ['PCI-DSS 8.1.6'],
      riskScore: 8.0
    },
    {
      id: 'WEAK-003',
      type: 'weakness',
      severity: 'high',
      title: 'Session tokens never expire',
      description: 'JWT tokens have no expiration time set, remaining valid indefinitely',
      location: 'src/services/auth.js:89',
      category: 'Session Management',
      recommendation: 'Set appropriate token expiration (15-30 min for sensitive operations) with refresh token rotation',
      effort: 'medium',
      complianceImpact: ['PCI-DSS 8.1.8'],
      riskScore: 7.5
    },
    {
      id: 'WEAK-004',
      type: 'weakness',
      severity: 'medium',
      title: 'Overly permissive CORS configuration',
      description: 'CORS allows all origins (*) for API endpoints handling sensitive data',
      location: 'src/middleware/cors.js:12',
      category: 'Access Control',
      recommendation: 'Whitelist specific trusted origins instead of using wildcard',
      effort: 'low',
      riskScore: 6.5
    },

    // Code Smells (maintainability issues with security implications)
    {
      id: 'SMELL-001',
      type: 'code_smell',
      severity: 'medium',
      title: 'Deprecated cryptographic function usage',
      description: 'Using MD5 for checksums instead of SHA-256',
      location: 'src/utils/hash.js:34',
      category: 'Cryptography',
      recommendation: 'Replace MD5 with SHA-256 or SHA-3 for all hash operations',
      effort: 'low',
      riskScore: 5.0
    },
    {
      id: 'SMELL-002',
      type: 'code_smell',
      severity: 'low',
      title: 'Error messages expose internal paths',
      description: 'Stack traces and file paths shown in error responses',
      location: 'src/middleware/errorHandler.js:23',
      category: 'Information Disclosure',
      recommendation: 'Return generic error messages to users, log detailed errors server-side only',
      effort: 'low',
      riskScore: 4.0
    },
    {
      id: 'SMELL-003',
      type: 'code_smell',
      severity: 'info',
      title: 'Logging sensitive data fields',
      description: 'User email and IP addresses logged at DEBUG level',
      location: 'src/middleware/logger.js:67',
      category: 'Data Privacy',
      recommendation: 'Mask or remove PII from logs, or ensure proper log access controls',
      effort: 'low',
      complianceImpact: ['GDPR Art. 5'],
      riskScore: 3.5
    },

    // Secret Exposures
    {
      id: 'SECRET-001',
      type: 'secret_exposure',
      severity: 'critical',
      title: 'API key committed to repository',
      description: 'Stripe API key found in source code (detected pattern, not actual key)',
      location: 'src/config/payments.js:5',
      category: 'Secrets Management',
      recommendation: 'Remove from code, rotate the key immediately, use environment variables or secrets manager',
      effort: 'low',
      complianceImpact: ['PCI-DSS 3.6'],
      riskScore: 9.8
    },
    {
      id: 'SECRET-002',
      type: 'secret_exposure',
      severity: 'high',
      title: 'Database connection string in config file',
      description: 'PostgreSQL connection string with credentials in plain text configuration',
      location: 'config/database.json:8',
      category: 'Secrets Management',
      recommendation: 'Use environment variables or a secrets manager like HashiCorp Vault',
      effort: 'medium',
      complianceImpact: ['PCI-DSS 8.2.1'],
      riskScore: 8.2
    },

    // Insecure Defaults
    {
      id: 'DEFAULT-001',
      type: 'insecure_default',
      severity: 'high',
      title: 'Default admin credentials active',
      description: 'Admin panel accessible with default username/password (admin/admin)',
      location: 'src/admin/auth.js:12',
      category: 'Authentication',
      recommendation: 'Force password change on first login, disable default credentials in production',
      effort: 'low',
      complianceImpact: ['PCI-DSS 2.1'],
      riskScore: 8.8
    },
    {
      id: 'DEFAULT-002',
      type: 'insecure_default',
      severity: 'medium',
      title: 'Directory listing enabled on web server',
      description: 'Nginx configured to show directory contents when no index file present',
      location: 'nginx/nginx.conf:45',
      category: 'Security Hardening',
      recommendation: 'Disable autoindex in nginx configuration',
      effort: 'low',
      riskScore: 5.5
    },
    {
      id: 'DEFAULT-003',
      type: 'insecure_default',
      severity: 'medium',
      title: 'HTTPS strict transport security not enabled',
      description: 'HSTS header not set, allowing protocol downgrade attacks',
      location: 'nginx/nginx.conf:78',
      category: 'Transport Security',
      recommendation: 'Add Strict-Transport-Security header with appropriate max-age',
      effort: 'low',
      riskScore: 5.0
    }
  ];
}

// Generate Application Topology for Arena View
function generateTopology(): ApplicationTopology {
  return {
    nodes: [
      // Main Application Layer
      {
        id: 'frontend',
        name: 'Web Frontend',
        type: 'application',
        technology: 'React',
        riskLevel: 'medium',
        cveCount: 12,
        exposureCount: 2
      },
      {
        id: 'api-gateway',
        name: 'API Gateway',
        type: 'gateway',
        technology: 'Kong',
        riskLevel: 'low',
        cveCount: 3,
        exposureCount: 1
      },
      {
        id: 'payment-service',
        name: 'Payment Service',
        type: 'service',
        technology: 'Node.js',
        riskLevel: 'critical',
        cveCount: 28,
        exposureCount: 5
      },
      {
        id: 'auth-service',
        name: 'Auth Service',
        type: 'service',
        technology: 'Java/Spring',
        riskLevel: 'high',
        cveCount: 15,
        exposureCount: 4
      },
      {
        id: 'user-service',
        name: 'User Service',
        type: 'service',
        technology: 'Python/Flask',
        riskLevel: 'medium',
        cveCount: 8,
        exposureCount: 2
      },
      {
        id: 'notification-service',
        name: 'Notification Service',
        type: 'service',
        technology: 'Node.js',
        riskLevel: 'low',
        cveCount: 4,
        exposureCount: 0
      },

      // Data Layer
      {
        id: 'postgres-primary',
        name: 'PostgreSQL Primary',
        type: 'database',
        technology: 'PostgreSQL 14',
        riskLevel: 'critical',
        cveCount: 2,
        exposureCount: 3
      },
      {
        id: 'redis-cache',
        name: 'Redis Cache',
        type: 'cache',
        technology: 'Redis 7',
        riskLevel: 'medium',
        cveCount: 1,
        exposureCount: 1
      },
      {
        id: 'rabbitmq',
        name: 'Message Queue',
        type: 'queue',
        technology: 'RabbitMQ',
        riskLevel: 'low',
        cveCount: 2,
        exposureCount: 0
      },
      {
        id: 's3-storage',
        name: 'Document Storage',
        type: 'storage',
        technology: 'AWS S3',
        riskLevel: 'high',
        cveCount: 0,
        exposureCount: 2
      },

      // External Services
      {
        id: 'stripe',
        name: 'Stripe API',
        type: 'external',
        technology: 'Payment Gateway',
        riskLevel: 'healthy',
        cveCount: 0,
        exposureCount: 1
      },
      {
        id: 'sendgrid',
        name: 'SendGrid',
        type: 'external',
        technology: 'Email Service',
        riskLevel: 'healthy',
        cveCount: 0,
        exposureCount: 0
      },

      // Infrastructure
      {
        id: 'docker-host',
        name: 'Container Runtime',
        type: 'container',
        technology: 'Docker',
        riskLevel: 'high',
        cveCount: 9,
        exposureCount: 2
      }
    ],
    edges: [
      // Frontend connections
      { source: 'frontend', target: 'api-gateway', label: 'HTTPS', protocol: 'HTTPS', encrypted: true },

      // API Gateway routing
      { source: 'api-gateway', target: 'payment-service', label: 'REST', protocol: 'HTTP', encrypted: false },
      { source: 'api-gateway', target: 'auth-service', label: 'REST', protocol: 'HTTPS', encrypted: true },
      { source: 'api-gateway', target: 'user-service', label: 'REST', protocol: 'HTTP', encrypted: false },

      // Service-to-service
      { source: 'payment-service', target: 'auth-service', label: 'gRPC', protocol: 'gRPC', encrypted: true },
      { source: 'payment-service', target: 'stripe', label: 'HTTPS', protocol: 'HTTPS', encrypted: true },
      { source: 'payment-service', target: 'rabbitmq', label: 'AMQP', protocol: 'AMQP', encrypted: false },
      { source: 'user-service', target: 'auth-service', label: 'REST', protocol: 'HTTP', encrypted: false },
      { source: 'notification-service', target: 'sendgrid', label: 'HTTPS', protocol: 'HTTPS', encrypted: true },
      { source: 'notification-service', target: 'rabbitmq', label: 'AMQP', protocol: 'AMQP', encrypted: false },

      // Data layer connections
      { source: 'payment-service', target: 'postgres-primary', label: 'SQL', protocol: 'PostgreSQL', encrypted: true },
      { source: 'auth-service', target: 'postgres-primary', label: 'SQL', protocol: 'PostgreSQL', encrypted: true },
      { source: 'user-service', target: 'postgres-primary', label: 'SQL', protocol: 'PostgreSQL', encrypted: false },
      { source: 'auth-service', target: 'redis-cache', label: 'Sessions', protocol: 'Redis', encrypted: false },
      { source: 'payment-service', target: 'redis-cache', label: 'Cache', protocol: 'Redis', encrypted: false },
      { source: 'user-service', target: 's3-storage', label: 'Docs', protocol: 'HTTPS', encrypted: true },

      // Container hosting
      { source: 'docker-host', target: 'payment-service', label: 'hosts', protocol: 'Docker', encrypted: false },
      { source: 'docker-host', target: 'auth-service', label: 'hosts', protocol: 'Docker', encrypted: false },
      { source: 'docker-host', target: 'user-service', label: 'hosts', protocol: 'Docker', encrypted: false },
      { source: 'docker-host', target: 'notification-service', label: 'hosts', protocol: 'Docker', encrypted: false }
    ]
  };
}

// Generate demo data
const demoCVEs = generateDemoCVEs();
const demoNonCVEExposuresData = generateNonCVEExposures();
const demoTopology = generateTopology();

export const demoScanResult: ScanResult = {
  scanId: 'demo-scan-001',
  status: 'complete',
  progress: 100,
  progressMessage: 'Scan complete',
  metadata: {
    repoUrl: 'https://github.com/acme-corp/payment-api',
    branch: 'main',
    context: demoContext,
    languages: ['javascript', 'java', 'python'],
    scanTypes: ['sca', 'sast', 'container', 'iac'],
    startTime: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    endTime: new Date().toISOString()
  },
  summary: {
    totalCVEs: demoCVEs.length,
    critical: demoCVEs.filter(c => c.severity === 'critical').length,
    high: demoCVEs.filter(c => c.severity === 'high').length,
    medium: demoCVEs.filter(c => c.severity === 'medium').length,
    low: demoCVEs.filter(c => c.severity === 'low').length,
    riskScore: {
      concert: 7.8,
      comprehensive: 763
    },
    cisaKEVCount: demoCVEs.filter(c => c.cisaKEV).length,
    bySource: {
      demo: demoCVEs.length
    },
    bySourceType: {
      sca: demoCVEs.filter(c => c.sourceType === 'sca').length,
      sast: demoCVEs.filter(c => c.sourceType === 'sast').length,
      container: demoCVEs.filter(c => c.sourceType === 'container').length,
      iac: demoCVEs.filter(c => c.sourceType === 'iac').length
    }
  },
  cves: demoCVEs,
  nonCVEExposures: demoNonCVEExposuresData,
  topology: demoTopology,
  remediationGroups: generateRemediationGroups(demoCVEs)
};

// Export exposures for use in components
export const demoNonCVEExposures = demoNonCVEExposuresData;
export const demoApplicationTopology = demoTopology;

// Demo financial analysis
export const demoFinancialAnalysis = {
  breachCost: 8800000,
  downtimeCost: 2100000,
  regulatoryFines: 1200000,
  totalRisk: 12100000,
  remediationCost: 51000,
  roi: 237
};

// Demo compliance status
export const demoComplianceStatus = {
  pciDss: 8,
  hipaa: 0,
  sox: 5,
  gdpr: 12
};

// Demo SLA status
export const demoSLAStatus = {
  overdue: 2,
  dueSoon: 5,
  onTrack: 160,
  complianceRate: 85
};

// ============================================================
// UNIFIED EXPOSURE DEMO DATA (NEW)
// ============================================================

// Generate Certificate Exposures
function generateCertificateExposures(): CertificateExposure[] {
  return [
    {
      id: 'cert-001',
      type: 'certificate',
      title: 'Expired Certificate: api.acme.com',
      description: 'Certificate for api.acme.com expired 5 days ago. This will cause service outages and browser warnings.',
      severity: 'critical',
      riskScore: { concert: 9.5, comprehensive: 9.5 },
      location: 'certs/api.acme.com.pem',
      detectedAt: new Date().toISOString(),
      source: 'certificate-scanner',
      domain: 'api.acme.com',
      issuer: 'DigiCert Inc',
      validFrom: '2023-01-15T00:00:00Z',
      validTo: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiration: -5,
      algorithm: 'RSA-SHA256',
      keySize: 2048,
      isExpired: true,
      isSelfSigned: false,
      hasWeakAlgorithm: false,
      certType: 'ssl',
      complianceImpact: ['PCI-DSS 4.1', 'HIPAA 164.312(e)(1)'],
      slaDeadline: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'overdue',
      daysRemaining: -5
    },
    {
      id: 'cert-002',
      type: 'certificate',
      title: 'Expiring Certificate: payments.acme.com',
      description: 'Certificate for payments.acme.com expires in 7 days. Renew before expiration to avoid service disruption.',
      severity: 'high',
      riskScore: { concert: 8.0, comprehensive: 8.0 },
      location: 'certs/payments.acme.com.pem',
      detectedAt: new Date().toISOString(),
      source: 'certificate-scanner',
      domain: 'payments.acme.com',
      issuer: "Let's Encrypt",
      validFrom: '2024-01-10T00:00:00Z',
      validTo: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiration: 7,
      algorithm: 'ECDSA-SHA256',
      keySize: 256,
      isExpired: false,
      isSelfSigned: false,
      hasWeakAlgorithm: false,
      certType: 'ssl',
      complianceImpact: ['PCI-DSS 4.1'],
      slaDeadline: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 5
    },
    {
      id: 'cert-003',
      type: 'certificate',
      title: 'Weak Algorithm Certificate: internal.acme.com',
      description: 'Certificate for internal.acme.com uses weak signature algorithm (SHA1). This is vulnerable to cryptographic attacks.',
      severity: 'high',
      riskScore: { concert: 7.5, comprehensive: 7.5 },
      location: 'certs/internal.acme.com.pem',
      detectedAt: new Date().toISOString(),
      source: 'certificate-scanner',
      domain: 'internal.acme.com',
      issuer: 'Internal CA',
      validFrom: '2022-06-01T00:00:00Z',
      validTo: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiration: 180,
      algorithm: 'SHA1WithRSA',
      keySize: 2048,
      isExpired: false,
      isSelfSigned: false,
      hasWeakAlgorithm: true,
      certType: 'ssl',
      complianceImpact: ['NIST SP 800-52', 'PCI-DSS 4.1'],
      slaDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 30
    },
    {
      id: 'cert-004',
      type: 'certificate',
      title: 'Self-Signed Certificate: dev.acme.com',
      description: 'Certificate for dev.acme.com is self-signed. This may cause trust issues in production environments.',
      severity: 'medium',
      riskScore: { concert: 5.0, comprehensive: 5.0 },
      location: 'certs/dev.acme.com.pem',
      detectedAt: new Date().toISOString(),
      source: 'certificate-scanner',
      domain: 'dev.acme.com',
      issuer: 'Self-Signed',
      validFrom: '2024-01-01T00:00:00Z',
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiration: 365,
      algorithm: 'RSA-SHA256',
      keySize: 4096,
      isExpired: false,
      isSelfSigned: true,
      hasWeakAlgorithm: false,
      certType: 'ssl',
      slaDeadline: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 60
    }
  ];
}

// Generate Secret Exposures
function generateSecretExposures(): SecretExposure[] {
  return [
    {
      id: 'secret-001',
      type: 'secret',
      title: 'Hardcoded AWS Credentials: AWS Access Key',
      description: 'AWS credentials exposed in code at src/config/aws.js:12. An attacker could access your AWS account, steal data, or incur charges.',
      severity: 'critical',
      riskScore: { concert: 9.8, comprehensive: 9.8 },
      location: 'src/config/aws.js:12',
      detectedAt: new Date().toISOString(),
      source: 'trufflehog',
      secretType: 'aws',
      detectorName: 'AWS Access Key ID',
      verified: true,
      entropy: 4.2,
      inGitHistory: true,
      lineNumber: 12,
      complianceImpact: ['PCI-DSS 3.4', 'SOX Section 404', 'GDPR Article 32'],
      slaDeadline: new Date().toISOString(),
      slaStatus: 'overdue',
      daysRemaining: 0
    },
    {
      id: 'secret-002',
      type: 'secret',
      title: 'Hardcoded API Key: Stripe Secret Key',
      description: 'Stripe secret key found in source code at src/services/payment.js:34. This could allow unauthorized payment processing.',
      severity: 'critical',
      riskScore: { concert: 9.5, comprehensive: 9.5 },
      location: 'src/services/payment.js:34',
      detectedAt: new Date().toISOString(),
      source: 'trufflehog',
      secretType: 'api_key',
      detectorName: 'Stripe API Key',
      verified: true,
      entropy: 4.8,
      inGitHistory: false,
      lineNumber: 34,
      complianceImpact: ['PCI-DSS 3.4', 'PCI-DSS 8.2'],
      slaDeadline: new Date().toISOString(),
      slaStatus: 'overdue',
      daysRemaining: 0
    },
    {
      id: 'secret-003',
      type: 'secret',
      title: 'Hardcoded Private Key: RSA Private Key',
      description: 'Private key exposed at config/ssl/server.key. This compromises any system using this key for authentication.',
      severity: 'critical',
      riskScore: { concert: 9.5, comprehensive: 9.5 },
      location: 'config/ssl/server.key',
      detectedAt: new Date().toISOString(),
      source: 'trufflehog',
      secretType: 'private_key',
      detectorName: 'RSA Private Key',
      verified: false,
      entropy: 5.2,
      inGitHistory: true,
      complianceImpact: ['PCI-DSS 3.4', 'HIPAA 164.312(a)(2)(iv)'],
      slaDeadline: new Date().toISOString(),
      slaStatus: 'overdue',
      daysRemaining: 0
    },
    {
      id: 'secret-004',
      type: 'secret',
      title: 'Hardcoded Password: Database Password',
      description: 'Database password found at src/config/database.js:8. This credential should be moved to a secrets manager.',
      severity: 'high',
      riskScore: { concert: 8.5, comprehensive: 8.5 },
      location: 'src/config/database.js:8',
      detectedAt: new Date().toISOString(),
      source: 'pattern-scanner',
      secretType: 'password',
      detectorName: 'Generic Password',
      verified: false,
      entropy: 3.8,
      inGitHistory: false,
      lineNumber: 8,
      complianceImpact: ['PCI-DSS 8.2', 'SOX Section 404'],
      slaDeadline: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 1
    },
    {
      id: 'secret-005',
      type: 'secret',
      title: 'Hardcoded Authentication Token: GitHub Token',
      description: 'GitHub personal access token found at .github/workflows/deploy.yml:15. This could allow impersonation.',
      severity: 'high',
      riskScore: { concert: 8.0, comprehensive: 8.0 },
      location: '.github/workflows/deploy.yml:15',
      detectedAt: new Date().toISOString(),
      source: 'trufflehog',
      secretType: 'token',
      detectorName: 'GitHub Personal Access Token',
      verified: true,
      entropy: 4.5,
      inGitHistory: true,
      lineNumber: 15,
      complianceImpact: ['SOX Section 404'],
      slaDeadline: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 1
    }
  ];
}

// Generate Misconfiguration Exposures
function generateMisconfigExposures(): MisconfigurationExposure[] {
  return [
    {
      id: 'misconfig-001',
      type: 'misconfiguration',
      title: 'S3 bucket with public access enabled',
      description: 'S3 bucket allows public read access, exposing sensitive data. Set bucket ACL to private.',
      severity: 'critical',
      riskScore: { concert: 9.0, comprehensive: 9.0 },
      location: 'terraform/storage.tf:23',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'aws_s3_bucket',
      checkId: 'CKV-AWS-21',
      checkName: 'Ensure S3 bucket has public access disabled',
      guideline: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
      isPubliclyAccessible: true,
      framework: 'terraform',
      resourceName: 'customer_data_bucket',
      complianceImpact: ['PCI-DSS 2.2', 'GDPR Art 32'],
      slaDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 7
    },
    {
      id: 'misconfig-002',
      type: 'misconfiguration',
      title: 'Security group allows unrestricted SSH',
      description: 'Security group allows SSH access from 0.0.0.0/0. Restrict to specific IP ranges.',
      severity: 'critical',
      riskScore: { concert: 9.0, comprehensive: 9.0 },
      location: 'terraform/network.tf:45',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'aws_security_group',
      checkId: 'CKV-AWS-24',
      checkName: 'Ensure no security groups allow unrestricted SSH',
      isPubliclyAccessible: true,
      framework: 'terraform',
      resourceName: 'web_server_sg',
      complianceImpact: ['PCI-DSS 1.3', 'CIS Controls'],
      slaDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 7
    },
    {
      id: 'misconfig-003',
      type: 'misconfiguration',
      title: 'RDS instance is publicly accessible',
      description: 'RDS database is configured with public accessibility. Move to private subnet.',
      severity: 'high',
      riskScore: { concert: 8.0, comprehensive: 8.0 },
      location: 'terraform/database.tf:67',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'aws_db_instance',
      checkId: 'CKV-AWS-17',
      checkName: 'Ensure RDS instance is not publicly accessible',
      isPubliclyAccessible: true,
      framework: 'terraform',
      resourceName: 'payment_db',
      complianceImpact: ['PCI-DSS 1.3', 'SOC2 CC6.1'],
      slaDeadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 14
    },
    {
      id: 'misconfig-004',
      type: 'misconfiguration',
      title: 'Container running as root',
      description: 'Kubernetes deployment runs containers as root user. Use non-root user.',
      severity: 'high',
      riskScore: { concert: 7.5, comprehensive: 7.5 },
      location: 'kubernetes/payment-deployment.yaml:34',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'kubernetes_deployment',
      checkId: 'CKV-K8S-1',
      checkName: 'Ensure containers do not run as root',
      isPubliclyAccessible: false,
      framework: 'kubernetes',
      resourceName: 'payment-service',
      complianceImpact: ['CIS Kubernetes Benchmark'],
      slaDeadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 14
    },
    {
      id: 'misconfig-005',
      type: 'misconfiguration',
      title: 'RDS instance without encryption',
      description: 'RDS database does not have encryption enabled. Enable storage encryption.',
      severity: 'medium',
      riskScore: { concert: 6.5, comprehensive: 6.5 },
      location: 'terraform/database.tf:89',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'aws_db_instance',
      checkId: 'CKV-AWS-16',
      checkName: 'Ensure RDS instance has encryption enabled',
      isPubliclyAccessible: false,
      framework: 'terraform',
      resourceName: 'analytics_db',
      complianceImpact: ['PCI-DSS 3.4', 'HIPAA 164.312(a)(2)(iv)'],
      slaDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 30
    },
    {
      id: 'misconfig-006',
      type: 'misconfiguration',
      title: 'Dockerfile using latest tag',
      description: 'Dockerfile uses latest tag which can lead to non-reproducible builds.',
      severity: 'medium',
      riskScore: { concert: 5.5, comprehensive: 5.5 },
      location: 'Dockerfile:1',
      detectedAt: new Date().toISOString(),
      source: 'checkov',
      resourceType: 'Dockerfile',
      checkId: 'CKV-DOCKER-7',
      checkName: 'Ensure base image uses a specific version tag',
      isPubliclyAccessible: false,
      framework: 'docker',
      complianceImpact: ['DevSecOps Best Practice'],
      slaDeadline: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 45
    }
  ];
}

// Generate License Exposures
function generateLicenseExposures(): LicenseExposure[] {
  return [
    {
      id: 'license-001',
      type: 'license',
      title: 'Copyleft: mysql-connector',
      description: 'Package mysql-connector uses copyleft license GPL-2.0. If you modify or distribute this software, you may be required to release your source code under the same license.',
      severity: 'high',
      riskScore: { concert: 7.0, comprehensive: 7.0 },
      location: 'package.json (mysql-connector)',
      detectedAt: new Date().toISOString(),
      source: 'license-checker',
      licenseType: 'GPL-2.0',
      licenseName: 'GPL-2.0',
      packageName: 'mysql-connector',
      packageVersion: '2.3.1',
      isCopyleft: true,
      isUnknown: false,
      requiresAttribution: true,
      commercialUseAllowed: true,
      complianceImpact: ['Legal - Copyleft License Compliance'],
      slaDeadline: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 60
    },
    {
      id: 'license-002',
      type: 'license',
      title: 'Copyleft: react-pdf-viewer',
      description: 'Package react-pdf-viewer uses copyleft license AGPL-3.0. Strong copyleft license may require releasing your entire application source code.',
      severity: 'high',
      riskScore: { concert: 8.0, comprehensive: 8.0 },
      location: 'package.json (react-pdf-viewer)',
      detectedAt: new Date().toISOString(),
      source: 'license-checker',
      licenseType: 'AGPL-3.0',
      licenseName: 'AGPL-3.0',
      packageName: 'react-pdf-viewer',
      packageVersion: '3.12.0',
      isCopyleft: true,
      isUnknown: false,
      requiresAttribution: true,
      commercialUseAllowed: true,
      complianceImpact: ['Legal - Copyleft License Compliance', 'Legal - IP Compliance'],
      slaDeadline: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 60
    },
    {
      id: 'license-003',
      type: 'license',
      title: 'Unknown License: internal-utils',
      description: 'Package internal-utils has unknown or unrecognized license "UNLICENSED". Review the license terms before using in production.',
      severity: 'medium',
      riskScore: { concert: 6.0, comprehensive: 6.0 },
      location: 'package.json (internal-utils)',
      detectedAt: new Date().toISOString(),
      source: 'license-checker',
      licenseType: 'UNLICENSED',
      licenseName: 'UNKNOWN',
      packageName: 'internal-utils',
      packageVersion: '1.0.0',
      isCopyleft: false,
      isUnknown: true,
      requiresAttribution: true,
      commercialUseAllowed: false,
      complianceImpact: ['Legal - License Risk Assessment Required'],
      slaDeadline: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 90
    },
    {
      id: 'license-004',
      type: 'license',
      title: 'Copyleft: charting-library',
      description: 'Package charting-library uses copyleft license LGPL-3.0. Ensure compliance with linking requirements.',
      severity: 'medium',
      riskScore: { concert: 5.0, comprehensive: 5.0 },
      location: 'package.json (charting-library)',
      detectedAt: new Date().toISOString(),
      source: 'license-checker',
      licenseType: 'LGPL-3.0',
      licenseName: 'LGPL-3.0',
      packageName: 'charting-library',
      packageVersion: '4.5.2',
      isCopyleft: true,
      isUnknown: false,
      requiresAttribution: true,
      commercialUseAllowed: true,
      complianceImpact: ['Legal - Copyleft License Compliance'],
      slaDeadline: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 90
    }
  ];
}

// Generate Code Security Exposures
function generateCodeSecurityExposures(): CodeSecurityExposure[] {
  return [
    {
      id: 'code-sec-001',
      type: 'code-security',
      title: 'SQL Injection in user query handler',
      description: 'User input is directly concatenated into SQL query without parameterization.',
      severity: 'critical',
      riskScore: { concert: 9.8, comprehensive: 9.8 },
      location: 'src/api/users.js:45',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'sql_injection',
      ruleId: 'javascript.express.security.sql-injection.sql-injection',
      ruleName: 'SQL Injection',
      lineNumber: 45,
      endLineNumber: 48,
      codeSnippet: 'const query = "SELECT * FROM users WHERE id = " + userId;',
      fixSuggestion: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])',
      cwe: ['CWE-89'],
      owasp: ['A03:2021'],
      complianceImpact: ['PCI-DSS 6.5', 'OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 7
    },
    {
      id: 'code-sec-002',
      type: 'code-security',
      title: 'Cross-Site Scripting (XSS) in template',
      description: 'User input rendered without proper escaping, allowing XSS attacks.',
      severity: 'high',
      riskScore: { concert: 7.5, comprehensive: 7.5 },
      location: 'src/views/profile.html:120',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'xss',
      ruleId: 'javascript.browser.security.xss.xss',
      ruleName: 'Cross-Site Scripting',
      lineNumber: 120,
      codeSnippet: 'innerHTML = userData.name;',
      fixSuggestion: 'Use textContent instead of innerHTML, or properly escape HTML entities',
      cwe: ['CWE-79'],
      owasp: ['A03:2021'],
      complianceImpact: ['OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 14
    },
    {
      id: 'code-sec-003',
      type: 'code-security',
      title: 'OS Command Injection in file handler',
      description: 'User input passed directly to shell command execution.',
      severity: 'critical',
      riskScore: { concert: 9.8, comprehensive: 9.8 },
      location: 'src/utils/files.js:89',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'command_injection',
      ruleId: 'javascript.lang.security.command-injection.command-injection',
      ruleName: 'Command Injection',
      lineNumber: 89,
      codeSnippet: 'exec("rm -rf " + userPath);',
      fixSuggestion: 'Use child_process.execFile with an argument array, or validate/sanitize input',
      cwe: ['CWE-78'],
      owasp: ['A03:2021'],
      complianceImpact: ['PCI-DSS 6.5', 'OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 7
    },
    {
      id: 'code-sec-004',
      type: 'code-security',
      title: 'Broken Authentication in login handler',
      description: 'Authentication bypass possible due to improper credential validation.',
      severity: 'critical',
      riskScore: { concert: 9.0, comprehensive: 9.0 },
      location: 'src/auth/login.js:89',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'broken_auth',
      ruleId: 'javascript.express.security.broken-auth.broken-auth',
      ruleName: 'Broken Authentication',
      lineNumber: 89,
      codeSnippet: 'if (password == storedHash) { ... }',
      fixSuggestion: 'Use bcrypt.compare() for secure password comparison',
      cwe: ['CWE-287'],
      owasp: ['A07:2021'],
      complianceImpact: ['PCI-DSS 8.2', 'OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'due_soon',
      daysRemaining: 7
    },
    {
      id: 'code-sec-005',
      type: 'code-security',
      title: 'Use of broken cryptographic algorithm',
      description: 'Using MD5 for password hashing which is cryptographically broken.',
      severity: 'high',
      riskScore: { concert: 7.5, comprehensive: 7.5 },
      location: 'src/utils/crypto.js:23',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'weak_cryptography',
      ruleId: 'javascript.crypto.security.insecure-hash.insecure-hash',
      ruleName: 'Insecure Cryptographic Algorithm',
      lineNumber: 23,
      codeSnippet: 'crypto.createHash("md5")',
      fixSuggestion: 'Use bcrypt, scrypt, or Argon2 for password hashing',
      cwe: ['CWE-327'],
      owasp: ['A02:2021'],
      complianceImpact: ['PCI-DSS 3.4', 'OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 14
    },
    {
      id: 'code-sec-006',
      type: 'code-security',
      title: 'Path Traversal in file upload',
      description: 'User-controlled file path allows directory traversal attack.',
      severity: 'high',
      riskScore: { concert: 7.5, comprehensive: 7.5 },
      location: 'src/api/upload.js:34',
      detectedAt: new Date().toISOString(),
      source: 'semgrep',
      issueType: 'path_traversal',
      ruleId: 'javascript.express.security.path-traversal.path-traversal',
      ruleName: 'Path Traversal',
      lineNumber: 34,
      codeSnippet: 'fs.writeFile(basePath + req.body.filename, data);',
      fixSuggestion: 'Validate and sanitize filename, use path.basename() to strip directory components',
      cwe: ['CWE-22'],
      owasp: ['A01:2021'],
      complianceImpact: ['OWASP Top 10'],
      slaDeadline: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      slaStatus: 'on_track',
      daysRemaining: 14
    }
  ];
}

// Convert CVEs to CVEExposures
function convertCVEsToExposures(cves: CVE[]): CVEExposure[] {
  return cves.map((cve, index) => ({
    id: `cve-exp-${index}`,
    type: 'cve' as const,
    title: `${cve.id}: ${cve.description.substring(0, 60)}${cve.description.length > 60 ? '...' : ''}`,
    description: cve.description,
    severity: cve.severity,
    riskScore: cve.riskScore || { concert: 5.0, comprehensive: 5.0 },
    location: cve.component,
    detectedAt: new Date().toISOString(),
    source: cve.source,
    cveId: cve.id,
    cvss: cve.cvss,
    cvssVector: cve.cvssVector,
    epss: cve.epss,
    epssPercentile: cve.epssPercentile,
    cisaKEV: cve.cisaKEV,
    kevDateAdded: cve.kevDateAdded,
    component: cve.component,
    version: cve.version,
    fixedVersion: cve.fixedVersion,
    sourceType: cve.sourceType,
    references: cve.references,
    complianceImpact: cve.complianceImpact,
    slaDeadline: cve.slaDeadline,
    slaStatus: cve.slaStatus,
    daysRemaining: cve.daysRemaining
  }));
}

// Generate all unified exposures
function generateAllExposures(): Exposure[] {
  const cveExposures = convertCVEsToExposures(demoCVEs).slice(0, 50); // Limit for performance
  const certificateExposures = generateCertificateExposures();
  const secretExposures = generateSecretExposures();
  const misconfigExposures = generateMisconfigExposures();
  const licenseExposures = generateLicenseExposures();
  const codeSecurityExposures = generateCodeSecurityExposures();

  return [
    ...secretExposures, // Secrets first (highest priority)
    ...certificateExposures,
    ...cveExposures,
    ...misconfigExposures,
    ...licenseExposures,
    ...codeSecurityExposures
  ];
}

// Generate extended summary
function generateExtendedSummary(exposures: Exposure[]): ExtendedScanSummary {
  const byType = {
    cve: exposures.filter(e => e.type === 'cve').length,
    certificate: exposures.filter(e => e.type === 'certificate').length,
    secret: exposures.filter(e => e.type === 'secret').length,
    misconfiguration: exposures.filter(e => e.type === 'misconfiguration').length,
    license: exposures.filter(e => e.type === 'license').length,
    codeSecurity: exposures.filter(e => e.type === 'code-security').length
  };

  const bySeverity = {
    critical: exposures.filter(e => e.severity === 'critical').length,
    high: exposures.filter(e => e.severity === 'high').length,
    medium: exposures.filter(e => e.severity === 'medium').length,
    low: exposures.filter(e => e.severity === 'low').length
  };

  const slaStatus = {
    overdue: exposures.filter(e => e.slaStatus === 'overdue').length,
    dueSoon: exposures.filter(e => e.slaStatus === 'due_soon').length,
    onTrack: exposures.filter(e => e.slaStatus === 'on_track').length,
    complianceRate: Math.round(((exposures.length - exposures.filter(e => e.slaStatus === 'overdue').length) / exposures.length) * 100)
  };

  return {
    totalExposures: exposures.length,
    critical: bySeverity.critical,
    high: bySeverity.high,
    medium: bySeverity.medium,
    low: bySeverity.low,
    overallRiskScore: 7.8,
    riskScore: { concert: 7.8, comprehensive: 7.8 },
    cisaKEVCount: exposures.filter(e => e.type === 'cve' && (e as CVEExposure).cisaKEV).length,
    byType,
    bySource: {
      demo: byType.cve,
      'certificate-scanner': byType.certificate,
      trufflehog: byType.secret,
      checkov: byType.misconfiguration,
      'license-checker': byType.license,
      semgrep: byType.codeSecurity
    },
    slaStatus
  };
}

// Generate extended remediation groups
function generateExtendedRemediationGroups(exposures: Exposure[]): ExtendedRemediationGroup[] {
  const groups: ExtendedRemediationGroup[] = [];

  // Secrets group (highest priority)
  const secrets = exposures.filter(e => e.type === 'secret');
  if (secrets.length > 0) {
    groups.push({
      id: 'rem-secrets',
      title: 'Remove Hardcoded Secrets',
      type: 'secret_removal',
      exposureType: 'secret',
      exposures: secrets.map(e => e.id),
      exposuresCount: secrets.length,
      riskReduction: 48,
      effort: 'medium',
      effortHours: secrets.length * 2,
      priority: 100,
      slaStatus: 'overdue',
      overdueCount: secrets.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: secrets.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 3.4', 'SOX Section 404', 'GDPR Article 32'],
      description: 'Rotate all credentials immediately and move to a secrets manager'
    });
  }

  // Certificates group
  const certificates = exposures.filter(e => e.type === 'certificate');
  if (certificates.length > 0) {
    groups.push({
      id: 'rem-certificates',
      title: 'Renew Expiring Certificates',
      type: 'certificate_renewal',
      exposureType: 'certificate',
      exposures: certificates.map(e => e.id),
      exposuresCount: certificates.length,
      riskReduction: 28,
      effort: 'low',
      effortHours: certificates.length * 0.5,
      priority: 90,
      slaStatus: certificates.some(e => e.slaStatus === 'overdue') ? 'overdue' : 'due_soon',
      overdueCount: certificates.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: certificates.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 4.1'],
      description: 'Renew certificates before they expire to prevent service outages'
    });
  }

  // Critical CVEs group
  const criticalCVEs = exposures.filter(e => e.type === 'cve' && e.severity === 'critical');
  if (criticalCVEs.length > 0) {
    groups.push({
      id: 'rem-critical-cves',
      title: 'Fix Critical CVEs',
      type: 'dependency_update',
      exposureType: 'cve',
      exposures: criticalCVEs.map(e => e.id),
      exposuresCount: criticalCVEs.length,
      riskReduction: 42,
      effort: 'medium',
      effortHours: criticalCVEs.length * 2,
      priority: 85,
      slaStatus: criticalCVEs.some(e => e.slaStatus === 'overdue') ? 'overdue' : 'due_soon',
      overdueCount: criticalCVEs.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: criticalCVEs.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 6.2', 'CISA BOD 22-01'],
      description: 'Update dependencies to fix critical CVEs including CISA KEV entries'
    });
  }

  // Code security group
  const codeIssues = exposures.filter(e => e.type === 'code-security');
  if (codeIssues.length > 0) {
    groups.push({
      id: 'rem-code-security',
      title: 'Fix Code Security Issues',
      type: 'code_fix',
      exposureType: 'code-security',
      exposures: codeIssues.map(e => e.id),
      exposuresCount: codeIssues.length,
      riskReduction: 35,
      effort: 'medium',
      effortHours: codeIssues.length * 1.5,
      priority: 75,
      slaStatus: codeIssues.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: codeIssues.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: codeIssues.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 6.5', 'OWASP Top 10'],
      description: 'Fix SQL injection, XSS, and other code vulnerabilities'
    });
  }

  // Misconfigurations group
  const misconfigs = exposures.filter(e => e.type === 'misconfiguration');
  if (misconfigs.length > 0) {
    groups.push({
      id: 'rem-misconfigs',
      title: 'Fix Infrastructure Misconfigurations',
      type: 'config_fix',
      exposureType: 'misconfiguration',
      exposures: misconfigs.map(e => e.id),
      exposuresCount: misconfigs.length,
      riskReduction: 25,
      effort: 'medium',
      effortHours: misconfigs.length * 1,
      priority: 60,
      slaStatus: misconfigs.some(e => e.slaStatus === 'due_soon') ? 'due_soon' : 'on_track',
      overdueCount: misconfigs.filter(e => e.slaStatus === 'overdue').length,
      dueSoonCount: misconfigs.filter(e => e.slaStatus === 'due_soon').length,
      complianceImpact: ['PCI-DSS 2.2', 'CIS Controls'],
      description: 'Fix Terraform and Kubernetes security misconfigurations'
    });
  }

  // License issues group
  const licenses = exposures.filter(e => e.type === 'license');
  if (licenses.length > 0) {
    groups.push({
      id: 'rem-licenses',
      title: 'Resolve License Issues',
      type: 'license_resolution',
      exposureType: 'license',
      exposures: licenses.map(e => e.id),
      exposuresCount: licenses.length,
      riskReduction: 15,
      effort: 'high',
      effortHours: licenses.length * 4,
      priority: 40,
      slaStatus: 'on_track',
      overdueCount: 0,
      dueSoonCount: 0,
      complianceImpact: ['Legal - IP Compliance'],
      description: 'Review and resolve copyleft and unknown license issues'
    });
  }

  return groups;
}

// Generate extended financial analysis
const demoExtendedFinancialAnalysis: ExtendedFinancialAnalysis = {
  breachCost: 4.2,
  secretBreachCost: 4.6,
  downtimeCost: 1.5,
  configurationRisk: 2.1,
  legalFees: 0.8,
  regulatoryFines: 2.5,
  totalRisk: 15.7,
  remediationCost: 0.085,
  roi: 185,
  breakdown: {
    cve: 4.2,
    certificate: 1.5,
    secret: 4.6,
    misconfiguration: 2.1,
    license: 0.8,
    codeSecurity: 2.5
  }
};

// Generate extended compliance status
const demoExtendedComplianceStatus: ExtendedComplianceStatus = {
  pciDss: { count: 24, exposures: ['secret-001', 'secret-002', 'cve-exp-1'] },
  hipaa: { count: 8, exposures: ['secret-003', 'cert-001'] },
  sox: { count: 12, exposures: ['secret-001', 'misconfig-001'] },
  gdpr: { count: 15, exposures: ['misconfig-001', 'code-sec-001'] },
  legal: { count: 4, exposures: ['license-001', 'license-002', 'license-003', 'license-004'] }
};

// Generate the unified exposures
const demoExposuresUnified = generateAllExposures();
const demoExtendedSummary = generateExtendedSummary(demoExposuresUnified);
const demoExtendedRemediationGroups = generateExtendedRemediationGroups(demoExposuresUnified);

// Extended Scan Result (NEW)
export const demoExtendedScanResult: ExtendedScanResult = {
  scanId: 'demo-exposure-scan-001',
  status: 'complete',
  progress: 100,
  progressMessage: 'Exposure scan complete',
  metadata: {
    repoUrl: 'https://github.com/acme-corp/payment-api',
    branch: 'main',
    context: demoContext,
    languages: ['javascript', 'java', 'python', 'terraform'],
    scanTypes: ['cve', 'certificate', 'secret', 'misconfiguration', 'license', 'code-security'],
    startTime: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
    endTime: new Date().toISOString()
  },
  summary: demoExtendedSummary,
  exposures: demoExposuresUnified,
  topology: demoTopology,
  remediationGroups: demoExtendedRemediationGroups,
  financialImpact: demoExtendedFinancialAnalysis,
  complianceStatus: demoExtendedComplianceStatus
};

// Export new unified exposure data
export const demoExposures = demoExposuresUnified;
export { demoExtendedFinancialAnalysis, demoExtendedComplianceStatus, demoExtendedSummary, demoExtendedRemediationGroups };
