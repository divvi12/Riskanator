import * as fs from 'fs';
import * as path from 'path';
import { CodeSecurityExposure } from '../types';
import { v4 as uuidv4 } from 'uuid';

export interface CodeSecurityScanResult {
  exposures: CodeSecurityExposure[];
  success: boolean;
  error?: string;
}

// Security patterns to detect
interface SecurityPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  issueType: string;
  description: string;
  cwe: string[];
  owasp: string[];
  fixSuggestion: string;
}

const SECURITY_PATTERNS: SecurityPattern[] = [
  // SQL Injection
  {
    id: 'sql-injection-concat',
    name: 'SQL Injection via String Concatenation',
    pattern: /(?:query|execute|exec)\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\$\{/gi,
    severity: 'critical',
    issueType: 'sql_injection',
    description: 'User input directly concatenated into SQL query, enabling SQL injection attacks',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Use parameterized queries or prepared statements instead of string concatenation'
  },
  {
    id: 'sql-injection-plus',
    name: 'SQL Injection via String Concatenation',
    pattern: /(?:query|execute)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+\s*(?:req\.|user|input)/gi,
    severity: 'critical',
    issueType: 'sql_injection',
    description: 'User input concatenated with + operator into SQL query',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Use parameterized queries with placeholders like ? or $1'
  },
  // Command Injection
  {
    id: 'command-injection-exec',
    name: 'Command Injection via exec()',
    pattern: /exec\s*\(\s*[`'"].*\$\{.*\}/gi,
    severity: 'critical',
    issueType: 'command_injection',
    description: 'User input directly passed to shell command execution',
    cwe: ['CWE-78'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Validate and sanitize input, use execFile() with argument arrays, or avoid shell execution'
  },
  {
    id: 'command-injection-spawn',
    name: 'Potential Command Injection',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:req\.|user|input|params)/gi,
    severity: 'high',
    issueType: 'command_injection',
    description: 'User input potentially passed to command execution function',
    cwe: ['CWE-78'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Validate input against allowlist, use execFile with argument arrays'
  },
  // XSS
  {
    id: 'xss-reflected',
    name: 'Reflected XSS',
    pattern: /res\.(?:send|write)\s*\([^)]*(?:<html|<body|<div|<script)[^)]*\$\{/gi,
    severity: 'high',
    issueType: 'xss',
    description: 'User input directly rendered in HTML response without sanitization',
    cwe: ['CWE-79'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Sanitize user input using a library like DOMPurify or encode HTML entities'
  },
  {
    id: 'xss-innerHTML',
    name: 'Potential DOM XSS',
    pattern: /innerHTML\s*=\s*(?!['"`])/gi,
    severity: 'medium',
    issueType: 'xss',
    description: 'Dynamic content assigned to innerHTML without sanitization',
    cwe: ['CWE-79'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Use textContent instead or sanitize with DOMPurify'
  },
  // Path Traversal
  {
    id: 'path-traversal',
    name: 'Path Traversal Vulnerability',
    pattern: /(?:readFile|writeFile|createReadStream|access)\s*\([^)]*(?:req\.|user|params|filename)/gi,
    severity: 'high',
    issueType: 'path_traversal',
    description: 'User input used in file path without sanitization',
    cwe: ['CWE-22'],
    owasp: ['A01:2021'],
    fixSuggestion: 'Validate path against base directory, use path.resolve() and check for directory traversal'
  },
  // Weak Cryptography
  {
    id: 'weak-hash-md5',
    name: 'Weak Hash Algorithm (MD5)',
    pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    severity: 'high',
    issueType: 'weak_cryptography',
    description: 'MD5 is cryptographically broken and should not be used for security',
    cwe: ['CWE-328'],
    owasp: ['A02:2021'],
    fixSuggestion: 'Use SHA-256 or better: crypto.createHash("sha256")'
  },
  {
    id: 'weak-hash-sha1',
    name: 'Weak Hash Algorithm (SHA1)',
    pattern: /createHash\s*\(\s*['"]sha1?['"]\s*\)/gi,
    severity: 'medium',
    issueType: 'weak_cryptography',
    description: 'SHA-1 is deprecated and vulnerable to collision attacks',
    cwe: ['CWE-328'],
    owasp: ['A02:2021'],
    fixSuggestion: 'Use SHA-256 or better: crypto.createHash("sha256")'
  },
  {
    id: 'weak-cipher-des',
    name: 'Weak Cipher Algorithm (DES)',
    pattern: /createCipher(?:iv)?\s*\(\s*['"](?:des|des3|rc4)['"]/gi,
    severity: 'high',
    issueType: 'weak_cryptography',
    description: 'DES/RC4 are weak encryption algorithms vulnerable to attacks',
    cwe: ['CWE-327'],
    owasp: ['A02:2021'],
    fixSuggestion: 'Use AES-256-GCM: crypto.createCipheriv("aes-256-gcm", key, iv)'
  },
  // Insecure Randomness
  {
    id: 'insecure-random',
    name: 'Insecure Random Number Generator',
    pattern: /Math\.random\s*\(\s*\)/g,
    severity: 'medium',
    issueType: 'insecure_randomness',
    description: 'Math.random() is not cryptographically secure',
    cwe: ['CWE-330'],
    owasp: ['A02:2021'],
    fixSuggestion: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive operations'
  },
  // Hardcoded Secrets (backup detection)
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded Secret',
    pattern: /(?:password|secret|api_?key|token|credential)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'high',
    issueType: 'hardcoded_secret',
    description: 'Sensitive credential appears to be hardcoded in source code',
    cwe: ['CWE-798'],
    owasp: ['A07:2021'],
    fixSuggestion: 'Store secrets in environment variables or a secrets manager'
  },
  // Open Redirect
  {
    id: 'open-redirect',
    name: 'Open Redirect Vulnerability',
    pattern: /res\.redirect\s*\(\s*(?:req\.|user|url|params)/gi,
    severity: 'medium',
    issueType: 'open_redirect',
    description: 'User-controlled redirect URL without validation',
    cwe: ['CWE-601'],
    owasp: ['A01:2021'],
    fixSuggestion: 'Validate redirect URLs against an allowlist of trusted domains'
  },
  // Information Disclosure
  {
    id: 'stack-trace-exposure',
    name: 'Stack Trace Exposure',
    pattern: /(?:err|error)\.stack/gi,
    severity: 'low',
    issueType: 'information_disclosure',
    description: 'Stack traces may expose sensitive implementation details',
    cwe: ['CWE-209'],
    owasp: ['A04:2021'],
    fixSuggestion: 'Log stack traces server-side but return generic error messages to users'
  },
  // Eval usage
  {
    id: 'dangerous-eval',
    name: 'Dangerous eval() Usage',
    pattern: /\beval\s*\(/g,
    severity: 'critical',
    issueType: 'code_injection',
    description: 'eval() can execute arbitrary code and is a security risk',
    cwe: ['CWE-95'],
    owasp: ['A03:2021'],
    fixSuggestion: 'Avoid eval() entirely. Use JSON.parse() for JSON or safer alternatives'
  },
  // CORS Misconfiguration
  {
    id: 'cors-wildcard',
    name: 'Permissive CORS Configuration',
    pattern: /Access-Control-Allow-Origin['"]\s*,\s*['"][*]['"]/gi,
    severity: 'medium',
    issueType: 'security_misconfiguration',
    description: 'CORS allows requests from any origin',
    cwe: ['CWE-942'],
    owasp: ['A05:2021'],
    fixSuggestion: 'Restrict CORS to specific trusted domains'
  },
  // JWT without algorithm
  {
    id: 'jwt-no-algorithm',
    name: 'JWT Without Algorithm Specification',
    pattern: /jwt\.sign\s*\([^)]*,\s*[^,)]+\s*\)/gi,
    severity: 'medium',
    issueType: 'weak_cryptography',
    description: 'JWT signed without explicit algorithm specification',
    cwe: ['CWE-347'],
    owasp: ['A02:2021'],
    fixSuggestion: 'Specify algorithm explicitly: jwt.sign(payload, secret, { algorithm: "HS256" })'
  }
];

// File extensions to scan
const SCANNABLE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];

// Directories to skip
const SKIP_DIRS = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'vendor'];

// Recursively get all scannable files
function getScannableFiles(dir: string): string[] {
  const files: string[] = [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.includes(entry.name)) {
          files.push(...getScannableFiles(fullPath));
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCANNABLE_EXTENSIONS.includes(ext)) {
          files.push(fullPath);
        }
      }
    }
  } catch (err) {
    // Skip directories we can't read
  }

  return files;
}

// Extract code snippet around a match
function extractCodeSnippet(content: string, matchIndex: number, matchLength: number): string {
  const lines = content.split('\n');
  let currentIndex = 0;
  let matchLine = 0;

  // Find which line contains the match
  for (let i = 0; i < lines.length; i++) {
    if (currentIndex + lines[i].length >= matchIndex) {
      matchLine = i;
      break;
    }
    currentIndex += lines[i].length + 1; // +1 for newline
  }

  // Get 2 lines before and after
  const startLine = Math.max(0, matchLine - 2);
  const endLine = Math.min(lines.length - 1, matchLine + 2);

  return lines.slice(startLine, endLine + 1).join('\n');
}

// Get line number from character index
function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

// Scan a single file for security issues
function scanFile(filePath: string, repoPath: string): CodeSecurityExposure[] {
  const exposures: CodeSecurityExposure[] = [];

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const relativePath = filePath.replace(repoPath + '/', '').replace(repoPath, '').replace(/^\//, '');

    for (const pattern of SECURITY_PATTERNS) {
      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNumber = getLineNumber(content, match.index);
        const codeSnippet = extractCodeSnippet(content, match.index, match[0].length);

        const exposure: CodeSecurityExposure = {
          id: uuidv4(),
          type: 'code-security',
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          riskScore: { concert: 0, comprehensive: 0 },
          location: `${relativePath}:${lineNumber}`,
          detectedAt: new Date().toISOString(),
          source: 'pattern-scanner',
          issueType: pattern.issueType as any,
          ruleName: pattern.id,
          ruleId: pattern.id,
          filePath: relativePath,
          lineNumber,
          codeSnippet,
          cwe: pattern.cwe,
          owasp: pattern.owasp,
          fixSuggestion: pattern.fixSuggestion
        };

        exposures.push(exposure);

        // Prevent infinite loops on zero-length matches
        if (match[0].length === 0) {
          pattern.pattern.lastIndex++;
        }
      }
    }
  } catch (err) {
    // Skip files we can't read
  }

  return exposures;
}

// Main scanning function
export async function runCodeSecurityScanning(repoPath: string): Promise<CodeSecurityScanResult> {
  try {
    const files = getScannableFiles(repoPath);
    const allExposures: CodeSecurityExposure[] = [];

    for (const file of files) {
      const fileExposures = scanFile(file, repoPath);
      allExposures.push(...fileExposures);
    }

    // Deduplicate by location + rule
    const seen = new Set<string>();
    const dedupedExposures = allExposures.filter(exp => {
      const key = `${exp.location}:${exp.ruleName}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return {
      exposures: dedupedExposures,
      success: true
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error in code security scanning';
    return {
      exposures: [],
      success: false,
      error: errorMessage
    };
  }
}
