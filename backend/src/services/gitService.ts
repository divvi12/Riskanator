import simpleGit, { SimpleGit } from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

const REPO_TEMP_DIR = process.env.REPO_TEMP_DIR || '/tmp/cve-scanner/repos';

export interface CloneResult {
  success: boolean;
  localPath: string;
  error?: string;
}

export async function cloneRepository(
  repoUrl: string,
  isPrivate: boolean,
  pat?: string,
  branch: string = 'main'
): Promise<CloneResult> {
  const scanId = uuidv4();
  const localPath = path.join(REPO_TEMP_DIR, scanId);

  try {
    // Ensure temp directory exists
    if (!fs.existsSync(REPO_TEMP_DIR)) {
      fs.mkdirSync(REPO_TEMP_DIR, { recursive: true });
    }

    // Build authenticated URL if private
    let cloneUrl = repoUrl;
    if (isPrivate && pat) {
      const urlObj = new URL(repoUrl);
      // Handle GitHub, GitLab, Bitbucket
      if (urlObj.hostname.includes('github')) {
        cloneUrl = `https://${pat}@${urlObj.hostname}${urlObj.pathname}`;
      } else if (urlObj.hostname.includes('gitlab')) {
        cloneUrl = `https://oauth2:${pat}@${urlObj.hostname}${urlObj.pathname}`;
      } else if (urlObj.hostname.includes('bitbucket')) {
        cloneUrl = `https://x-token-auth:${pat}@${urlObj.hostname}${urlObj.pathname}`;
      } else {
        // Generic git URL with PAT
        cloneUrl = `https://${pat}@${urlObj.hostname}${urlObj.pathname}`;
      }
    }

    const git: SimpleGit = simpleGit();

    await git.clone(cloneUrl, localPath, [
      '--depth', '1',
      '--branch', branch,
      '--single-branch'
    ]);

    return {
      success: true,
      localPath
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error during clone';
    return {
      success: false,
      localPath,
      error: errorMessage
    };
  }
}

export async function cleanupRepository(localPath: string): Promise<void> {
  try {
    if (fs.existsSync(localPath)) {
      fs.rmSync(localPath, { recursive: true, force: true });
    }
  } catch (error) {
    console.error('Error cleaning up repository:', error);
  }
}

export function detectLanguages(localPath: string): string[] {
  const languages: string[] = [];

  const languageFiles: Record<string, string> = {
    'package.json': 'javascript',
    'package-lock.json': 'javascript',
    'yarn.lock': 'javascript',
    'requirements.txt': 'python',
    'Pipfile': 'python',
    'setup.py': 'python',
    'pyproject.toml': 'python',
    'pom.xml': 'java',
    'build.gradle': 'java',
    'Gemfile': 'ruby',
    'go.mod': 'go',
    'Cargo.toml': 'rust',
    '*.csproj': 'dotnet',
    'packages.config': 'dotnet',
    'composer.json': 'php',
    'Dockerfile': 'docker',
    '*.tf': 'terraform',
    '*.yaml': 'kubernetes',
    '*.yml': 'kubernetes',
  };

  try {
    const files = getAllFiles(localPath);

    for (const file of files) {
      const basename = path.basename(file);
      const ext = path.extname(file);

      // Check exact matches
      if (languageFiles[basename] && !languages.includes(languageFiles[basename])) {
        languages.push(languageFiles[basename]);
      }

      // Check extensions
      if (ext === '.tf' && !languages.includes('terraform')) {
        languages.push('terraform');
      }
      if (ext === '.py' && !languages.includes('python')) {
        languages.push('python');
      }
      if ((ext === '.js' || ext === '.ts' || ext === '.jsx' || ext === '.tsx') && !languages.includes('javascript')) {
        languages.push('javascript');
      }
      if (ext === '.java' && !languages.includes('java')) {
        languages.push('java');
      }
      if (ext === '.rb' && !languages.includes('ruby')) {
        languages.push('ruby');
      }
      if (ext === '.go' && !languages.includes('go')) {
        languages.push('go');
      }
      if (ext === '.rs' && !languages.includes('rust')) {
        languages.push('rust');
      }
      if ((ext === '.cs' || ext === '.vb') && !languages.includes('dotnet')) {
        languages.push('dotnet');
      }
      if (ext === '.php' && !languages.includes('php')) {
        languages.push('php');
      }
      if (basename === 'Dockerfile' && !languages.includes('docker')) {
        languages.push('docker');
      }
    }
  } catch (error) {
    console.error('Error detecting languages:', error);
  }

  return languages;
}

function getAllFiles(dirPath: string, arrayOfFiles: string[] = []): string[] {
  try {
    const files = fs.readdirSync(dirPath);

    for (const file of files) {
      // Skip hidden files/folders and node_modules
      if (file.startsWith('.') || file === 'node_modules' || file === '__pycache__' || file === 'venv') {
        continue;
      }

      const fullPath = path.join(dirPath, file);

      if (fs.statSync(fullPath).isDirectory()) {
        getAllFiles(fullPath, arrayOfFiles);
      } else {
        arrayOfFiles.push(fullPath);
      }
    }
  } catch (error) {
    // Ignore permission errors
  }

  return arrayOfFiles;
}
