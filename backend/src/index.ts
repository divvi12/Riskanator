import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { exec } from 'child_process';
import { promisify } from 'util';
import scanRoutes from './routes/scanRoutes';
import aiRoutes from './routes/aiRoutes';

const execAsync = promisify(exec);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'https://concert-tem-frontend.25bete04mfc7.eu-gb.codeengine.appdomain.cloud',
    /\.codeengine\.appdomain\.cloud$/,  // Allow all Code Engine subdomains
    /\.web\.app$/,                       // Allow Firebase Hosting domains
    /\.firebaseapp\.com$/                // Allow Firebase legacy domains
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Debug endpoint to check tool availability
app.get('/debug/tools', async (req, res) => {
  const results: Record<string, any> = {
    path: process.env.PATH,
    tools: {}
  };

  const commands = [
    { name: 'trivy', cmd: 'which trivy && trivy --version' },
    { name: 'pip-audit', cmd: 'which pip-audit && pip-audit --version' },
    { name: 'git', cmd: 'which git && git --version' },
    { name: 'ls-usr-local-bin', cmd: 'ls -la /usr/local/bin/' },
    { name: 'ls-usr-bin', cmd: 'ls -la /usr/bin/ | grep -E "trivy|pip"' }
  ];

  for (const { name, cmd } of commands) {
    try {
      const { stdout, stderr } = await execAsync(cmd, { timeout: 10000 });
      results.tools[name] = { success: true, stdout: stdout.trim(), stderr: stderr.trim() };
    } catch (e: any) {
      results.tools[name] = { success: false, error: e.message, stderr: e.stderr?.toString() };
    }
  }

  res.json(results);
});

// API Routes
app.use('/api', scanRoutes);
app.use('/api', aiRoutes);

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err.message);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Riskanator Backend Server                               ║
║   Unified Exposure Management Platform                    ║
║                                                           ║
║   Status: Running                                         ║
║   Port:   ${PORT}                                            ║
║   Mode:   ${process.env.NODE_ENV || 'development'}                               ║
║                                                           ║
║   Scan Endpoints:                                         ║
║   - POST /api/scan            - Start CVE scan            ║
║   - POST /api/exposure-scan   - Start exposure scan       ║
║   - GET  /api/scan/:id/status - Get scan status           ║
║   - GET  /api/scan/:id/results- Get scan results          ║
║                                                           ║
║   AI Endpoints:                                           ║
║   - POST /api/ai/initialize   - Initialize Gemini AI      ║
║   - GET  /api/ai/status       - Check AI status           ║
║   - POST /api/ai/explain      - Explain exposure          ║
║   - POST /api/ai/executive-summary - Generate summary     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

export default app;
