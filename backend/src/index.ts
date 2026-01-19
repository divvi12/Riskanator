import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import scanRoutes from './routes/scanRoutes';
import aiRoutes from './routes/aiRoutes';

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
    /\.codeengine\.appdomain\.cloud$/  // Allow all Code Engine subdomains
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
