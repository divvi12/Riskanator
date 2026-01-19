import { Router, Request, Response } from 'express';
import {
  initializeGemini,
  isGeminiInitialized,
  generateExposureExplanation,
  generateExecutiveSummary
} from '../services/geminiService';
import { Exposure, ApplicationContext } from '../types';

const router = Router();

// Initialize Gemini with API key
router.post('/ai/initialize', async (req: Request, res: Response) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ error: 'API key is required' });
  }

  const success = initializeGemini(apiKey);

  if (success) {
    res.json({ success: true, message: 'Gemini AI initialized successfully' });
  } else {
    res.status(500).json({ error: 'Failed to initialize Gemini AI' });
  }
});

// Check if Gemini is initialized
router.get('/ai/status', (req: Request, res: Response) => {
  res.json({ initialized: isGeminiInitialized() });
});

// Generate explanation for a single exposure
router.post('/ai/explain', async (req: Request, res: Response) => {
  const { exposure, context, model } = req.body as {
    exposure: Exposure;
    context?: ApplicationContext;
    model?: string;
  };

  if (!exposure) {
    return res.status(400).json({ error: 'Exposure data is required' });
  }

  if (!isGeminiInitialized()) {
    return res.status(400).json({
      error: 'Gemini AI not initialized',
      message: 'Please configure your API key in Settings'
    });
  }

  try {
    const explanation = await generateExposureExplanation(exposure, context, model);
    res.json(explanation);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to generate explanation', message });
  }
});

// Generate explanation for multiple exposures (batch)
router.post('/ai/explain-batch', async (req: Request, res: Response) => {
  const { exposures, context, model } = req.body as {
    exposures: Exposure[];
    context?: ApplicationContext;
    model?: string;
  };

  if (!exposures || !Array.isArray(exposures)) {
    return res.status(400).json({ error: 'Exposures array is required' });
  }

  if (!isGeminiInitialized()) {
    return res.status(400).json({
      error: 'Gemini AI not initialized',
      message: 'Please configure your API key in Settings'
    });
  }

  try {
    const explanations = await Promise.all(
      exposures.slice(0, 10).map(exposure => // Limit to 10 to avoid rate limits
        generateExposureExplanation(exposure, context, model)
          .catch(err => ({
            exposureId: exposure.id,
            exposureType: exposure.type,
            error: err.message
          }))
      )
    );
    res.json({ explanations });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to generate explanations', message });
  }
});

// Generate executive summary
router.post('/ai/executive-summary', async (req: Request, res: Response) => {
  const { exposures, context, model } = req.body as {
    exposures: Exposure[];
    context?: ApplicationContext;
    model?: string;
  };

  if (!exposures || !Array.isArray(exposures)) {
    return res.status(400).json({ error: 'Exposures array is required' });
  }

  if (!isGeminiInitialized()) {
    return res.status(400).json({
      error: 'Gemini AI not initialized',
      message: 'Please configure your API key in Settings'
    });
  }

  try {
    const summary = await generateExecutiveSummary(exposures, context, model);
    res.json(summary);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    res.status(500).json({ error: 'Failed to generate executive summary', message });
  }
});

export default router;
