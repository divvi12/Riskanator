// API Configuration
// In development: defaults to localhost
// In production: uses VITE_API_URL environment variable

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export const API_ENDPOINTS = {
  exposureScan: `${API_BASE_URL}/api/exposure-scan`,
  scan: `${API_BASE_URL}/api/scan`,
  explain: `${API_BASE_URL}/api/explain`,
  health: `${API_BASE_URL}/api/health`,
};
