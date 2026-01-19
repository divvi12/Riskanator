// ============================================================
// CALCULATOR MODULE INDEX
// Exports all calculator classes and factory functions
// ============================================================

// Base calculator
export { BaseExposureCalculator } from './baseCalculator';

// Type-specific calculators
export { CVECalculator, cveCalculator } from './cveCalculator';
export { SecretCalculator, secretCalculator } from './secretCalculator';
export { CertificateCalculator, certificateCalculator } from './certificateCalculator';
export {
  MisconfigurationCalculator,
  misconfigurationCalculator,
  createMisconfigurationCalculator
} from './misconfigurationCalculator';
export {
  LicenseCalculator,
  licenseCalculator,
  createLicenseCalculator
} from './licenseCalculator';
export {
  CodeSecurityCalculator,
  codeSecurityCalculator,
  createCodeSecurityCalculator
} from './codeSecurityCalculator';

// Aggregate calculator
export { AggregateScoreCalculator, aggregateCalculator } from './aggregateCalculator';

// Re-export config for convenience
export * from '../../config/scoringConfig';
