import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  TextInput,
  RadioButtonGroup,
  RadioButton,
  Checkbox,
  Select,
  SelectItem,
  ProgressIndicator,
  ProgressStep,
  NumberInput,
  InlineLoading,
  InlineNotification,
  Tile,
  Tag,
  ProgressBar
} from '@carbon/react';
import { ArrowRight, ArrowLeft, Application, Code, Security, Warning, CheckmarkFilled, Folder } from '@carbon/icons-react';
import { useAppContext } from '../App';
import {
  ApplicationContext,
  INDUSTRIES,
  SECURITY_CONTROLS,
  CRITICALITY_TIERS,
  ScanRequest
} from '../types';
import { startScan, pollScanStatus } from '../services/api';
import { saveToHistory } from '../services/scanHistoryService';

const STEPS = [
  'Repository',
  'Basic Info',
  'Criticality',
  'Data Sensitivity',
  'Access & Controls',
  'Formula'
];

function ScanSetup() {
  const navigate = useNavigate();
  const { setCurrentScan, setApplicationContext } = useAppContext();

  const [currentStep, setCurrentStep] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({ status: '', progress: 0, message: '' });
  const [scanLog, setScanLog] = useState<Array<{ time: string; message: string; type: 'info' | 'success' | 'warning' | 'error' }>>([]);
  const [detectedLanguages, setDetectedLanguages] = useState<string[]>([]);
  const [scanStartTime, setScanStartTime] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Form state
  const [formData, setFormData] = useState({
    // Step 1: Repository
    repoUrl: '',
    isPrivate: false,
    pat: '',
    branch: 'main',
    // Step 2: Basic Info
    appName: '',
    industry: '',
    purpose: '',
    // Step 3: Criticality
    criticality: 3,
    // Step 4: Data Sensitivity
    pii: false,
    phi: false,
    pci: false,
    tradeSecrets: false,
    // Step 5: Access & Controls
    publicEndpoints: 0,
    privateEndpoints: 0,
    networkExposure: 'internal' as 'internal' | 'dmz' | 'public',
    controls: [] as string[],
    // Step 6: Formula
    formula: 'concert' as 'concert' | 'comprehensive'
  });

  const updateFormData = (field: string, value: unknown) => {
    setFormData(prev => {
      const updated = { ...prev, [field]: value };

      // Auto-fill app name from repo URL if not already set
      if (field === 'repoUrl' && typeof value === 'string' && !prev.appName) {
        const repoName = extractRepoName(value);
        if (repoName) {
          updated.appName = repoName;
        }
      }

      return updated;
    });
  };

  const extractRepoName = (url: string): string => {
    try {
      // Handle various git URL formats
      // https://github.com/owner/repo.git
      // https://github.com/owner/repo
      // git@github.com:owner/repo.git
      const cleaned = url.replace(/\.git$/, '');
      const parts = cleaned.split('/');
      const repoName = parts[parts.length - 1];
      return repoName || '';
    } catch {
      return '';
    }
  };

  const handleNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  // Auto-scroll log to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [scanLog]);

  // Update elapsed time every second while scanning
  const [, setTick] = useState(0);
  useEffect(() => {
    if (isScanning) {
      const interval = setInterval(() => setTick(t => t + 1), 1000);
      return () => clearInterval(interval);
    }
  }, [isScanning]);

  const addLogEntry = (message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    const time = new Date().toLocaleTimeString();
    setScanLog(prev => [...prev, { time, message, type }]);

    // Extract detected languages from message
    if (message.includes('Detected') && message.includes('language')) {
      const match = message.match(/Detected \d+ language\(s\): (.+)\. Starting/);
      if (match) {
        setDetectedLanguages(match[1].split(', '));
      }
    }
  };

  const handleStartScan = async () => {
    setIsScanning(true);
    setError(null);
    setScanLog([]);
    setScanStartTime(new Date());
    setDetectedLanguages([]);

    const context: ApplicationContext = {
      appName: formData.appName || 'Unnamed Application',
      industry: formData.industry || 'other',
      purpose: formData.purpose,
      criticality: formData.criticality,
      dataSensitivity: {
        pii: formData.pii,
        phi: formData.phi,
        pci: formData.pci,
        tradeSecrets: formData.tradeSecrets
      },
      accessControls: {
        publicEndpoints: formData.publicEndpoints,
        privateEndpoints: formData.privateEndpoints,
        networkExposure: formData.networkExposure,
        controls: formData.controls
      },
      formula: formData.formula
    };

    const request: ScanRequest = {
      repoUrl: formData.repoUrl,
      isPrivate: formData.isPrivate,
      pat: formData.pat || undefined,
      branch: formData.branch,
      context
    };

    addLogEntry('Starting scan...', 'info');

    try {
      const { scanId } = await startScan(request);
      addLogEntry(`Scan initiated (ID: ${scanId.substring(0, 8)}...)`, 'info');

      const result = await pollScanStatus(
        scanId,
        (status, progress, message) => {
          setScanProgress({ status, progress, message });

          // Determine log entry type based on message content
          let type: 'info' | 'success' | 'warning' | 'error' = 'info';
          if (message.includes('Found') || message.includes('complete')) type = 'success';
          if (message.includes('WARNING') || message.includes('CISA')) type = 'warning';
          if (message.includes('error') || message.includes('failed')) type = 'error';

          addLogEntry(message, type);
        }
      );

      addLogEntry('Scan completed successfully!', 'success');
      setCurrentScan(result);
      setApplicationContext(context);
      saveToHistory(result);
      navigate('/app/dashboard');
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Scan failed';
      addLogEntry(errorMsg, 'error');
      setError(errorMsg);
      setIsScanning(false);
    }
  };

  const isStepValid = (): boolean => {
    switch (currentStep) {
      case 0:
        return formData.repoUrl.length > 0;
      default:
        return true;
    }
  };

  // Calculate elapsed time
  const getElapsedTime = () => {
    if (!scanStartTime) return '0:00';
    const elapsed = Math.floor((Date.now() - scanStartTime.getTime()) / 1000);
    const mins = Math.floor(elapsed / 60);
    const secs = elapsed % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Get industry label
  const getIndustryLabel = (value: string) => {
    const industry = INDUSTRIES.find(i => i.value === value);
    return industry?.label || value || 'Not specified';
  };

  // Get criticality label
  const getCriticalityLabel = (value: number) => {
    const tier = CRITICALITY_TIERS.find(t => t.value === value);
    return tier?.label || `Tier ${value}`;
  };

  if (isScanning) {
    return (
      <div style={{ maxWidth: '1200px' }}>
        <h2 style={{ marginBottom: '0.5rem' }}>Scanning Repository</h2>
        <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem' }}>
          Analyzing your codebase for security exposures...
        </p>

        {/* Progress Bar */}
        <div style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.875rem' }}>{scanProgress.message || 'Initializing...'}</span>
            <span style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
              {scanProgress.progress}% • {getElapsedTime()}
            </span>
          </div>
          <ProgressBar value={scanProgress.progress} max={100} size="big" label="Scan progress" hideLabel />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          {/* Left Column: Application Info */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Repository Info */}
            <Tile style={{ padding: '1.25rem', backgroundColor: '#161616' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <Folder size={20} style={{ color: '#0f62fe' }} />
                <h4 style={{ margin: 0 }}>Repository</h4>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.875rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>URL:</span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {formData.repoUrl}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Branch:</span>
                  <span>{formData.branch}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Access:</span>
                  <Tag size="sm" type={formData.isPrivate ? 'purple' : 'green'}>
                    {formData.isPrivate ? 'Private' : 'Public'}
                  </Tag>
                </div>
                {detectedLanguages.length > 0 && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ color: 'var(--cve-text-secondary)' }}>Languages:</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.25rem' }}>
                      {detectedLanguages.map(lang => (
                        <Tag key={lang} size="sm" type="blue">{lang}</Tag>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Tile>

            {/* Application Context */}
            <Tile style={{ padding: '1.25rem', backgroundColor: '#161616' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <Application size={20} style={{ color: '#8a3ffc' }} />
                <h4 style={{ margin: 0 }}>Application Context</h4>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.875rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Name:</span>
                  <span>{formData.appName || 'Unnamed'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Industry:</span>
                  <span>{getIndustryLabel(formData.industry)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Criticality:</span>
                  <Tag size="sm" type={formData.criticality >= 4 ? 'red' : formData.criticality >= 3 ? 'magenta' : 'gray'}>
                    {getCriticalityLabel(formData.criticality)}
                  </Tag>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--cve-text-secondary)' }}>Network:</span>
                  <span style={{ textTransform: 'capitalize' }}>{formData.networkExposure}</span>
                </div>
              </div>
            </Tile>

            {/* Data Sensitivity */}
            <Tile style={{ padding: '1.25rem', backgroundColor: '#161616' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                <Security size={20} style={{ color: '#da1e28' }} />
                <h4 style={{ margin: 0 }}>Data Sensitivity</h4>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {formData.pii && <Tag size="sm" type="red">PII</Tag>}
                {formData.phi && <Tag size="sm" type="red">PHI</Tag>}
                {formData.pci && <Tag size="sm" type="red">PCI</Tag>}
                {formData.tradeSecrets && <Tag size="sm" type="magenta">Trade Secrets</Tag>}
                {!formData.pii && !formData.phi && !formData.pci && !formData.tradeSecrets && (
                  <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>No sensitive data flagged</span>
                )}
              </div>
              {formData.controls.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem' }}>Security Controls:</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.25rem' }}>
                    {formData.controls.slice(0, 4).map(ctrl => {
                      const control = SECURITY_CONTROLS.find(c => c.id === ctrl);
                      return <Tag key={ctrl} size="sm" type="green">{control?.label || ctrl}</Tag>;
                    })}
                    {formData.controls.length > 4 && (
                      <Tag size="sm" type="gray">+{formData.controls.length - 4} more</Tag>
                    )}
                  </div>
                </div>
              )}
            </Tile>
          </div>

          {/* Right Column: Scan Log */}
          <Tile style={{ padding: '1.25rem', backgroundColor: '#161616', height: 'fit-content', maxHeight: '500px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <Code size={20} style={{ color: '#42be65' }} />
              <h4 style={{ margin: 0 }}>Scan Activity</h4>
              <InlineLoading style={{ marginLeft: 'auto' }} />
            </div>
            <div style={{
              flex: 1,
              overflowY: 'auto',
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              backgroundColor: '#0d0d0d',
              padding: '0.75rem',
              borderRadius: '4px',
              maxHeight: '400px'
            }}>
              {scanLog.map((entry, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  gap: '0.5rem',
                  marginBottom: '0.25rem',
                  color: entry.type === 'error' ? '#fa4d56' :
                         entry.type === 'warning' ? '#f1c21b' :
                         entry.type === 'success' ? '#42be65' : '#c6c6c6'
                }}>
                  <span style={{ color: '#6f6f6f', flexShrink: 0 }}>[{entry.time}]</span>
                  {entry.type === 'warning' && <Warning size={12} style={{ flexShrink: 0, marginTop: '2px' }} />}
                  {entry.type === 'success' && <CheckmarkFilled size={12} style={{ flexShrink: 0, marginTop: '2px' }} />}
                  <span style={{ wordBreak: 'break-word' }}>{entry.message}</span>
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </Tile>
        </div>

        {/* Progress Steps */}
        <div style={{ marginTop: '2rem' }}>
          <ProgressIndicator currentIndex={getProgressIndex(scanProgress.status)}>
            <ProgressStep label="Clone" secondaryLabel="Repository" />
            <ProgressStep label="Detect" secondaryLabel="Languages" />
            <ProgressStep label="Scan" secondaryLabel="Vulnerabilities" />
            <ProgressStep label="Enrich" secondaryLabel="CVE Data" />
            <ProgressStep label="Complete" secondaryLabel="Analysis" />
          </ProgressIndicator>
        </div>
      </div>
    );
  }

  return (
    <div className="wizard-container">
      <h1 style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>New Scan</h1>
      <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '2rem' }}>
        Configure your repository scan with application context for accurate risk scoring.
      </p>

      {error && (
        <InlineNotification
          kind="error"
          title="Scan Failed"
          subtitle={error}
          onCloseButtonClick={() => setError(null)}
          style={{ marginBottom: '1rem' }}
        />
      )}

      <ProgressIndicator currentIndex={currentStep} spaceEqually>
        {STEPS.map((step, index) => (
          <ProgressStep key={index} label={step} />
        ))}
      </ProgressIndicator>

      <div className="wizard-step">
        {/* Step 1: Repository */}
        {currentStep === 0 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Repository Information</h3>

            <div className="form-group">
              <TextInput
                id="repo-url"
                labelText="Repository URL"
                placeholder="https://github.com/owner/repo"
                value={formData.repoUrl}
                onChange={(e) => updateFormData('repoUrl', e.target.value)}
              />
            </div>

            <div className="form-group">
              <RadioButtonGroup
                legendText="Repository Access"
                name="repo-access"
                valueSelected={formData.isPrivate ? 'private' : 'public'}
                onChange={(value) => updateFormData('isPrivate', value === 'private')}
              >
                <RadioButton labelText="Public" value="public" />
                <RadioButton labelText="Private" value="private" />
              </RadioButtonGroup>
            </div>

            {formData.isPrivate && (
              <div className="form-group">
                <TextInput
                  id="pat"
                  type="password"
                  labelText="Personal Access Token"
                  placeholder="ghp_xxxxxxxxxxxx"
                  value={formData.pat}
                  onChange={(e) => updateFormData('pat', e.target.value)}
                  helperText="GitHub: 'repo' scope | GitLab: 'read_repository' scope | Bitbucket: 'repository:read' scope"
                />
              </div>
            )}

            <div className="form-group">
              <TextInput
                id="branch"
                labelText="Branch"
                placeholder="main"
                value={formData.branch}
                onChange={(e) => updateFormData('branch', e.target.value)}
              />
            </div>
          </div>
        )}

        {/* Step 2: Basic Info */}
        {currentStep === 1 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Application Information</h3>

            <div className="form-group">
              <TextInput
                id="app-name"
                labelText="Application Name"
                placeholder="My Application"
                value={formData.appName}
                onChange={(e) => updateFormData('appName', e.target.value)}
              />
            </div>

            <div className="form-group">
              <Select
                id="industry"
                labelText="Industry"
                value={formData.industry}
                onChange={(e) => updateFormData('industry', e.target.value)}
              >
                <SelectItem value="" text="Select industry..." />
                {INDUSTRIES.map((ind) => (
                  <SelectItem key={ind.value} value={ind.value} text={ind.label} />
                ))}
              </Select>
            </div>

            <div className="form-group">
              <TextInput
                id="purpose"
                labelText="Application Purpose"
                placeholder="Describe what this application does..."
                value={formData.purpose}
                onChange={(e) => updateFormData('purpose', e.target.value)}
              />
            </div>
          </div>
        )}

        {/* Step 3: Criticality */}
        {currentStep === 2 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Business Criticality</h3>
            <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem' }}>
              Select the criticality tier that best describes this application's importance to your business.
            </p>

            <RadioButtonGroup
              legendText="Criticality Tier"
              name="criticality"
              orientation="vertical"
              valueSelected={formData.criticality.toString()}
              onChange={(value) => updateFormData('criticality', parseInt(value as string))}
            >
              {CRITICALITY_TIERS.map((tier) => (
                <RadioButton
                  key={tier.value}
                  labelText={
                    <div>
                      <strong>{tier.label}</strong>
                      <br />
                      <span style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                        {tier.description}
                      </span>
                      <br />
                      <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                        Examples: {tier.examples}
                      </span>
                    </div>
                  }
                  value={tier.value.toString()}
                />
              ))}
            </RadioButtonGroup>
          </div>
        )}

        {/* Step 4: Data Sensitivity */}
        {currentStep === 3 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Data Sensitivity</h3>
            <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem' }}>
              Select all types of sensitive data this application processes or stores.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <Checkbox
                id="pii"
                labelText="PII - Personally Identifiable Information (names, emails, addresses)"
                checked={formData.pii}
                onChange={(_, { checked }) => updateFormData('pii', checked)}
              />
              <Checkbox
                id="phi"
                labelText="PHI - Protected Health Information (medical records, health data)"
                checked={formData.phi}
                onChange={(_, { checked }) => updateFormData('phi', checked)}
              />
              <Checkbox
                id="pci"
                labelText="PCI - Payment Card Information (credit cards, bank accounts)"
                checked={formData.pci}
                onChange={(_, { checked }) => updateFormData('pci', checked)}
              />
              <Checkbox
                id="trade-secrets"
                labelText="Trade Secrets / Proprietary Information"
                checked={formData.tradeSecrets}
                onChange={(_, { checked }) => updateFormData('tradeSecrets', checked)}
              />
            </div>
          </div>
        )}

        {/* Step 5: Access & Controls */}
        {currentStep === 4 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Access & Security Controls</h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <NumberInput
                id="public-endpoints"
                label="Public API Endpoints"
                min={0}
                value={formData.publicEndpoints}
                onChange={(_, { value }) => updateFormData('publicEndpoints', value || 0)}
              />
              <NumberInput
                id="private-endpoints"
                label="Private API Endpoints"
                min={0}
                value={formData.privateEndpoints}
                onChange={(_, { value }) => updateFormData('privateEndpoints', value || 0)}
              />
            </div>

            <div className="form-group">
              <RadioButtonGroup
                legendText="Network Exposure"
                name="network-exposure"
                valueSelected={formData.networkExposure}
                onChange={(value) => updateFormData('networkExposure', value)}
              >
                <RadioButton labelText="Internal Only" value="internal" />
                <RadioButton labelText="DMZ / Limited External" value="dmz" />
                <RadioButton labelText="Public Internet" value="public" />
              </RadioButtonGroup>
            </div>

            <div className="form-group">
              <p style={{ marginBottom: '0.75rem' }}>Security Controls in Place</p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                {SECURITY_CONTROLS.map((control) => (
                  <Checkbox
                    key={control.id}
                    id={control.id}
                    labelText={control.label}
                    checked={formData.controls.includes(control.id)}
                    onChange={(_, { checked }) => {
                      const newControls = checked
                        ? [...formData.controls, control.id]
                        : formData.controls.filter((c) => c !== control.id);
                      updateFormData('controls', newControls);
                    }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Step 6: Formula */}
        {currentStep === 5 && (
          <div>
            <h3 style={{ marginBottom: '1.5rem' }}>Risk Scoring Formula</h3>
            <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem' }}>
              Choose the risk scoring methodology to use for prioritizing vulnerabilities.
            </p>

            <RadioButtonGroup
              legendText="Formula"
              name="formula"
              orientation="vertical"
              valueSelected={formData.formula}
              onChange={(value) => updateFormData('formula', value)}
            >
              <RadioButton
                labelText={
                  <div>
                    <strong>Concert Formula</strong>
                    <br />
                    <span style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                      Risk = CVSS x Exploitability(EPSS) x Environmental(Context)
                    </span>
                    <br />
                    <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                      Scale: 0-10 | Best for: Quick prioritization
                    </span>
                  </div>
                }
                value="concert"
              />
              <RadioButton
                labelText={
                  <div>
                    <strong>Comprehensive Formula</strong>
                    <br />
                    <span style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                      Risk = Likelihood x Impact x Exposure x (1-Controls) x 1000
                    </span>
                    <br />
                    <span style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>
                      Scale: 0-1000 | Best for: Detailed analysis
                    </span>
                  </div>
                }
                value="comprehensive"
              />
            </RadioButtonGroup>
          </div>
        )}

        {/* Navigation */}
        <div className="wizard-actions">
          <Button
            kind="secondary"
            renderIcon={ArrowLeft}
            onClick={handleBack}
            disabled={currentStep === 0}
          >
            Back
          </Button>

          {currentStep < STEPS.length - 1 ? (
            <Button
              kind="primary"
              renderIcon={ArrowRight}
              onClick={handleNext}
              disabled={!isStepValid()}
            >
              Next
            </Button>
          ) : (
            <Button
              kind="primary"
              onClick={handleStartScan}
              disabled={!isStepValid()}
            >
              Start Scan
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function getProgressIndex(status: string): number {
  switch (status) {
    case 'cloning':
      return 0;
    case 'detecting':
      return 1;
    case 'scanning':
      return 2;
    case 'enriching':
      return 3;
    case 'complete':
      return 4;
    default:
      return 0;
  }
}

export default ScanSetup;
