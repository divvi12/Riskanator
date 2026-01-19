import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Tile,
  TextInput,
  Toggle,
  Select,
  SelectItem,
  NumberInput,
  Checkbox,
  ProgressIndicator,
  ProgressStep,
  InlineNotification
} from '@carbon/react';
import {
  Play,
  Demo,
  Scan,
  Security,
  ArrowRight,
  ArrowLeft,
  Certificate,
  Password,
  SettingsCheck,
  Document,
  Code,
  Checkmark
} from '@carbon/icons-react';
import { useAppContext } from '../App';
import { ScanRequest, INDUSTRIES, SECURITY_CONTROLS, CRITICALITY_TIERS } from '../types';
import { API_ENDPOINTS } from '../config';

function Landing() {
  const navigate = useNavigate();
  const { setIsDemoMode, isDemoMode } = useAppContext();
  const [showScanWizard, setShowScanWizard] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Scan form state
  const [scanForm, setScanForm] = useState<ScanRequest>({
    repoUrl: '',
    isPrivate: false,
    pat: '',
    branch: 'main',
    context: {
      appName: '',
      industry: 'technology',
      purpose: '',
      criticality: 3,
      dataSensitivity: {
        pii: false,
        phi: false,
        pci: false,
        tradeSecrets: false
      },
      accessControls: {
        publicEndpoints: 0,
        privateEndpoints: 0,
        networkExposure: 'internal',
        controls: []
      },
      formula: 'concert'
    }
  });

  const handleDemoMode = () => {
    setIsDemoMode(true);
    navigate('/app/dashboard');
  };

  const handleStartScan = async () => {
    setIsScanning(true);
    setScanError(null);

    try {
      // Call the exposure scan API
      const response = await fetch(API_ENDPOINTS.exposureScan, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanForm)
      });

      if (!response.ok) {
        throw new Error('Failed to start scan');
      }

      const data = await response.json();
      setIsDemoMode(false);

      // Navigate to dashboard with scan ID
      navigate('/app/dashboard', { state: { scanId: data.scanId } });
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Failed to start scan');
      setIsScanning(false);
    }
  };

  const wizardSteps = [
    { label: 'Repository', description: 'Enter repository details' },
    { label: 'Application', description: 'Application context' },
    { label: 'Data Sensitivity', description: 'Data classification' },
    { label: 'Access Controls', description: 'Security controls' },
    { label: 'Scan Options', description: 'Configure scan' },
    { label: 'Review', description: 'Confirm and start' }
  ];

  const canProceed = () => {
    switch (currentStep) {
      case 0:
        return scanForm.repoUrl.length > 0;
      case 1:
        return scanForm.context?.appName && scanForm.context?.appName.length > 0;
      default:
        return true;
    }
  };

  if (showScanWizard) {
    return (
      <div style={{ maxWidth: '800px', margin: '0 auto', padding: '2rem' }}>
        <Button
          kind="ghost"
          size="sm"
          onClick={() => setShowScanWizard(false)}
          style={{ marginBottom: '1rem' }}
        >
          <ArrowLeft size={16} style={{ marginRight: '0.5rem' }} />
          Back to Home
        </Button>

        <h1 style={{ fontSize: '2rem', fontWeight: 300, marginBottom: '0.5rem' }}>
          New Exposure Scan
        </h1>
        <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '2rem' }}>
          Scan your repository for all 6 exposure types
        </p>

        {/* Progress Indicator */}
        <ProgressIndicator currentIndex={currentStep} style={{ marginBottom: '2rem' }}>
          {wizardSteps.map((step, i) => (
            <ProgressStep
              key={i}
              label={step.label}
              description={step.description}
              secondaryLabel={i < currentStep ? 'Complete' : ''}
            />
          ))}
        </ProgressIndicator>

        {scanError && (
          <InlineNotification
            kind="error"
            title="Scan Error"
            subtitle={scanError}
            onCloseButtonClick={() => setScanError(null)}
            style={{ marginBottom: '1rem' }}
          />
        )}

        {/* Step Content */}
        <Tile style={{ padding: '2rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
          {currentStep === 0 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Repository Details</h3>
              <TextInput
                id="repoUrl"
                labelText="Repository URL"
                placeholder="https://github.com/owner/repo"
                value={scanForm.repoUrl}
                onChange={(e) => setScanForm({ ...scanForm, repoUrl: e.target.value })}
                style={{ marginBottom: '1rem' }}
              />
              <TextInput
                id="branch"
                labelText="Branch"
                placeholder="main"
                value={scanForm.branch}
                onChange={(e) => setScanForm({ ...scanForm, branch: e.target.value })}
                style={{ marginBottom: '1rem' }}
              />
              <Toggle
                id="isPrivate"
                labelText="Private Repository"
                labelA="Public"
                labelB="Private"
                toggled={scanForm.isPrivate}
                onToggle={(toggled) => setScanForm({ ...scanForm, isPrivate: toggled })}
                style={{ marginBottom: '1rem' }}
              />
              {scanForm.isPrivate && (
                <TextInput
                  id="pat"
                  labelText="Personal Access Token"
                  placeholder="ghp_xxxxxxxxxxxx"
                  type="password"
                  value={scanForm.pat || ''}
                  onChange={(e) => setScanForm({ ...scanForm, pat: e.target.value })}
                />
              )}
            </div>
          )}

          {currentStep === 1 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Application Context</h3>
              <TextInput
                id="appName"
                labelText="Application Name"
                placeholder="My Application"
                value={scanForm.context?.appName || ''}
                onChange={(e) => setScanForm({
                  ...scanForm,
                  context: { ...scanForm.context!, appName: e.target.value }
                })}
                style={{ marginBottom: '1rem' }}
              />
              <Select
                id="industry"
                labelText="Industry"
                value={scanForm.context?.industry || 'technology'}
                onChange={(e) => setScanForm({
                  ...scanForm,
                  context: { ...scanForm.context!, industry: e.target.value }
                })}
                style={{ marginBottom: '1rem' }}
              >
                {INDUSTRIES.map((ind) => (
                  <SelectItem key={ind.value} value={ind.value} text={ind.label} />
                ))}
              </Select>
              <TextInput
                id="purpose"
                labelText="Application Purpose"
                placeholder="Describe what this application does..."
                value={scanForm.context?.purpose || ''}
                onChange={(e) => setScanForm({
                  ...scanForm,
                  context: { ...scanForm.context!, purpose: e.target.value }
                })}
              />
            </div>
          )}

          {currentStep === 2 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Data Sensitivity</h3>
              <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem' }}>
                Select the types of sensitive data this application handles:
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <Checkbox
                  id="pii"
                  labelText="PII (Personally Identifiable Information)"
                  checked={scanForm.context?.dataSensitivity.pii}
                  onChange={(_, { checked }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      dataSensitivity: { ...scanForm.context!.dataSensitivity, pii: checked }
                    }
                  })}
                />
                <Checkbox
                  id="phi"
                  labelText="PHI (Protected Health Information)"
                  checked={scanForm.context?.dataSensitivity.phi}
                  onChange={(_, { checked }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      dataSensitivity: { ...scanForm.context!.dataSensitivity, phi: checked }
                    }
                  })}
                />
                <Checkbox
                  id="pci"
                  labelText="PCI (Payment Card Industry data)"
                  checked={scanForm.context?.dataSensitivity.pci}
                  onChange={(_, { checked }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      dataSensitivity: { ...scanForm.context!.dataSensitivity, pci: checked }
                    }
                  })}
                />
                <Checkbox
                  id="tradeSecrets"
                  labelText="Trade Secrets / Proprietary Information"
                  checked={scanForm.context?.dataSensitivity.tradeSecrets}
                  onChange={(_, { checked }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      dataSensitivity: { ...scanForm.context!.dataSensitivity, tradeSecrets: checked }
                    }
                  })}
                />
              </div>
            </div>
          )}

          {currentStep === 3 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Access Controls & Network Exposure</h3>
              <Select
                id="networkExposure"
                labelText="Network Exposure"
                value={scanForm.context?.accessControls.networkExposure || 'internal'}
                onChange={(e) => setScanForm({
                  ...scanForm,
                  context: {
                    ...scanForm.context!,
                    accessControls: { ...scanForm.context!.accessControls, networkExposure: e.target.value as any }
                  }
                })}
                style={{ marginBottom: '1rem' }}
              >
                <SelectItem value="internal" text="Internal Only" />
                <SelectItem value="dmz" text="DMZ / Semi-Public" />
                <SelectItem value="public" text="Public Internet" />
              </Select>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <NumberInput
                  id="publicEndpoints"
                  label="Public Endpoints"
                  value={scanForm.context?.accessControls.publicEndpoints || 0}
                  min={0}
                  onChange={(_, { value }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      accessControls: { ...scanForm.context!.accessControls, publicEndpoints: Number(value) || 0 }
                    }
                  })}
                />
                <NumberInput
                  id="privateEndpoints"
                  label="Private Endpoints"
                  value={scanForm.context?.accessControls.privateEndpoints || 0}
                  min={0}
                  onChange={(_, { value }) => setScanForm({
                    ...scanForm,
                    context: {
                      ...scanForm.context!,
                      accessControls: { ...scanForm.context!.accessControls, privateEndpoints: Number(value) || 0 }
                    }
                  })}
                />
              </div>

              <p style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>Security Controls in Place:</p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                {SECURITY_CONTROLS.map((control) => (
                  <Checkbox
                    key={control.id}
                    id={control.id}
                    labelText={control.label}
                    checked={scanForm.context?.accessControls.controls.includes(control.id)}
                    onChange={(_, { checked }) => {
                      const controls = scanForm.context?.accessControls.controls || [];
                      const newControls = checked
                        ? [...controls, control.id]
                        : controls.filter(c => c !== control.id);
                      setScanForm({
                        ...scanForm,
                        context: {
                          ...scanForm.context!,
                          accessControls: { ...scanForm.context!.accessControls, controls: newControls }
                        }
                      });
                    }}
                  />
                ))}
              </div>
            </div>
          )}

          {currentStep === 4 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Criticality & Scan Options</h3>
              <p style={{ fontSize: '0.875rem', marginBottom: '1rem' }}>Application Criticality Tier:</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
                {CRITICALITY_TIERS.map((tier) => (
                  <div
                    key={tier.value}
                    onClick={() => setScanForm({
                      ...scanForm,
                      context: { ...scanForm.context!, criticality: tier.value }
                    })}
                    style={{
                      padding: '1rem',
                      backgroundColor: scanForm.context?.criticality === tier.value ? '#0f62fe20' : '#262626',
                      border: scanForm.context?.criticality === tier.value ? '1px solid #0f62fe' : '1px solid #393939',
                      borderRadius: 4,
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <div style={{ fontWeight: 600 }}>{tier.label}</div>
                        <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                          {tier.description}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', marginTop: '0.25rem' }}>
                          Examples: {tier.examples}
                        </div>
                      </div>
                      {scanForm.context?.criticality === tier.value && (
                        <Checkmark size={20} style={{ color: '#0f62fe' }} />
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <Select
                id="formula"
                labelText="Risk Scoring Formula"
                value={scanForm.context?.formula || 'concert'}
                onChange={(e) => setScanForm({
                  ...scanForm,
                  context: { ...scanForm.context!, formula: e.target.value as 'concert' | 'comprehensive' }
                })}
              >
                <SelectItem value="concert" text="Concert (0-10 scale)" />
                <SelectItem value="comprehensive" text="Comprehensive (0-1000 scale)" />
              </Select>
            </div>
          )}

          {currentStep === 5 && (
            <div>
              <h3 style={{ marginBottom: '1.5rem' }}>Review & Start Scan</h3>
              <div style={{ display: 'grid', gap: '1rem' }}>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Repository</div>
                  <div>{scanForm.repoUrl}</div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                    Branch: {scanForm.branch} | {scanForm.isPrivate ? 'Private' : 'Public'}
                  </div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Application</div>
                  <div>{scanForm.context?.appName}</div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                    {INDUSTRIES.find(i => i.value === scanForm.context?.industry)?.label} |
                    Tier {scanForm.context?.criticality}
                  </div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Data Sensitivity</div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                    {scanForm.context?.dataSensitivity.pii && <span style={{ padding: '0.25rem 0.5rem', backgroundColor: '#393939', borderRadius: 4, fontSize: '0.8125rem' }}>PII</span>}
                    {scanForm.context?.dataSensitivity.phi && <span style={{ padding: '0.25rem 0.5rem', backgroundColor: '#393939', borderRadius: 4, fontSize: '0.8125rem' }}>PHI</span>}
                    {scanForm.context?.dataSensitivity.pci && <span style={{ padding: '0.25rem 0.5rem', backgroundColor: '#393939', borderRadius: 4, fontSize: '0.8125rem' }}>PCI</span>}
                    {scanForm.context?.dataSensitivity.tradeSecrets && <span style={{ padding: '0.25rem 0.5rem', backgroundColor: '#393939', borderRadius: 4, fontSize: '0.8125rem' }}>Trade Secrets</span>}
                    {!scanForm.context?.dataSensitivity.pii && !scanForm.context?.dataSensitivity.phi && !scanForm.context?.dataSensitivity.pci && !scanForm.context?.dataSensitivity.tradeSecrets && (
                      <span style={{ color: 'var(--cve-text-secondary)' }}>None selected</span>
                    )}
                  </div>
                </div>
                <div style={{ padding: '1rem', backgroundColor: '#262626', borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)' }}>Scan Types</div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#FA4D5620', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <Security size={14} /> CVEs
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#8A3FFC20', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <Certificate size={14} /> Certificates
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#FF832B20', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <Password size={14} /> Secrets
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#1192E820', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <SettingsCheck size={14} /> Misconfigs
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#009D9A20', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <Document size={14} /> Licenses
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem', backgroundColor: '#6929C420', borderRadius: 4, fontSize: '0.8125rem' }}>
                      <Code size={14} /> Code Security
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </Tile>

        {/* Navigation Buttons */}
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <Button
            kind="secondary"
            onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
            disabled={currentStep === 0}
          >
            <ArrowLeft size={16} style={{ marginRight: '0.5rem' }} />
            Previous
          </Button>
          {currentStep < wizardSteps.length - 1 ? (
            <Button
              kind="primary"
              onClick={() => setCurrentStep(currentStep + 1)}
              disabled={!canProceed()}
            >
              Next
              <ArrowRight size={16} style={{ marginLeft: '0.5rem' }} />
            </Button>
          ) : (
            <Button
              kind="primary"
              onClick={handleStartScan}
              disabled={isScanning}
            >
              {isScanning ? 'Starting Scan...' : 'Start Exposure Scan'}
              <Scan size={16} style={{ marginLeft: '0.5rem' }} />
            </Button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem',
      background: 'linear-gradient(180deg, #161616 0%, #262626 100%)'
    }}>
      {/* Logo / Title */}
      <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
        <div style={{
          width: 80,
          height: 80,
          borderRadius: 16,
          backgroundColor: '#0f62fe',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto 1.5rem'
        }}>
          <Security size={40} />
        </div>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 300, marginBottom: '0.5rem' }}>
          Concert
        </h1>
        <p style={{ fontSize: '1.125rem', color: 'var(--cve-text-secondary)' }}>
          Threat Exposure Management
        </p>
        <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginTop: '0.5rem' }}>
          Scan for CVEs, Secrets, Certificates, Misconfigurations, Licenses & Code Security
        </p>
      </div>

      {/* Action Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', maxWidth: '800px', width: '100%' }}>
        {/* Demo Mode Tile */}
        <Tile
          style={{
            padding: '2rem',
            backgroundColor: '#161616',
            border: isDemoMode ? '2px solid #0f62fe' : '1px solid #393939',
            cursor: 'pointer',
            transition: 'all 0.2s ease'
          }}
          onClick={handleDemoMode}
        >
          <div style={{
            width: 56,
            height: 56,
            borderRadius: 12,
            backgroundColor: '#8A3FFC20',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1.5rem'
          }}>
            <Demo size={28} style={{ color: '#8A3FFC' }} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 400, marginBottom: '0.75rem' }}>
            Demo Mode
          </h2>
          <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            Explore the platform with sample data from a fictional financial services application.
            See all 6 exposure types, risk scores, and remediation recommendations.
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', backgroundColor: '#FA4D5620', borderRadius: 4, color: '#FA4D56' }}>167 CVEs</span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', backgroundColor: '#FF832B20', borderRadius: 4, color: '#FF832B' }}>5 Secrets</span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', backgroundColor: '#8A3FFC20', borderRadius: 4, color: '#8A3FFC' }}>4 Certs</span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', backgroundColor: '#1192E820', borderRadius: 4, color: '#1192E8' }}>6 Misconfigs</span>
          </div>
          <Button kind="tertiary" style={{ width: '100%' }}>
            Enter Demo Mode
            <ArrowRight size={16} style={{ marginLeft: '0.5rem' }} />
          </Button>
        </Tile>

        {/* Scan Repository Tile */}
        <Tile
          style={{
            padding: '2rem',
            backgroundColor: '#161616',
            border: '1px solid #393939',
            cursor: 'pointer',
            transition: 'all 0.2s ease'
          }}
          onClick={() => setShowScanWizard(true)}
        >
          <div style={{
            width: 56,
            height: 56,
            borderRadius: 12,
            backgroundColor: '#0f62fe20',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1.5rem'
          }}>
            <Scan size={28} style={{ color: '#0f62fe' }} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 400, marginBottom: '0.75rem' }}>
            Scan Repository
          </h2>
          <p style={{ color: 'var(--cve-text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            Connect your GitHub repository and run a comprehensive exposure scan.
            Provide application context for accurate risk scoring.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
              <Checkmark size={16} style={{ color: '#42BE65' }} />
              CVE scanning with NVD/EPSS/KEV enrichment
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
              <Checkmark size={16} style={{ color: '#42BE65' }} />
              Secret detection with TruffleHog
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
              <Checkmark size={16} style={{ color: '#42BE65' }} />
              Infrastructure misconfiguration scanning
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
              <Checkmark size={16} style={{ color: '#42BE65' }} />
              License compliance analysis
            </div>
          </div>
          <Button kind="primary" style={{ width: '100%' }}>
            Start New Scan
            <Play size={16} style={{ marginLeft: '0.5rem' }} />
          </Button>
        </Tile>
      </div>

      {/* Footer info */}
      <div style={{ marginTop: '3rem', textAlign: 'center', color: 'var(--cve-text-secondary)' }}>
        <p style={{ fontSize: '0.8125rem' }}>
          Powered by IBM Concert-style risk scoring with dual formula support
        </p>
      </div>
    </div>
  );
}

export default Landing;
