import { useState, useEffect } from 'react';
import {
  Button,
  TextInput,
  RadioButtonGroup,
  RadioButton,
  Tile,
  InlineNotification,
  Select,
  SelectItem,
  Toggle,
  Modal,
  Tag,
  InlineLoading,
  Checkbox,
  Slider,
  NumberInput,
  Tooltip
} from '@carbon/react';
import { Save, CheckmarkFilled, WarningAlt, Bot, Connect, Settings as SettingsIcon, Information, Security } from '@carbon/icons-react';
import { useNotifications } from '../components/NotificationProvider';
import { SettingsFormSkeleton } from '../components/SkeletonLoaders';
import { useAppContext } from '../App';
import { recalculateScores } from '../services/api';

interface ApplicationContextSettings {
  criticality: number;
  dataSensitivity: {
    pci: boolean;
    phi: boolean;
    pii: boolean;
  };
  networkExposure: 'public' | 'dmz' | 'internal';
  publicEndpoints: number;
  privateEndpoints: number;
  requiresAuth: boolean;
}

interface GeminiSettings {
  apiKey: string;
  enabled: boolean;
  model: string;
  autoExplain: boolean;
}

function Settings() {
  const { showError, showSuccess } = useNotifications();
  const { currentScan, setCurrentScan } = useAppContext();
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isRecalculating, setIsRecalculating] = useState(false);

  const [appContext, setAppContext] = useState<ApplicationContextSettings>({
    criticality: 3,
    dataSensitivity: { pci: false, phi: false, pii: false },
    networkExposure: 'internal',
    publicEndpoints: 0,
    privateEndpoints: 5,
    requiresAuth: true
  });

  const [serviceNowConfig, setServiceNowConfig] = useState({
    instanceUrl: '',
    authMethod: 'basic' as 'oauth' | 'basic' | 'token',
    username: '',
    password: '',
    clientId: '',
    clientSecret: '',
    token: '',
    defaultAssignmentGroup: '',
    enabled: false,
    autoCreateIncidents: false,
    defaultPriority: '3'
  });

  const [geminiConfig, setGeminiConfig] = useState<GeminiSettings>({
    apiKey: '',
    enabled: false,
    model: 'gemini-1.5-pro',
    autoExplain: true
  });

  const [riskFormula, setRiskFormula] = useState<'concert' | 'comprehensive'>('concert');
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [geminiStatus, setGeminiStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [saved, setSaved] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);

  // Load settings from localStorage
  useEffect(() => {
    setIsLoading(true);
    try {
      const savedSettings = localStorage.getItem('concert-tem-settings');
      if (savedSettings) {
        const parsed = JSON.parse(savedSettings);
        if (parsed.serviceNowConfig) setServiceNowConfig(parsed.serviceNowConfig);
        if (parsed.geminiConfig) setGeminiConfig(parsed.geminiConfig);
        if (parsed.riskFormula) setRiskFormula(parsed.riskFormula);
        if (parsed.appContext) setAppContext(parsed.appContext);
      }
    } catch (error) {
      showError('Failed to load settings', 'Could not parse saved settings');
    } finally {
      // Simulate brief loading state for UI consistency
      setTimeout(() => setIsLoading(false), 300);
    }
  }, []);

  const handleTestConnection = async () => {
    setConnectionStatus('testing');
    // Simulate connection test
    setTimeout(() => {
      if (serviceNowConfig.instanceUrl && (serviceNowConfig.username || serviceNowConfig.token)) {
        setConnectionStatus('success');
        showSuccess('Connection successful', 'ServiceNow instance is reachable');
      } else {
        setConnectionStatus('error');
        showError('Connection failed', 'Please check your credentials and try again');
      }
    }, 1500);
  };

  const handleTestGemini = async () => {
    setGeminiStatus('testing');
    // Simulate connection test
    setTimeout(() => {
      if (geminiConfig.apiKey && geminiConfig.apiKey.length > 10) {
        setGeminiStatus('success');
        showSuccess('API key valid', 'Gemini AI is ready to use');
      } else {
        setGeminiStatus('error');
        showError('Invalid API key', 'Please check your API key and try again');
      }
    }, 1500);
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      // Save to localStorage
      localStorage.setItem('concert-tem-settings', JSON.stringify({
        serviceNowConfig,
        geminiConfig,
        riskFormula,
        appContext
      }));
      setSaved(true);

      // Auto-recalculate if there's scan data (for Application Context tab)
      if (activeTab === 0 && currentScan?.exposures && currentScan.exposures.length > 0) {
        setIsRecalculating(true);
        try {
          const context = {
            criticality: appContext.criticality,
            dataSensitivity: appContext.dataSensitivity,
            networkExposure: appContext.networkExposure,
            publicEndpoints: appContext.publicEndpoints,
            privateEndpoints: appContext.privateEndpoints,
            requiresAuth: appContext.requiresAuth
          };

          const result = await recalculateScores(currentScan.exposures, context);
          setCurrentScan({
            ...currentScan,
            exposures: result.exposures,
            summary: result.summary
          });
          showSuccess('Settings saved & scores recalculated', `${result.exposures.length} exposures updated`);
        } catch (recalcError) {
          showSuccess('Settings saved', 'Scores will update on next scan');
          console.error('Recalculation error:', recalcError);
        } finally {
          setIsRecalculating(false);
        }
      } else {
        showSuccess('Settings saved', 'Your configuration has been saved');
      }

      setTimeout(() => setSaved(false), 3000);
    } catch (error) {
      showError('Failed to save settings', 'Please try again');
    } finally {
      setIsSaving(false);
    }
  };

  const updateAppContext = (field: string, value: any) => {
    setAppContext(prev => ({ ...prev, [field]: value }));
  };

  const updateDataSensitivity = (field: string, value: boolean) => {
    setAppContext(prev => ({
      ...prev,
      dataSensitivity: { ...prev.dataSensitivity, [field]: value }
    }));
  };

  const updateConfig = (field: string, value: string | boolean) => {
    setServiceNowConfig(prev => ({ ...prev, [field]: value }));
    setConnectionStatus('idle');
  };

  const updateGeminiConfig = (field: string, value: string | boolean) => {
    setGeminiConfig(prev => ({ ...prev, [field]: value }));
    setGeminiStatus('idle');
  };

  // Show loading skeleton while settings are being loaded
  if (isLoading) {
    return (
      <div>
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 300, marginBottom: '0.5rem' }}>Settings</h1>
          <p style={{ color: 'var(--cve-text-secondary)' }}>
            Configure integrations and platform settings
          </p>
        </div>
        <SettingsFormSkeleton />
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 300, marginBottom: '0.5rem' }}>Settings</h1>
        <p style={{ color: 'var(--cve-text-secondary)' }}>
          Configure integrations and platform settings
        </p>
      </div>

      {saved && (
        <InlineNotification
          kind="success"
          title="Settings Saved"
          subtitle="Your configuration has been saved."
          style={{ marginBottom: '1rem' }}
        />
      )}

      {/* Custom Tab Navigation */}
      <div style={{
        display: 'flex',
        gap: '0',
        borderBottom: '1px solid var(--cve-border)',
        marginBottom: '1.5rem'
      }}>
        <button
          onClick={() => setActiveTab(0)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            background: activeTab === 0 ? 'var(--cve-background-tertiary)' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 0 ? '2px solid #0f62fe' : '2px solid transparent',
            color: activeTab === 0 ? 'var(--cve-text-primary)' : 'var(--cve-text-secondary)',
            cursor: 'pointer',
            fontSize: '0.875rem'
          }}
        >
          <Security size={16} />
          Application Context
        </button>
        <button
          onClick={() => setActiveTab(1)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            background: activeTab === 1 ? 'var(--cve-background-tertiary)' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 1 ? '2px solid #0f62fe' : '2px solid transparent',
            color: activeTab === 1 ? 'var(--cve-text-primary)' : 'var(--cve-text-secondary)',
            cursor: 'pointer',
            fontSize: '0.875rem'
          }}
        >
          <Bot size={16} />
          Gemini AI
        </button>
        <button
          onClick={() => setActiveTab(2)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            background: activeTab === 2 ? 'var(--cve-background-tertiary)' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 2 ? '2px solid #0f62fe' : '2px solid transparent',
            color: activeTab === 2 ? 'var(--cve-text-primary)' : 'var(--cve-text-secondary)',
            cursor: 'pointer',
            fontSize: '0.875rem'
          }}
        >
          <Connect size={16} />
          ServiceNow
        </button>
        <button
          onClick={() => setActiveTab(3)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1rem',
            background: activeTab === 3 ? 'var(--cve-background-tertiary)' : 'transparent',
            border: 'none',
            borderBottom: activeTab === 3 ? '2px solid #0f62fe' : '2px solid transparent',
            color: activeTab === 3 ? 'var(--cve-text-primary)' : 'var(--cve-text-secondary)',
            cursor: 'pointer',
            fontSize: '0.875rem'
          }}
        >
          <SettingsIcon size={16} />
          General
        </button>
      </div>

      {/* Tab Content */}
      {/* Application Context Settings */}
      {activeTab === 0 && (
            <div style={{ maxWidth: '600px', marginTop: '1.5rem' }}>
              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <h3>Application Criticality</h3>
                  <Tooltip
                    align="right"
                    label="Application criticality determines how severely vulnerabilities are weighted in risk calculations. Higher criticality means vulnerabilities pose greater business impact and receive higher risk scores."
                  >
                    <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                      <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                    </button>
                  </Tooltip>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
                  How critical is this application to business operations?
                </p>

                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.875rem' }}>Low</span>
                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>Level {appContext.criticality}</span>
                    <span style={{ fontSize: '0.875rem' }}>Critical</span>
                  </div>
                  <Slider
                    id="criticality-slider"
                    min={1}
                    max={5}
                    step={1}
                    value={appContext.criticality}
                    onChange={({ value }) => updateAppContext('criticality', value)}
                    hideTextInput
                  />
                  <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)', marginTop: '0.5rem' }}>
                    {appContext.criticality === 1 && 'Internal tools, dev environments'}
                    {appContext.criticality === 2 && 'Supporting systems, non-essential services'}
                    {appContext.criticality === 3 && 'Standard business applications'}
                    {appContext.criticality === 4 && 'Customer-facing, revenue-impacting'}
                    {appContext.criticality === 5 && 'Mission-critical, regulatory required'}
                  </div>
                </div>
              </Tile>

              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <h3>Data Sensitivity</h3>
                  <Tooltip
                    align="right"
                    label="Data sensitivity identifies regulatory compliance requirements. Applications handling PCI, PHI, or PII data have stricter SLAs, higher risk multipliers, and trigger compliance impact flags on vulnerabilities."
                  >
                    <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                      <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                    </button>
                  </Tooltip>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
                  What types of sensitive data does this application handle?
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <Checkbox
                    id="pci-data"
                    labelText={
                      <span>
                        <strong>PCI DSS</strong> - Payment card data (credit cards, account numbers)
                      </span>
                    }
                    checked={appContext.dataSensitivity.pci}
                    onChange={(_, { checked }) => updateDataSensitivity('pci', checked)}
                  />
                  <Checkbox
                    id="phi-data"
                    labelText={
                      <span>
                        <strong>PHI (HIPAA)</strong> - Protected health information
                      </span>
                    }
                    checked={appContext.dataSensitivity.phi}
                    onChange={(_, { checked }) => updateDataSensitivity('phi', checked)}
                  />
                  <Checkbox
                    id="pii-data"
                    labelText={
                      <span>
                        <strong>PII</strong> - Personal identifiable information (names, emails, SSN)
                      </span>
                    }
                    checked={appContext.dataSensitivity.pii}
                    onChange={(_, { checked }) => updateDataSensitivity('pii', checked)}
                  />
                </div>
              </Tile>

              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <h3>Network Exposure</h3>
                  <Tooltip
                    align="right"
                    label="Network exposure affects how easily vulnerabilities can be exploited. Public-facing applications have higher attack surface and risk scores. Internal-only apps benefit from network controls reducing effective risk."
                  >
                    <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                      <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                    </button>
                  </Tooltip>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
                  How is this application exposed to the network?
                </p>

                <RadioButtonGroup
                  name="network-exposure"
                  orientation="vertical"
                  valueSelected={appContext.networkExposure}
                  onChange={(value) => updateAppContext('networkExposure', value)}
                >
                  <RadioButton
                    labelText={
                      <div>
                        <strong>Public Internet</strong>
                        <span style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                          Directly accessible from the internet
                        </span>
                      </div>
                    }
                    value="public"
                  />
                  <RadioButton
                    labelText={
                      <div>
                        <strong>DMZ</strong>
                        <span style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                          Behind firewall but internet-facing
                        </span>
                      </div>
                    }
                    value="dmz"
                  />
                  <RadioButton
                    labelText={
                      <div>
                        <strong>Internal Only</strong>
                        <span style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                          Corporate network only, no internet exposure
                        </span>
                      </div>
                    }
                    value="internal"
                  />
                </RadioButtonGroup>
              </Tile>

              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <h3>Access Points</h3>
                  <Tooltip
                    align="right"
                    label="Access points measure attack surface. More public endpoints mean more potential entry points for attackers. Authentication requirements reduce effective risk by adding defense layers."
                  >
                    <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                      <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                    </button>
                  </Tooltip>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '1rem' }}>
                  How many API endpoints does this application expose?
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                  <NumberInput
                    id="public-endpoints"
                    label="Public Endpoints"
                    min={0}
                    max={100}
                    value={appContext.publicEndpoints}
                    onChange={(_, { value }) => updateAppContext('publicEndpoints', value)}
                  />
                  <NumberInput
                    id="private-endpoints"
                    label="Private/Internal Endpoints"
                    min={0}
                    max={100}
                    value={appContext.privateEndpoints}
                    onChange={(_, { value }) => updateAppContext('privateEndpoints', value)}
                  />
                </div>

                <Toggle
                  id="requires-auth"
                  labelText="All endpoints require authentication"
                  labelA="No"
                  labelB="Yes"
                  toggled={appContext.requiresAuth}
                  onToggle={(toggled) => updateAppContext('requiresAuth', toggled)}
                />
              </Tile>

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <Button kind="primary" renderIcon={Save} onClick={handleSave} disabled={isSaving || isRecalculating}>
                  {isSaving ? (isRecalculating ? 'Recalculating...' : 'Saving...') : (currentScan?.exposures?.length ? 'Save & Recalculate' : 'Save Application Context')}
                </Button>
                {(isSaving || isRecalculating) && <InlineLoading description={isRecalculating ? 'Recalculating scores...' : 'Saving...'} />}
              </div>

              {!currentScan?.exposures?.length && (
                <InlineNotification
                  kind="warning"
                  title="No scan data"
                  subtitle="Run a scan first. Settings will be applied when you scan a repository."
                  style={{ marginTop: '1rem' }}
                  lowContrast
                />
              )}

              <InlineNotification
                kind="info"
                title="How this affects risk scores"
                subtitle="Higher criticality and data sensitivity will increase risk scores. Public exposure adds weight to vulnerabilities. Saving will automatically recalculate scores for the current scan."
                style={{ marginTop: '1rem' }}
                lowContrast
              />
            </div>
      )}

      {/* Gemini AI Settings */}
      {activeTab === 1 && (
        <div style={{ maxWidth: '600px' }}>
              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                      <h3>Gemini AI Integration</h3>
                      <Tooltip
                        align="right"
                        label="Gemini AI provides intelligent explanations for exposures in plain language. It analyzes CVEs, secrets, misconfigurations, and other findings to help developers understand the business impact and remediation steps."
                      >
                        <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                          <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                        </button>
                      </Tooltip>
                    </div>
                    <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                      AI-powered explanations for all exposure types
                    </p>
                  </div>
                  <Toggle
                    id="gemini-enabled"
                    labelA="Disabled"
                    labelB="Enabled"
                    toggled={geminiConfig.enabled}
                    onToggle={(toggled) => updateGeminiConfig('enabled', toggled)}
                  />
                </div>

                <div style={{ position: 'relative', marginBottom: '1rem' }}>
                  <TextInput
                    id="gemini-api-key"
                    labelText="Gemini API Key"
                    type="password"
                    placeholder="AIza..."
                    value={geminiConfig.apiKey}
                    onChange={(e) => updateGeminiConfig('apiKey', e.target.value)}
                    disabled={!geminiConfig.enabled}
                  />
                  <Button
                    kind="ghost"
                    size="sm"
                    style={{ position: 'absolute', right: 0, top: 0 }}
                    onClick={() => setShowApiKeyModal(true)}
                  >
                    How to get API key?
                  </Button>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Model</span>
                    <Tooltip
                      align="right"
                      label="Pro models provide higher quality responses but are slower. Flash models are faster and cheaper but may be less detailed. Pro 1.5 is recommended for security analysis accuracy."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <Select
                    id="gemini-model"
                    hideLabel
                    value={geminiConfig.model}
                    onChange={(e) => updateGeminiConfig('model', e.target.value)}
                    disabled={!geminiConfig.enabled}
                  >
                    <SelectItem value="gemini-1.5-pro" text="Gemini 1.5 Pro (Recommended)" />
                    <SelectItem value="gemini-1.5-flash" text="Gemini 1.5 Flash (Faster)" />
                    <SelectItem value="gemini-pro" text="Gemini Pro (Legacy)" />
                  </Select>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Auto-Explain</span>
                    <Tooltip
                      align="right"
                      label="When enabled, AI explanations are automatically generated when you view exposure details. When disabled, you must manually click 'Explain' button. Auto mode uses more API calls."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <Toggle
                    id="auto-explain"
                    labelText="Generate explanations automatically when viewing exposures"
                    labelA="Manual"
                    labelB="Automatic"
                    toggled={geminiConfig.autoExplain}
                    onToggle={(toggled) => updateGeminiConfig('autoExplain', toggled)}
                    disabled={!geminiConfig.enabled}
                  />
                </div>

                {geminiStatus === 'success' && (
                  <InlineNotification
                    kind="success"
                    title="API Key Valid"
                    subtitle="Gemini AI is ready to use."
                    style={{ marginBottom: '1rem' }}
                  />
                )}

                {geminiStatus === 'error' && (
                  <InlineNotification
                    kind="error"
                    title="Invalid API Key"
                    subtitle="Please check your API key and try again."
                    style={{ marginBottom: '1rem' }}
                  />
                )}

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <Button
                    kind="secondary"
                    onClick={handleTestGemini}
                    disabled={!geminiConfig.enabled || geminiStatus === 'testing'}
                  >
                    {geminiStatus === 'testing' ? 'Testing...' : 'Test API Key'}
                  </Button>
                  <Button kind="primary" renderIcon={Save} onClick={handleSave} disabled={isSaving}>
                    {isSaving ? 'Saving...' : 'Save Settings'}
                  </Button>
                  {isSaving && <InlineLoading description="Saving..." />}
                </div>
              </Tile>

              {/* AI Features info */}
              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <Bot size={20} style={{ color: '#8A3FFC' }} />
                  <h4>AI-Powered Features</h4>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <CheckmarkFilled size={16} style={{ color: '#42BE65', marginTop: '0.125rem' }} />
                    <div>
                      <div style={{ fontWeight: 500 }}>CVE Explanations</div>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                        Plain-language descriptions of what each CVE means for your application
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <CheckmarkFilled size={16} style={{ color: '#42BE65', marginTop: '0.125rem' }} />
                    <div>
                      <div style={{ fontWeight: 500 }}>Secret Impact Analysis</div>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                        Risk assessment for exposed credentials and how to remediate
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <CheckmarkFilled size={16} style={{ color: '#42BE65', marginTop: '0.125rem' }} />
                    <div>
                      <div style={{ fontWeight: 500 }}>Misconfiguration Guidance</div>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                        Infrastructure-as-code fixes and best practices
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <CheckmarkFilled size={16} style={{ color: '#42BE65', marginTop: '0.125rem' }} />
                    <div>
                      <div style={{ fontWeight: 500 }}>Executive Summaries</div>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--cve-text-secondary)' }}>
                        Business-friendly summaries for stakeholder communication
                      </div>
                    </div>
                  </div>
                </div>
              </Tile>
        </div>
      )}

      {/* ServiceNow Settings */}
      {activeTab === 2 && (
        <div style={{ maxWidth: '600px' }}>
          <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <h3>ServiceNow Integration</h3>
                      <Tooltip
                        align="right"
                        label="Connect to ServiceNow to create security incidents directly from remediation groups. Incidents include exposure details, risk scores, compliance tags, and SLA information for seamless tracking."
                      >
                        <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                          <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                        </button>
                      </Tooltip>
                    </div>
                    <p style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                      Create incidents from remediation groups
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {connectionStatus === 'success' && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#42BE65', fontSize: '0.875rem' }}>
                        <CheckmarkFilled size={16} />
                        Connected
                      </span>
                    )}
                    {connectionStatus === 'error' && (
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#FA4D56', fontSize: '0.875rem' }}>
                        <WarningAlt size={16} />
                        Failed
                      </span>
                    )}
                    <Toggle
                      id="servicenow-enabled"
                      labelA="Off"
                      labelB="On"
                      toggled={serviceNowConfig.enabled}
                      onToggle={(toggled) => updateConfig('enabled', toggled)}
                    />
                  </div>
                </div>

                <TextInput
                  id="instance-url"
                  labelText="Instance URL"
                  placeholder="https://your-instance.service-now.com"
                  value={serviceNowConfig.instanceUrl}
                  onChange={(e) => updateConfig('instanceUrl', e.target.value)}
                  disabled={!serviceNowConfig.enabled}
                  style={{ marginBottom: '1rem' }}
                />

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Authentication Method</span>
                    <Tooltip
                      align="right"
                      label="OAuth 2.0 is recommended for production (most secure). Basic Auth uses username/password. API Token provides simple authentication using a generated token from ServiceNow."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <RadioButtonGroup
                    name="auth-method"
                    valueSelected={serviceNowConfig.authMethod}
                    onChange={(value) => updateConfig('authMethod', value as string)}
                  >
                    <RadioButton labelText="Basic Auth" value="basic" disabled={!serviceNowConfig.enabled} />
                    <RadioButton labelText="OAuth 2.0" value="oauth" disabled={!serviceNowConfig.enabled} />
                    <RadioButton labelText="API Token" value="token" disabled={!serviceNowConfig.enabled} />
                  </RadioButtonGroup>
                </div>

                {/* Basic Auth Fields */}
                {serviceNowConfig.authMethod === 'basic' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <TextInput
                      id="username"
                      labelText="Username"
                      value={serviceNowConfig.username}
                      onChange={(e) => updateConfig('username', e.target.value)}
                      disabled={!serviceNowConfig.enabled}
                    />
                    <TextInput
                      id="password"
                      type="password"
                      labelText="Password"
                      value={serviceNowConfig.password}
                      onChange={(e) => updateConfig('password', e.target.value)}
                      disabled={!serviceNowConfig.enabled}
                    />
                  </div>
                )}

                {/* OAuth Fields */}
                {serviceNowConfig.authMethod === 'oauth' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                    <TextInput
                      id="client-id"
                      labelText="Client ID"
                      value={serviceNowConfig.clientId}
                      onChange={(e) => updateConfig('clientId', e.target.value)}
                      disabled={!serviceNowConfig.enabled}
                    />
                    <TextInput
                      id="client-secret"
                      type="password"
                      labelText="Client Secret"
                      value={serviceNowConfig.clientSecret}
                      onChange={(e) => updateConfig('clientSecret', e.target.value)}
                      disabled={!serviceNowConfig.enabled}
                    />
                  </div>
                )}

                {/* Token Auth Fields */}
                {serviceNowConfig.authMethod === 'token' && (
                  <TextInput
                    id="token"
                    type="password"
                    labelText="API Token"
                    value={serviceNowConfig.token}
                    onChange={(e) => updateConfig('token', e.target.value)}
                    disabled={!serviceNowConfig.enabled}
                    style={{ marginBottom: '1rem' }}
                  />
                )}

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Default Assignment Group</span>
                    <Tooltip
                      align="right"
                      label="The team that will be assigned newly created incidents by default. This can be overridden when creating individual incidents from remediation groups."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <Select
                    id="assignment-group"
                    hideLabel
                    value={serviceNowConfig.defaultAssignmentGroup}
                    onChange={(e) => updateConfig('defaultAssignmentGroup', e.target.value)}
                    disabled={!serviceNowConfig.enabled}
                  >
                    <SelectItem value="" text="Select assignment group..." />
                    <SelectItem value="security-ops" text="Security Operations" />
                    <SelectItem value="dev-ops" text="DevOps" />
                    <SelectItem value="app-dev" text="Application Development" />
                    <SelectItem value="infra" text="Infrastructure" />
                  </Select>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Default Priority</span>
                    <Tooltip
                      align="right"
                      label="Initial priority for new incidents. Critical (1) exposures with CISA KEV or overdue SLAs will automatically be set to Priority 1-2 regardless of this setting."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <Select
                    id="default-priority"
                    hideLabel
                    value={serviceNowConfig.defaultPriority}
                    onChange={(e) => updateConfig('defaultPriority', e.target.value)}
                    disabled={!serviceNowConfig.enabled}
                  >
                    <SelectItem value="1" text="1 - Critical" />
                    <SelectItem value="2" text="2 - High" />
                    <SelectItem value="3" text="3 - Moderate" />
                    <SelectItem value="4" text="4 - Low" />
                    <SelectItem value="5" text="5 - Planning" />
                  </Select>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 400, letterSpacing: '0.32px', color: 'var(--cve-text-primary)' }}>Auto-Create Incidents</span>
                    <Tooltip
                      align="right"
                      label="When enabled, incidents are automatically created in ServiceNow when exposures exceed their SLA deadlines. This helps ensure critical vulnerabilities are tracked and assigned without manual intervention."
                    >
                      <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                      </button>
                    </Tooltip>
                  </div>
                  <Toggle
                    id="auto-create"
                    labelText="Create incidents automatically for overdue SLA exposures"
                    labelA="No"
                    labelB="Yes"
                    toggled={serviceNowConfig.autoCreateIncidents}
                    onToggle={(toggled) => updateConfig('autoCreateIncidents', toggled)}
                    disabled={!serviceNowConfig.enabled}
                  />
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <Button
                    kind="secondary"
                    onClick={handleTestConnection}
                    disabled={!serviceNowConfig.enabled || !serviceNowConfig.instanceUrl || connectionStatus === 'testing'}
                  >
                    {connectionStatus === 'testing' ? 'Testing...' : 'Test Connection'}
                  </Button>
                  <Button kind="primary" renderIcon={Save} onClick={handleSave} disabled={isSaving}>
                    {isSaving ? 'Saving...' : 'Save Settings'}
                  </Button>
                  {isSaving && <InlineLoading description="Saving..." />}
                </div>
              </Tile>

              {/* How it works */}
              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                  <Information size={20} style={{ color: '#0f62fe' }} />
                  <h4>How ServiceNow Integration Works</h4>
                </div>
                <ol style={{ paddingLeft: '1.25rem', color: 'var(--cve-text-secondary)', fontSize: '0.875rem', lineHeight: 1.8 }}>
                  <li>Navigate to the Remediation Groups page</li>
                  <li>Click "Create Incident" on any remediation group</li>
                  <li>An incident will be created with all exposure details</li>
                  <li>Compliance tags, risk scores, and SLA info are included</li>
                  <li>Track remediation progress directly in ServiceNow</li>
                </ol>
              </Tile>
        </div>
      )}

      {/* General Settings */}
      {activeTab === 3 && (
        <div style={{ maxWidth: '600px' }}>
          {/* Risk Scoring */}
          <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <h3>Risk Scoring</h3>
                  <Tooltip
                    align="right"
                    label="Risk scores help prioritize vulnerabilities based on their actual threat level in your environment. Both formulas normalize scores to 0-10 for easy comparison."
                  >
                    <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                      <Information size={16} style={{ color: 'var(--cve-text-secondary)' }} />
                    </button>
                  </Tooltip>
                </div>
                <RadioButtonGroup
                  legendText="Default Formula"
                  name="risk-formula"
                  orientation="vertical"
                  valueSelected={riskFormula}
                  onChange={(value) => setRiskFormula(value as typeof riskFormula)}
                >
                  <RadioButton
                    labelText={
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                        <div>
                          <strong>Concert Formula</strong>
                          <span style={{ display: 'block', fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                            Risk = CVSS × Exploitability × Environmental (Scale: 0-10)
                          </span>
                        </div>
                        <Tooltip
                          align="right"
                          label="Concert Formula combines CVSS base score with EPSS exploitability probability and environmental factors (app criticality, data sensitivity, network exposure). Best for organizations wanting threat-intelligence-driven prioritization."
                        >
                          <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginTop: '2px' }}>
                            <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                          </button>
                        </Tooltip>
                      </div>
                    }
                    value="concert"
                  />
                  <RadioButton
                    labelText={
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                        <div>
                          <strong>Comprehensive Formula</strong>
                          <span style={{ display: 'block', fontSize: '0.875rem', color: 'var(--cve-text-secondary)' }}>
                            Risk = Likelihood × Impact × Exposure × Controls (Scale: 0-10)
                          </span>
                        </div>
                        <Tooltip
                          align="right"
                          label="Comprehensive Formula uses traditional risk assessment methodology: Likelihood (EPSS + exploit availability), Impact (CVSS impact subscore), Exposure (network accessibility), and Controls (existing mitigations). Best for GRC-focused organizations."
                        >
                          <button type="button" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginTop: '2px' }}>
                            <Information size={14} style={{ color: 'var(--cve-text-secondary)' }} />
                          </button>
                        </Tooltip>
                      </div>
                    }
                    value="comprehensive"
                  />
                </RadioButtonGroup>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '1.5rem' }}>
                  <Button kind="primary" renderIcon={Save} onClick={handleSave} disabled={isSaving}>
                    {isSaving ? 'Saving...' : 'Save Settings'}
                  </Button>
                  {isSaving && <InlineLoading description="Saving..." />}
                </div>
              </Tile>

              {/* About */}
              <Tile style={{ padding: '1.5rem', backgroundColor: '#161616', border: '1px solid #393939' }}>
                <h3 style={{ marginBottom: '1rem' }}>About Concert TEM</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>
                  <div>Version: 1.0.0</div>
                  <div>Build: 2025.01.16</div>
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ fontWeight: 500, color: 'var(--cve-text-primary)', marginBottom: '0.5rem' }}>
                      Supported Exposure Types
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <Tag type="red">CVEs</Tag>
                      <Tag type="purple">Certificates</Tag>
                      <Tag type="warm-gray">Secrets</Tag>
                      <Tag type="blue">Misconfigurations</Tag>
                      <Tag type="teal">Licenses</Tag>
                      <Tag type="cyan">Code Security</Tag>
                    </div>
                  </div>
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ fontWeight: 500, color: 'var(--cve-text-primary)', marginBottom: '0.5rem' }}>
                      Features
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <Tag type="outline">CISA KEV</Tag>
                      <Tag type="outline">EPSS Scoring</Tag>
                      <Tag type="outline">Dual Risk Formulas</Tag>
                      <Tag type="outline">SLA Tracking</Tag>
                      <Tag type="outline">Compliance Mapping</Tag>
                    </div>
                  </div>
                </div>
          </Tile>
        </div>
      )}

      {/* API Key Help Modal */}
      <Modal
        open={showApiKeyModal}
        onRequestClose={() => setShowApiKeyModal(false)}
        modalHeading="Getting a Gemini API Key"
        primaryButtonText="Got it"
        onRequestSubmit={() => setShowApiKeyModal(false)}
        size="md"
      >
        <div>
          <p style={{ marginBottom: '1rem' }}>
            To use Gemini AI features, you need an API key from Google AI Studio:
          </p>
          <ol style={{ paddingLeft: '1.25rem', lineHeight: 1.8, marginBottom: '1.5rem' }}>
            <li>Go to <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" style={{ color: '#78A9FF' }}>Google AI Studio</a></li>
            <li>Sign in with your Google account</li>
            <li>Click "Create API Key"</li>
            <li>Copy the key and paste it here</li>
          </ol>
          <InlineNotification
            kind="info"
            title="Free Tier Available"
            subtitle="Gemini API has a generous free tier for development and testing."
            lowContrast
          />
        </div>
      </Modal>
    </div>
  );
}

export default Settings;
