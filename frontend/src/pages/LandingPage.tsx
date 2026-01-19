import { useNavigate } from 'react-router-dom';
import { Button } from '@carbon/react';
import { Analytics, Scan, Security } from '@carbon/icons-react';

interface LandingPageProps {
  onEnterDemo: () => void;
}

function LandingPage({ onEnterDemo }: LandingPageProps) {
  const navigate = useNavigate();

  const handleDemoMode = () => {
    onEnterDemo();
    navigate('/app/dashboard');
  };

  const handleScanRepo = () => {
    navigate('/app/scan');
  };

  return (
    <div className="landing-page">
      <div className="landing-content">
        <div style={{ marginBottom: '2rem' }}>
          <div
            style={{
              width: '80px',
              height: '80px',
              background: 'linear-gradient(135deg, #4589FF 0%, #6929c4 100%)',
              borderRadius: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1.5rem',
              boxShadow: '0 8px 32px rgba(69, 137, 255, 0.3)'
            }}
          >
            <Security size={40} style={{ color: 'white' }} />
          </div>
        </div>

        <h1 className="landing-title">Concert</h1>
        <p className="landing-subtitle">
          Threat Exposure Management Platform.
          Scan repositories for vulnerabilities, apply contextualized risk scoring,
          and get AI-powered remediation guidance.
        </p>

        <div className="landing-actions">
          <Button
            kind="primary"
            size="lg"
            renderIcon={Analytics}
            onClick={handleDemoMode}
            style={{ minWidth: '240px' }}
          >
            Try Demo Mode
          </Button>

          <div className="landing-divider">
            <span>or</span>
          </div>

          <Button
            kind="secondary"
            size="lg"
            renderIcon={Scan}
            onClick={handleScanRepo}
            style={{ minWidth: '240px' }}
          >
            Scan Repository
          </Button>
        </div>

        <div style={{ marginTop: '4rem' }}>
          <h3 style={{ fontSize: '1rem', marginBottom: '1.5rem', color: 'var(--cve-text-secondary)' }}>
            Key Features
          </h3>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1.5rem',
              textAlign: 'left'
            }}
          >
            <FeatureCard
              title="Multi-Language Scanning"
              description="SCA, SAST, Container, and IaC vulnerability detection"
            />
            <FeatureCard
              title="Risk Scoring"
              description="Concert & Comprehensive formulas with context"
            />
            <FeatureCard
              title="AI Explanations"
              description="Gemini-powered CVE analysis and remediation"
            />
            <FeatureCard
              title="Compliance Mapping"
              description="PCI-DSS, HIPAA, SOX, and GDPR mapping"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div
      style={{
        padding: '1rem',
        backgroundColor: 'var(--cve-background-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--cve-border)'
      }}
    >
      <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem', color: 'var(--cve-text-primary)' }}>
        {title}
      </h4>
      <p style={{ fontSize: '0.75rem', color: 'var(--cve-text-secondary)', lineHeight: 1.5 }}>
        {description}
      </p>
    </div>
  );
}

export default LandingPage;
