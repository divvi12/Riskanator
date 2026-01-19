import { ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { Button, Toggle } from '@carbon/react';
import {
  Dashboard,
  ChartNetwork,
  Add,
  WarningAlt,
  Tools,
  Settings,
  Demo,
  Report
} from '@carbon/icons-react';
import { useAppContext } from '../App';
import GamificationSidebarWidget, { XPNotification, LevelUpModal } from './GamificationPanel';

interface LayoutProps {
  children: ReactNode;
  onExitDemo: () => void;
  onEnterDemo: () => void;
}

function Layout({ children, onExitDemo, onEnterDemo }: LayoutProps) {
  const { isDemoMode, currentScan } = useAppContext();
  const navigate = useNavigate();

  const handleDemoToggle = (toggled: boolean) => {
    if (toggled) {
      onEnterDemo();
      navigate('/app/dashboard');
    } else {
      onExitDemo();
      navigate('/app/dashboard');
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">C</div>
          <span className="sidebar-title">Concert TEM</span>
        </div>

        {/* New Scan Button */}
        <div style={{ padding: '0 1rem', marginBottom: '1rem' }}>
          <Button
            kind="primary"
            size="sm"
            renderIcon={Add}
            onClick={() => navigate('/app/scan')}
            style={{ width: '100%' }}
          >
            New Scan
          </Button>
        </div>

        <nav className="sidebar-nav">
          <NavLink
            to="/app/dashboard"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Dashboard />
            <span>Dashboard</span>
          </NavLink>

          <NavLink
            to="/app/arena"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <ChartNetwork />
            <span>Arena View</span>
          </NavLink>

          <NavLink
            to="/app/exposures"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <WarningAlt />
            <span>Exposures</span>
          </NavLink>

          <NavLink
            to="/app/remediation"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Tools />
            <span>Prioritized</span>
          </NavLink>

          <NavLink
            to="/app/compliance"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Report />
            <span>Compliance</span>
          </NavLink>

          <NavLink
            to="/app/settings"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Settings />
            <span>Settings</span>
          </NavLink>
        </nav>

        {/* Gamification Widget */}
        <div style={{
          padding: '1rem',
          borderTop: '1px solid var(--cve-border)',
          marginTop: 'auto'
        }}>
          <GamificationSidebarWidget />
        </div>

        {/* Demo Mode Toggle - Bottom Left */}
        <div style={{
          padding: '1rem',
          borderTop: '1px solid var(--cve-border)'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.5rem'
          }}>
            <Demo size={16} style={{ color: isDemoMode ? '#8A3FFC' : 'var(--cve-text-secondary)' }} />
            <span style={{
              fontSize: '0.75rem',
              color: isDemoMode ? '#8A3FFC' : 'var(--cve-text-secondary)',
              fontWeight: 500
            }}>
              Demo Mode
            </span>
          </div>
          <Toggle
            id="demo-mode-toggle"
            size="sm"
            labelA="Off"
            labelB="On"
            toggled={isDemoMode}
            onToggle={handleDemoToggle}
          />
        </div>
      </aside>

      {/* Main Content */}
      <div className="main-content">
        {/* Header */}
        <header className="app-header">
          <div className="header-left">
            {currentScan?.metadata?.repoUrl && (
              <span style={{ color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>
                {currentScan.metadata.repoUrl}
              </span>
            )}
          </div>

          <div className="header-right">
            {isDemoMode && (
              <span className="demo-badge">Demo Mode</span>
            )}
          </div>
        </header>

        {/* Page Content */}
        <main className="page-content">
          {children}
        </main>
      </div>

      {/* Gamification Overlays */}
      <XPNotification />
      <LevelUpModal />
    </div>
  );
}

export default Layout;
