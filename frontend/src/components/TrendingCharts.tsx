import { useMemo } from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine
} from 'recharts';
import { ScanHistoryEntry } from '../services/scanHistoryService';

// Severity colors (consistent with rest of app)
const SEVERITY_COLORS = {
  critical: '#FA4D56',
  high: '#FF832B',
  medium: '#F1C21B',
  low: '#42BE65'
};

// Exposure type colors (consistent with rest of app)
const TYPE_COLORS = {
  cve: '#FA4D56',
  secret: '#FF832B',
  certificate: '#8A3FFC',
  misconfiguration: '#1192E8',
  license: '#009D9A',
  codeSecurity: '#6929C4'
};

interface TrendingChartsProps {
  history: ScanHistoryEntry[];
  selectedRepo?: string;
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function formatDateTime(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Custom tooltip styling
const tooltipStyle = {
  backgroundColor: 'var(--cve-background-secondary)',
  border: '1px solid var(--cve-border)',
  borderRadius: '4px',
  padding: '8px 12px'
};

const tooltipLabelStyle = {
  color: 'var(--cve-text-primary)',
  fontWeight: 600,
  marginBottom: '4px'
};

// Risk Score Trend Line Chart
export function RiskScoreTrendChart({ history, selectedRepo }: TrendingChartsProps) {
  const data = useMemo(() => {
    let filtered = history;
    if (selectedRepo) {
      filtered = history.filter(h => h.repoUrl === selectedRepo);
    }

    return filtered
      .slice()
      .reverse() // Oldest first for trend
      .map(h => ({
        date: formatDate(h.scanDate),
        fullDate: formatDateTime(h.scanDate),
        riskScore: h.riskScore.concert,
        repoName: h.repoName
      }));
  }, [history, selectedRepo]);

  if (data.length === 0) {
    return (
      <div style={{ height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--cve-text-secondary)' }}>
        No scan history available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--cve-border)" />
        <XAxis
          dataKey="date"
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <YAxis
          domain={[0, 10]}
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelStyle={tooltipLabelStyle}
          formatter={(value: number) => [value.toFixed(2), 'Risk Score']}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.fullDate || ''}
        />
        <ReferenceLine y={5} stroke="#F1C21B" strokeDasharray="5 5" label={{ value: 'Threshold', fill: '#F1C21B', fontSize: 10 }} />
        <Line
          type="monotone"
          dataKey="riskScore"
          stroke="#4589FF"
          strokeWidth={2}
          dot={{ fill: '#4589FF', strokeWidth: 2, r: 4 }}
          activeDot={{ r: 6, stroke: '#4589FF', strokeWidth: 2 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

// Exposure Count Trend Area Chart (stacked by severity)
export function ExposureTrendChart({ history, selectedRepo }: TrendingChartsProps) {
  const data = useMemo(() => {
    let filtered = history;
    if (selectedRepo) {
      filtered = history.filter(h => h.repoUrl === selectedRepo);
    }

    return filtered
      .slice()
      .reverse()
      .map(h => ({
        date: formatDate(h.scanDate),
        fullDate: formatDateTime(h.scanDate),
        critical: h.bySeverity.critical,
        high: h.bySeverity.high,
        medium: h.bySeverity.medium,
        low: h.bySeverity.low,
        total: h.totalExposures
      }));
  }, [history, selectedRepo]);

  if (data.length === 0) {
    return (
      <div style={{ height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--cve-text-secondary)' }}>
        No scan history available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={250}>
      <AreaChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--cve-border)" />
        <XAxis
          dataKey="date"
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <YAxis
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelStyle={tooltipLabelStyle}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.fullDate || ''}
        />
        <Legend
          wrapperStyle={{ fontSize: 12, color: 'var(--cve-text-secondary)' }}
        />
        <Area type="monotone" dataKey="critical" stackId="1" stroke={SEVERITY_COLORS.critical} fill={SEVERITY_COLORS.critical} fillOpacity={0.8} name="Critical" />
        <Area type="monotone" dataKey="high" stackId="1" stroke={SEVERITY_COLORS.high} fill={SEVERITY_COLORS.high} fillOpacity={0.8} name="High" />
        <Area type="monotone" dataKey="medium" stackId="1" stroke={SEVERITY_COLORS.medium} fill={SEVERITY_COLORS.medium} fillOpacity={0.8} name="Medium" />
        <Area type="monotone" dataKey="low" stackId="1" stroke={SEVERITY_COLORS.low} fill={SEVERITY_COLORS.low} fillOpacity={0.8} name="Low" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// Exposure Type Distribution Bar Chart
export function ExposureTypeChart({ history, selectedRepo }: TrendingChartsProps) {
  const data = useMemo(() => {
    let filtered = history;
    if (selectedRepo) {
      filtered = history.filter(h => h.repoUrl === selectedRepo);
    }

    return filtered
      .slice()
      .reverse()
      .map(h => ({
        date: formatDate(h.scanDate),
        fullDate: formatDateTime(h.scanDate),
        CVEs: h.byType.cve,
        Secrets: h.byType.secret,
        Certificates: h.byType.certificate,
        Misconfigs: h.byType.misconfiguration,
        Licenses: h.byType.license,
        'Code Security': h.byType.codeSecurity
      }));
  }, [history, selectedRepo]);

  if (data.length === 0) {
    return (
      <div style={{ height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--cve-text-secondary)' }}>
        No scan history available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={250}>
      <BarChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--cve-border)" />
        <XAxis
          dataKey="date"
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <YAxis
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelStyle={tooltipLabelStyle}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.fullDate || ''}
        />
        <Legend
          wrapperStyle={{ fontSize: 11, color: 'var(--cve-text-secondary)' }}
        />
        <Bar dataKey="CVEs" stackId="a" fill={TYPE_COLORS.cve} />
        <Bar dataKey="Secrets" stackId="a" fill={TYPE_COLORS.secret} />
        <Bar dataKey="Certificates" stackId="a" fill={TYPE_COLORS.certificate} />
        <Bar dataKey="Misconfigs" stackId="a" fill={TYPE_COLORS.misconfiguration} />
        <Bar dataKey="Licenses" stackId="a" fill={TYPE_COLORS.license} />
        <Bar dataKey="Code Security" stackId="a" fill={TYPE_COLORS.codeSecurity} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// Repository Comparison Chart
export function RepoComparisonChart({ history }: { history: ScanHistoryEntry[] }) {
  const data = useMemo(() => {
    // Get latest scan for each repo
    const repoMap = new Map<string, ScanHistoryEntry>();
    history.forEach(h => {
      if (!repoMap.has(h.repoUrl)) {
        repoMap.set(h.repoUrl, h);
      }
    });

    return Array.from(repoMap.values())
      .slice(0, 10) // Top 10 repos
      .map(h => ({
        name: h.repoName.length > 20 ? h.repoName.substring(0, 18) + '...' : h.repoName,
        fullName: h.repoName,
        exposures: h.totalExposures,
        riskScore: h.riskScore.concert,
        critical: h.bySeverity.critical,
        high: h.bySeverity.high
      }))
      .sort((a, b) => b.riskScore - a.riskScore);
  }, [history]);

  if (data.length === 0) {
    return (
      <div style={{ height: 250, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--cve-text-secondary)' }}>
        No repositories scanned
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 40)}>
      <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--cve-border)" />
        <XAxis
          type="number"
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 12 }}
          stroke="var(--cve-border)"
        />
        <YAxis
          type="category"
          dataKey="name"
          tick={{ fill: 'var(--cve-text-secondary)', fontSize: 11 }}
          stroke="var(--cve-border)"
          width={90}
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelStyle={tooltipLabelStyle}
          formatter={(value: number, name: string) => [value, name === 'riskScore' ? 'Risk Score' : name]}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.fullName || ''}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="riskScore" fill="#4589FF" name="Risk Score" />
        <Bar dataKey="exposures" fill="#8A3FFC" name="Exposures" />
      </BarChart>
    </ResponsiveContainer>
  );
}

// Summary Stats Component
export function TrendingSummary({ history }: { history: ScanHistoryEntry[] }) {
  const stats = useMemo(() => {
    if (history.length === 0) {
      return {
        trendDirection: 'neutral' as const,
        riskChange: 0,
        exposureChange: 0
      };
    }

    if (history.length < 2) {
      return {
        trendDirection: 'neutral' as const,
        riskChange: 0,
        exposureChange: 0
      };
    }

    const latest = history[0];
    const previous = history[1];

    const riskChange = latest.riskScore.concert - previous.riskScore.concert;
    const exposureChange = latest.totalExposures - previous.totalExposures;

    let trendDirection: 'improving' | 'worsening' | 'neutral' = 'neutral';
    if (riskChange < -0.5 || exposureChange < -5) {
      trendDirection = 'improving';
    } else if (riskChange > 0.5 || exposureChange > 5) {
      trendDirection = 'worsening';
    }

    return {
      trendDirection,
      riskChange: Math.round(riskChange * 10) / 10,
      exposureChange
    };
  }, [history]);

  const getTrendColor = () => {
    switch (stats.trendDirection) {
      case 'improving': return '#42BE65';
      case 'worsening': return '#FA4D56';
      default: return 'var(--cve-text-secondary)';
    }
  };

  const getTrendIcon = () => {
    switch (stats.trendDirection) {
      case 'improving': return '\u2193'; // Down arrow (good)
      case 'worsening': return '\u2191'; // Up arrow (bad)
      default: return '\u2192'; // Right arrow (neutral)
    }
  };

  return (
    <div style={{
      display: 'flex',
      gap: '1rem',
      marginBottom: '1rem',
      flexWrap: 'wrap'
    }}>
      <div style={{
        background: 'var(--cve-background-secondary)',
        padding: '1rem',
        borderRadius: '4px',
        flex: '1 1 200px'
      }}>
        <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
          Security Trend
        </div>
        <div style={{ color: getTrendColor(), fontSize: '1.25rem', fontWeight: 600 }}>
          {getTrendIcon()} {stats.trendDirection.charAt(0).toUpperCase() + stats.trendDirection.slice(1)}
        </div>
      </div>

      <div style={{
        background: 'var(--cve-background-secondary)',
        padding: '1rem',
        borderRadius: '4px',
        flex: '1 1 200px'
      }}>
        <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
          Risk Score Change
        </div>
        <div style={{
          color: stats.riskChange <= 0 ? '#42BE65' : '#FA4D56',
          fontSize: '1.25rem',
          fontWeight: 600
        }}>
          {stats.riskChange > 0 ? '+' : ''}{stats.riskChange}
        </div>
      </div>

      <div style={{
        background: 'var(--cve-background-secondary)',
        padding: '1rem',
        borderRadius: '4px',
        flex: '1 1 200px'
      }}>
        <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
          Exposure Change
        </div>
        <div style={{
          color: stats.exposureChange <= 0 ? '#42BE65' : '#FA4D56',
          fontSize: '1.25rem',
          fontWeight: 600
        }}>
          {stats.exposureChange > 0 ? '+' : ''}{stats.exposureChange}
        </div>
      </div>
    </div>
  );
}
