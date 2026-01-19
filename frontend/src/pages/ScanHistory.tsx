import { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Button,
  Tile,
  Tag,
  Search,
  Modal,
  Select,
  SelectItem
} from '@carbon/react';
import {
  TrashCan,
  Download,
  View,
  Calendar,
  Warning,
  ChartLine,
  Renew
} from '@carbon/icons-react';
import {
  getHistory,
  clearHistory,
  deleteFromHistory,
  getHistoryStats,
  exportHistoryAsCSV,
  ScanHistoryEntry,
  getUniqueRepos
} from '../services/scanHistoryService';
import {
  RiskScoreTrendChart,
  ExposureTrendChart,
  ExposureTypeChart,
  RepoComparisonChart,
  TrendingSummary
} from '../components/TrendingCharts';
import { useAppContext } from '../App';

type SortField = 'date' | 'risk' | 'exposures' | 'repo';
type SortDirection = 'asc' | 'desc';

function ScanHistory() {
  const navigate = useNavigate();
  const { setCurrentScan, setApplicationContext } = useAppContext();

  const [history, setHistory] = useState<ScanHistoryEntry[]>(getHistory());
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [sortField, setSortField] = useState<SortField>('date');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [showClearModal, setShowClearModal] = useState(false);
  const [showChartsSection, setShowChartsSection] = useState(true);

  const stats = useMemo(() => getHistoryStats(), [history]);
  const uniqueRepos = useMemo(() => getUniqueRepos(), [history]);

  const refreshHistory = useCallback(() => {
    setHistory(getHistory());
  }, []);

  const filteredAndSortedHistory = useMemo(() => {
    let result = history;

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(h =>
        h.repoName.toLowerCase().includes(query) ||
        h.repoUrl.toLowerCase().includes(query) ||
        h.scanId.toLowerCase().includes(query)
      );
    }

    // Filter by selected repo
    if (selectedRepo) {
      result = result.filter(h => h.repoUrl === selectedRepo);
    }

    // Sort
    result = [...result].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'date':
          comparison = new Date(a.scanDate).getTime() - new Date(b.scanDate).getTime();
          break;
        case 'risk':
          comparison = a.riskScore.concert - b.riskScore.concert;
          break;
        case 'exposures':
          comparison = a.totalExposures - b.totalExposures;
          break;
        case 'repo':
          comparison = a.repoName.localeCompare(b.repoName);
          break;
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [history, searchQuery, selectedRepo, sortField, sortDirection]);

  const handleClearHistory = () => {
    clearHistory();
    setHistory([]);
    setShowClearModal(false);
  };

  const handleDeleteScan = (scanId: string) => {
    deleteFromHistory(scanId);
    refreshHistory();
  };

  const handleExportCSV = () => {
    const csv = exportHistoryAsCSV();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `riskanator-history-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleViewScan = async (entry: ScanHistoryEntry) => {
    // Try to fetch from backend if still available
    try {
      const response = await fetch(`/api/exposure-scan/${entry.scanId}/results`);
      if (response.ok) {
        const fullResult = await response.json();
        setCurrentScan(fullResult);
        if (fullResult.metadata?.context) {
          setApplicationContext(fullResult.metadata.context);
        }
        navigate('/app/dashboard');
        return;
      }
    } catch {
      // Backend doesn't have it, that's okay
    }

    // Show info that full details aren't available
    alert('Full scan details are no longer available. Only summary data is stored in history.');
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#FA4D56';
      case 'high': return '#FF832B';
      case 'medium': return '#F1C21B';
      case 'low': return '#42BE65';
      default: return 'var(--cve-text-secondary)';
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return { label: 'Critical', color: '#FA4D56' };
    if (score >= 6) return { label: 'High', color: '#FF832B' };
    if (score >= 4) return { label: 'Medium', color: '#F1C21B' };
    return { label: 'Low', color: '#42BE65' };
  };

  return (
    <div className="scan-history-page" style={{ padding: '1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '1.5rem',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.75rem', color: 'var(--cve-text-primary)' }}>
            Scan History
          </h1>
          <p style={{ margin: '0.25rem 0 0', color: 'var(--cve-text-secondary)', fontSize: '0.875rem' }}>
            View and analyze your previous security scans
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={Renew}
            onClick={refreshHistory}
          >
            Refresh
          </Button>
          <Button
            kind="tertiary"
            size="sm"
            renderIcon={Download}
            onClick={handleExportCSV}
            disabled={history.length === 0}
          >
            Export CSV
          </Button>
          <Button
            kind="danger--tertiary"
            size="sm"
            renderIcon={TrashCan}
            onClick={() => setShowClearModal(true)}
            disabled={history.length === 0}
          >
            Clear History
          </Button>
        </div>
      </div>

      {/* Stats Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem'
      }}>
        <Tile style={{ background: 'var(--cve-background-secondary)' }}>
          <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
            Total Scans
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: 'var(--cve-text-primary)' }}>
            {stats.totalScans}
          </div>
        </Tile>

        <Tile style={{ background: 'var(--cve-background-secondary)' }}>
          <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
            Repositories Scanned
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, color: 'var(--cve-text-primary)' }}>
            {stats.uniqueRepos}
          </div>
        </Tile>

        <Tile style={{ background: 'var(--cve-background-secondary)' }}>
          <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
            Average Risk Score
          </div>
          <div style={{
            fontSize: '2rem',
            fontWeight: 600,
            color: getRiskLevel(stats.averageRiskScore).color
          }}>
            {stats.averageRiskScore.toFixed(1)}
          </div>
        </Tile>

        <Tile style={{ background: 'var(--cve-background-secondary)' }}>
          <div style={{ color: 'var(--cve-text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
            Latest Scan
          </div>
          <div style={{ fontSize: '1rem', fontWeight: 500, color: 'var(--cve-text-primary)' }}>
            {stats.latestScan ? formatDate(stats.latestScan.scanDate) : 'No scans yet'}
          </div>
        </Tile>
      </div>

      {/* Trending Charts Section */}
      {history.length >= 2 && (
        <Tile style={{
          background: 'var(--cve-background-secondary)',
          marginBottom: '1.5rem',
          padding: '1rem'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ChartLine size={20} />
              <h2 style={{ margin: 0, fontSize: '1.125rem' }}>Security Trends</h2>
            </div>
            <Button
              kind="ghost"
              size="sm"
              onClick={() => setShowChartsSection(!showChartsSection)}
            >
              {showChartsSection ? 'Hide Charts' : 'Show Charts'}
            </Button>
          </div>

          {showChartsSection && (
            <>
              <TrendingSummary history={history} />

              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
                gap: '1.5rem'
              }}>
                <div>
                  <h3 style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                    Risk Score Over Time
                  </h3>
                  <RiskScoreTrendChart history={history} selectedRepo={selectedRepo} />
                </div>

                <div>
                  <h3 style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                    Exposures by Severity
                  </h3>
                  <ExposureTrendChart history={history} selectedRepo={selectedRepo} />
                </div>

                <div>
                  <h3 style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                    Exposures by Type
                  </h3>
                  <ExposureTypeChart history={history} selectedRepo={selectedRepo} />
                </div>

                <div>
                  <h3 style={{ fontSize: '0.875rem', color: 'var(--cve-text-secondary)', marginBottom: '0.5rem' }}>
                    Repository Comparison
                  </h3>
                  <RepoComparisonChart history={history} />
                </div>
              </div>
            </>
          )}
        </Tile>
      )}

      {/* Filters and Controls */}
      <div style={{
        display: 'flex',
        gap: '1rem',
        marginBottom: '1rem',
        flexWrap: 'wrap',
        alignItems: 'flex-end'
      }}>
        <div style={{ flex: '1 1 300px' }}>
          <Search
            id="history-search"
            labelText="Search"
            placeholder="Search by repository name or scan ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            size="md"
          />
        </div>

        <div style={{ width: '200px' }}>
          <Select
            id="repo-filter"
            labelText="Filter by Repository"
            value={selectedRepo}
            onChange={(e) => setSelectedRepo(e.target.value)}
          >
            <SelectItem value="" text="All Repositories" />
            {uniqueRepos.map(repo => (
              <SelectItem
                key={repo}
                value={repo}
                text={repo.split('/').pop() || repo}
              />
            ))}
          </Select>
        </div>

        <div style={{ width: '150px' }}>
          <Select
            id="sort-field"
            labelText="Sort By"
            value={sortField}
            onChange={(e) => setSortField(e.target.value as SortField)}
          >
            <SelectItem value="date" text="Date" />
            <SelectItem value="risk" text="Risk Score" />
            <SelectItem value="exposures" text="Exposures" />
            <SelectItem value="repo" text="Repository" />
          </Select>
        </div>

        <Button
          kind="ghost"
          size="md"
          onClick={() => setSortDirection(d => d === 'asc' ? 'desc' : 'asc')}
          style={{ minWidth: '100px' }}
        >
          {sortDirection === 'asc' ? '\u2191 Ascending' : '\u2193 Descending'}
        </Button>
      </div>

      {/* History List */}
      {filteredAndSortedHistory.length === 0 ? (
        <Tile style={{
          background: 'var(--cve-background-secondary)',
          textAlign: 'center',
          padding: '3rem'
        }}>
          <Warning size={48} style={{ color: 'var(--cve-text-secondary)', marginBottom: '1rem' }} />
          <h3 style={{ margin: '0 0 0.5rem', color: 'var(--cve-text-primary)' }}>
            {history.length === 0 ? 'No Scan History' : 'No Matching Results'}
          </h3>
          <p style={{ margin: 0, color: 'var(--cve-text-secondary)' }}>
            {history.length === 0
              ? 'Complete a security scan to start building your history.'
              : 'Try adjusting your search or filter criteria.'}
          </p>
          {history.length === 0 && (
            <Button
              kind="primary"
              style={{ marginTop: '1rem' }}
              onClick={() => navigate('/app/scan')}
            >
              Start New Scan
            </Button>
          )}
        </Tile>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {filteredAndSortedHistory.map((entry) => {
            const riskLevel = getRiskLevel(entry.riskScore.concert);

            return (
              <Tile
                key={entry.scanId}
                style={{
                  background: 'var(--cve-background-secondary)',
                  padding: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  cursor: 'pointer'
                }}
                onClick={() => handleViewScan(entry)}
              >
                {/* Risk Score Badge */}
                <div style={{
                  width: '60px',
                  height: '60px',
                  borderRadius: '8px',
                  background: `${riskLevel.color}20`,
                  border: `2px solid ${riskLevel.color}`,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}>
                  <span style={{ fontSize: '1.25rem', fontWeight: 700, color: riskLevel.color }}>
                    {entry.riskScore.concert.toFixed(1)}
                  </span>
                  <span style={{ fontSize: '0.625rem', color: riskLevel.color, textTransform: 'uppercase' }}>
                    Risk
                  </span>
                </div>

                {/* Main Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: '1rem',
                    fontWeight: 600,
                    color: 'var(--cve-text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}>
                    {entry.repoName}
                  </div>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    marginTop: '0.25rem',
                    color: 'var(--cve-text-secondary)',
                    fontSize: '0.75rem'
                  }}>
                    <Calendar size={14} />
                    <span>{formatDate(entry.scanDate)}</span>
                    {entry.branch && (
                      <>
                        <span style={{ margin: '0 0.25rem' }}>|</span>
                        <span>Branch: {entry.branch}</span>
                      </>
                    )}
                  </div>
                </div>

                {/* Severity Breakdown */}
                <div style={{
                  display: 'flex',
                  gap: '0.5rem',
                  flexShrink: 0
                }}>
                  {entry.bySeverity.critical > 0 && (
                    <Tag type="red" size="sm">
                      {entry.bySeverity.critical} Critical
                    </Tag>
                  )}
                  {entry.bySeverity.high > 0 && (
                    <Tag style={{ background: getSeverityColor('high'), color: '#000' }} size="sm">
                      {entry.bySeverity.high} High
                    </Tag>
                  )}
                  {entry.bySeverity.medium > 0 && (
                    <Tag type="warm-gray" size="sm">
                      {entry.bySeverity.medium} Med
                    </Tag>
                  )}
                  {entry.bySeverity.low > 0 && (
                    <Tag type="green" size="sm">
                      {entry.bySeverity.low} Low
                    </Tag>
                  )}
                </div>

                {/* Total Exposures */}
                <div style={{
                  textAlign: 'center',
                  padding: '0 1rem',
                  borderLeft: '1px solid var(--cve-border)',
                  flexShrink: 0
                }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--cve-text-primary)' }}>
                    {entry.totalExposures}
                  </div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--cve-text-secondary)', textTransform: 'uppercase' }}>
                    Exposures
                  </div>
                </div>

                {/* Actions */}
                <div style={{
                  display: 'flex',
                  gap: '0.25rem',
                  flexShrink: 0
                }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={View}
                    iconDescription="View Details"
                    hasIconOnly
                    onClick={() => handleViewScan(entry)}
                  />
                  <Button
                    kind="danger--ghost"
                    size="sm"
                    renderIcon={TrashCan}
                    iconDescription="Delete"
                    hasIconOnly
                    onClick={() => handleDeleteScan(entry.scanId)}
                  />
                </div>
              </Tile>
            );
          })}
        </div>
      )}

      {/* Clear History Modal */}
      <Modal
        open={showClearModal}
        onRequestClose={() => setShowClearModal(false)}
        onRequestSubmit={handleClearHistory}
        modalHeading="Clear Scan History"
        primaryButtonText="Clear All"
        secondaryButtonText="Cancel"
        danger
      >
        <p style={{ color: 'var(--cve-text-primary)' }}>
          Are you sure you want to clear all scan history? This action cannot be undone.
        </p>
        <p style={{ color: 'var(--cve-text-secondary)', marginTop: '0.5rem' }}>
          {history.length} scan{history.length !== 1 ? 's' : ''} will be permanently deleted.
        </p>
      </Modal>
    </div>
  );
}

export default ScanHistory;
