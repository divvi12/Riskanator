import {
  SkeletonText,
  SkeletonPlaceholder,
  DataTableSkeleton,
  Tile
} from '@carbon/react';

// Dashboard card skeleton
export function DashboardCardSkeleton() {
  return (
    <Tile style={{ padding: '1.5rem' }}>
      <SkeletonText heading width="60%" />
      <div style={{ marginTop: '1rem' }}>
        <SkeletonText paragraph lineCount={2} />
      </div>
      <div style={{ marginTop: '1rem' }}>
        <SkeletonPlaceholder style={{ height: '60px', width: '100%' }} />
      </div>
    </Tile>
  );
}

// Stats card skeleton for Dashboard
export function StatsCardSkeleton() {
  return (
    <Tile style={{ padding: '1rem', textAlign: 'center' }}>
      <div style={{ margin: '0 auto', width: '40%' }}>
        <SkeletonText width="100%" />
      </div>
      <SkeletonPlaceholder style={{ height: '48px', width: '80px', margin: '0.5rem auto' }} />
      <div style={{ margin: '0 auto', width: '60%' }}>
        <SkeletonText width="100%" />
      </div>
    </Tile>
  );
}

// Chart skeleton
export function ChartSkeleton({ height = 300 }: { height?: number }) {
  return (
    <Tile style={{ padding: '1.5rem' }}>
      <SkeletonText heading width="40%" />
      <SkeletonPlaceholder style={{ height: `${height}px`, width: '100%', marginTop: '1rem' }} />
    </Tile>
  );
}

// Table skeleton with configurable rows
export function TableSkeleton({
  rowCount = 5,
  columnCount = 5,
  showHeader = true,
  showToolbar = true
}: {
  rowCount?: number;
  columnCount?: number;
  showHeader?: boolean;
  showToolbar?: boolean;
}) {
  return (
    <DataTableSkeleton
      rowCount={rowCount}
      columnCount={columnCount}
      showHeader={showHeader}
      showToolbar={showToolbar}
    />
  );
}

// Exposure detail skeleton
export function ExposureDetailSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <Tile style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1 }}>
            <SkeletonText heading width="70%" />
            <div style={{ marginTop: '0.5rem' }}>
              <SkeletonText width="40%" />
            </div>
          </div>
          <SkeletonPlaceholder style={{ height: '40px', width: '100px' }} />
        </div>
        <div style={{ marginTop: '1.5rem' }}>
          <SkeletonText paragraph lineCount={3} />
        </div>
      </Tile>
      <Tile style={{ padding: '1.5rem' }}>
        <SkeletonText heading width="30%" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginTop: '1rem' }}>
          <SkeletonPlaceholder style={{ height: '60px' }} />
          <SkeletonPlaceholder style={{ height: '60px' }} />
          <SkeletonPlaceholder style={{ height: '60px' }} />
        </div>
      </Tile>
    </div>
  );
}

// Remediation group skeleton
export function RemediationGroupSkeleton() {
  return (
    <Tile style={{ padding: '1.5rem', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <SkeletonText heading width="50%" />
        <SkeletonPlaceholder style={{ height: '32px', width: '120px' }} />
      </div>
      <SkeletonText paragraph lineCount={2} />
      <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
        <SkeletonPlaceholder style={{ height: '24px', width: '80px' }} />
        <SkeletonPlaceholder style={{ height: '24px', width: '80px' }} />
        <SkeletonPlaceholder style={{ height: '24px', width: '80px' }} />
      </div>
    </Tile>
  );
}

// Arena node skeleton
export function ArenaNodeSkeleton() {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
      gap: '1rem',
      padding: '1rem'
    }}>
      {Array.from({ length: 8 }).map((_, i) => (
        <Tile key={i} style={{ padding: '1rem', textAlign: 'center' }}>
          <SkeletonPlaceholder style={{ height: '48px', width: '48px', margin: '0 auto', borderRadius: '50%' }} />
          <div style={{ margin: '0.5rem auto 0', width: '60%' }}>
            <SkeletonText width="100%" />
          </div>
          <div style={{ margin: '0.25rem auto 0', width: '40%' }}>
            <SkeletonText width="100%" />
          </div>
        </Tile>
      ))}
    </div>
  );
}

// Settings form skeleton
export function SettingsFormSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i}>
          <SkeletonText width="20%" />
          <SkeletonPlaceholder style={{ height: '40px', width: '100%', marginTop: '0.5rem' }} />
        </div>
      ))}
      <SkeletonPlaceholder style={{ height: '40px', width: '120px', marginTop: '1rem' }} />
    </div>
  );
}

// Full page loading skeleton
export function PageLoadingSkeleton() {
  return (
    <div style={{ padding: '2rem' }}>
      <div style={{ marginBottom: '2rem' }}>
        <SkeletonText heading width="30%" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        <StatsCardSkeleton />
        <StatsCardSkeleton />
        <StatsCardSkeleton />
        <StatsCardSkeleton />
      </div>
      <ChartSkeleton height={400} />
    </div>
  );
}

// Inline loading indicator
export function InlineLoadingIndicator({ description = 'Loading...' }: { description?: string }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '1rem',
      color: '#c6c6c6'
    }}>
      <div className="loading-spinner" style={{
        width: '16px',
        height: '16px',
        border: '2px solid #525252',
        borderTop: '2px solid #0f62fe',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite'
      }} />
      <span>{description}</span>
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default {
  DashboardCardSkeleton,
  StatsCardSkeleton,
  ChartSkeleton,
  TableSkeleton,
  ExposureDetailSkeleton,
  RemediationGroupSkeleton,
  ArenaNodeSkeleton,
  SettingsFormSkeleton,
  PageLoadingSkeleton,
  InlineLoadingIndicator
};
