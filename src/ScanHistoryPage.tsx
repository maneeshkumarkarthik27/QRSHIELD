import { useState } from 'react';
import type { ScanResult, Verdict, Page } from './types';
import {
  Search,
  Trash2,
  Clock,
  AlertTriangle,
  Layers,
} from 'lucide-react';

interface Props {
  history: ScanResult[];
  clearHistory: () => void;
  setDetailResult: (r: ScanResult | null) => void;
  setPage?: (p: Page) => void;
}

const FILTERS: Array<{ label: string; value: string }> = [
  { label: 'All', value: 'all' },
  { label: 'Malicious', value: 'MALICIOUS' },
  { label: 'Suspicious', value: 'SUSPICIOUS' },
  { label: 'Inconclusive', value: 'INCONCLUSIVE' },
  { label: 'No Threat', value: 'NO THREAT DETECTED' },
];

export default function ScanHistoryPage({ history, clearHistory, setDetailResult, setPage }: Props) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filter, setFilter] = useState<string>('all');
  const [confirmClear, setConfirmClear] = useState(false);

  const filtered = history.filter((item) => {
    if (filter !== 'all') {
      if (filter === 'MALICIOUS' && item.verdict !== 'MALICIOUS' && item.verdict !== 'HIGH RISK') return false;
      if (filter === 'SUSPICIOUS' && item.verdict !== 'SUSPICIOUS' && item.verdict !== 'CAUTION') return false;
      if (filter === 'INCONCLUSIVE' && item.verdict !== 'INCONCLUSIVE') return false;
      if (filter === 'NO THREAT DETECTED' && item.verdict !== 'NO THREAT DETECTED' && item.verdict !== 'SAFE') return false;
    }
    if (searchTerm && !item.url.toLowerCase().includes(searchTerm.toLowerCase()) && !item.domain.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const riskClass = (v: Verdict) => {
    if (v === 'MALICIOUS' || v === 'HIGH RISK') return 'high-risk';
    if (v === 'SUSPICIOUS' || v === 'CAUTION') return 'caution';
    if (v === 'INCONCLUSIVE') return 'text-muted';
    return 'safe';
  };

  return (
    <div>
      <div className="page-header">
        <div className="flex items-center justify-between">
          <div>
            <h2>Scan History</h2>
            <p>{history.length} total scan{history.length !== 1 ? 's' : ''} recorded across Windows sessions</p>
          </div>
          <button
            className="btn"
            onClick={() => setConfirmClear(true)}
            disabled={history.length === 0}
          >
            <Trash2 size={14} /> Clear History
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-10 mb-16" style={{ flexWrap: 'wrap' }}>
        <div className="search-wrapper" style={{ width: 280 }}>
          <Search />
          <input
            className="input"
            placeholder="Search by URL or domain…"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            aria-label="Search scan history"
          />
        </div>
        <div className="filter-row">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              className={`filter-chip ${filter === f.value ? 'active' : ''}`}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            {history.length === 0 ? (
              <>
                <Clock size={32} />
                <p>No scans recorded yet.<br />Use the Link Analyzer, QR Scanner, or Cursor Protection to get started.</p>
              </>
            ) : (
              <>
                <Search size={32} />
                <p>No results match your search or filter.</p>
              </>
            )}
          </div>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Domain</th>
                <th>Source</th>
                <th>Risk Score</th>
                <th>Final Verdict</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={r.id}>
                  <td style={{ whiteSpace: 'nowrap' }} className="text-xs text-muted">
                    {new Date(r.timestamp).toLocaleString()}
                  </td>
                  <td title={r.url} className="font-mono text-xs">{r.domain}</td>
                  <td style={{ textTransform: 'uppercase', fontSize: 10, fontWeight: 600, letterSpacing: '.5px' }}>
                    {r.pipelineResult?.sourceAttribution || r.scanType}
                  </td>
                  <td>
                    <strong>{r.riskScore}</strong>/100
                  </td>
                  <td>
                    <span
                      className={`risk-badge ${riskClass(r.verdict)}`}
                      style={r.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}
                    >
                      {r.verdict}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn btn-small btn-ghost"
                      onClick={() => {
                        setDetailResult(r);
                        if (setPage) setPage('scan-details');
                      }}
                    >
                      Details &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Clear confirmation modal */}
      {confirmClear && (
        <div className="modal-overlay" onClick={() => setConfirmClear(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()} style={{ width: 380 }}>
            <div className="confirm-dialog">
              <AlertTriangle size={32} style={{ color: 'var(--amber)', marginBottom: 12 }} />
              <h3>Clear Scan History?</h3>
              <p>This will permanently remove all {history.length} scan records from local storage. This action cannot be undone.</p>
              <div className="btn-row">
                <button className="btn" onClick={() => setConfirmClear(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={() => { clearHistory(); setConfirmClear(false); }}>
                  <Trash2 size={14} /> Clear All
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
