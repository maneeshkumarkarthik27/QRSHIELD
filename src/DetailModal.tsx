import type { ScanResult } from './types';
import {
  X,
  Globe,
  Lock,
  Unlock,
  ArrowRightLeft,
  Eye,
  Copy,
  AlertTriangle,
  CheckCircle,
  XCircle,
  HelpCircle,
  Clock,
  Layers,
} from 'lucide-react';

interface Props {
  result: ScanResult;
  onClose: () => void;
  showToast: (msg: string) => void;
  onViewFullReport?: () => void;
}

export default function DetailModal({ result, onClose, showToast, onViewFullReport }: Props) {
  const riskClass =
    result.verdict === 'MALICIOUS' || result.verdict === 'HIGH RISK'
      ? 'high-risk'
      : result.verdict === 'SUSPICIOUS' || result.verdict === 'CAUTION'
      ? 'caution'
      : result.verdict === 'INCONCLUSIVE'
      ? 'text-muted'
      : 'safe';

  const verdictIcon =
    result.verdict === 'MALICIOUS' || result.verdict === 'HIGH RISK' ? (
      <XCircle size={18} style={{ color: 'var(--red)' }} />
    ) : result.verdict === 'SUSPICIOUS' || result.verdict === 'CAUTION' ? (
      <AlertTriangle size={18} style={{ color: 'var(--amber)' }} />
    ) : result.verdict === 'INCONCLUSIVE' ? (
      <HelpCircle size={18} style={{ color: '#94a3b8' }} />
    ) : (
      <CheckCircle size={18} style={{ color: 'var(--green)' }} />
    );

  const copyUrl = async () => {
    try {
      await navigator.clipboard.writeText(result.url);
      showToast('URL copied to clipboard.');
    } catch {
      showToast('Failed to copy URL.');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-16">
          <h3 style={{ margin: 0 }}>Security Inspection Details</h3>
          <button className="btn btn-ghost btn-small" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        {/* Score + verdict */}
        <div className="flex items-center gap-10 mb-20">
          <div className={`risk-score-circle ${riskClass}`}>
            {result.riskScore}
          </div>
          <div>
            <div className="flex items-center gap-8 mb-4">
              {verdictIcon}
              <span
                className={`risk-badge ${riskClass}`}
                style={result.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}
              >
                {result.verdict}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Risk Score: <strong>{result.riskScore}</strong> / 100
            </div>
          </div>
        </div>

        {/* URL */}
        <div className="detail-section">
          <h4>Inspected URL Target</h4>
          <div className="flex items-center gap-8 font-mono" style={{ wordBreak: 'break-all', fontSize: 12, color: 'var(--text-primary)' }}>
            <span style={{ flex: 1 }}>{result.url}</span>
            <button className="btn btn-ghost btn-small" onClick={copyUrl} title="Copy URL">
              <Copy size={12} />
            </button>
          </div>
        </div>

        {/* Domain info */}
        <div className="detail-section">
          <h4>Domain Intelligence</h4>
          <div className="detail-row">
            <span className="label"><Globe size={12} style={{ marginRight: 4 }} />Domain</span>
            <span className="value font-mono">{result.domain}</span>
          </div>
          <div className="detail-row">
            <span className="label">{result.https ? <Lock size={12} style={{ marginRight: 4 }} /> : <Unlock size={12} style={{ marginRight: 4 }} />}HTTPS Scheme</span>
            <span className="value" style={{ color: result.https ? 'var(--green)' : 'var(--red)' }}>
              {result.https ? 'Encrypted (HTTPS)' : 'Insecure (HTTP)'}
            </span>
          </div>
          <div className="detail-row">
            <span className="label"><ArrowRightLeft size={12} style={{ marginRight: 4 }} />Redirect Check</span>
            <span className="value" style={{ color: result.redirects ? 'var(--amber)' : 'var(--green)' }}>
              {result.redirects ? 'Redirects Detected' : 'Direct Target'}
            </span>
          </div>
          <div className="detail-row">
            <span className="label"><Eye size={12} style={{ marginRight: 4 }} />Reputation</span>
            <span className="value" style={{
              color: result.reputation === 'good' ? 'var(--green)' : result.reputation === 'poor' ? 'var(--red)' : 'var(--amber)'
            }}>
              {result.reputation.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Reasons */}
        <div className="detail-section">
          <h4>Findings & Attack Indicators</h4>
          <ul className="detail-reasons">
            {result.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>

        {/* Recommended action */}
        <div className="detail-section">
          <h4>Recommended Protective Action</h4>
          <p style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.6 }}>
            {result.recommendedAction}
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex gap-8 mt-16">
          {onViewFullReport && (
            <button
              className="btn btn-primary"
              onClick={() => {
                onClose();
                onViewFullReport();
              }}
            >
              <Layers size={14} /> Open 4-Layer Report
            </button>
          )}
          <button className="btn btn-ghost" onClick={onClose}>
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
