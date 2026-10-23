import { useState, useEffect } from 'react';
import type { ScanResult } from './types';
import { Shield, X, ShieldAlert, ShieldCheck, HelpCircle } from 'lucide-react';

interface Props {
  pos: { x: number; y: number };
  scanning: boolean;
  result: ScanResult | null;
  onClose: () => void;
  onDetails: (r: ScanResult) => void;
}

export default function FloatingPanel({ pos, scanning, result, onClose, onDetails }: Props) {
  const [progress, setProgress] = useState(0);

  // Animate progress while scanning
  useEffect(() => {
    if (!scanning) {
      setProgress(100);
      return;
    }
    setProgress(0);
    const interval = setInterval(() => {
      setProgress((p) => {
        if (p >= 90) { clearInterval(interval); return 90; }
        return p + Math.random() * 12;
      });
    }, 150);
    return () => clearInterval(interval);
  }, [scanning]);

  // Clamp position within viewport
  const clampedX = Math.max(8, Math.min(pos.x, window.innerWidth - 360));
  const clampedY = Math.max(8, Math.min(pos.y, window.innerHeight - 340));

  const getVerdictState = (verdict: string) => {
    switch (verdict) {
      case 'MALICIOUS':
      case 'HIGH RISK':
        return { text: 'BLOCKED', color: 'var(--red)', badgeClass: 'high-risk', icon: <ShieldAlert size={12} /> };
      case 'SUSPICIOUS':
      case 'CAUTION':
        return { text: 'SUSPICIOUS', color: 'var(--amber)', badgeClass: 'caution', icon: <ShieldAlert size={12} /> };
      case 'INCONCLUSIVE':
        return { text: 'INCONCLUSIVE', color: '#94a3b8', badgeClass: 'text-muted', icon: <HelpCircle size={12} /> };
      case 'NO THREAT DETECTED':
      case 'SAFE':
      default:
        return { text: 'ALLOWED', color: 'var(--green)', badgeClass: 'safe', icon: <ShieldCheck size={12} /> };
    }
  };

  const vState = result ? getVerdictState(result.verdict) : null;

  return (
    <div className="floating-panel" style={{ left: clampedX, top: clampedY }}>
      <div className="fp-header">
        <span><Shield size={12} style={{ marginRight: 4, verticalAlign: -2 }} />QRShield Inspection</span>
        <button className="btn btn-ghost btn-small" onClick={onClose} aria-label="Close" style={{ padding: 2 }}>
          <X size={14} />
        </button>
      </div>

      {scanning && (
        <>
          <div className="fp-status scanning-pulse">Executing 4-layer inspection…</div>
          <div className="fp-bar-track">
            <div className="fp-bar-fill" style={{ width: `${progress}%`, background: 'var(--red)' }} />
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 6 }}>
            Safe Browsing &rarr; URL Heuristics &rarr; Sandbox &rarr; Gemini
          </div>
        </>
      )}

      {!scanning && result && vState && (
        <>
          <div className="fp-bar-track">
            <div className="fp-bar-fill" style={{ width: '100%', background: vState.color }} />
          </div>

          <div className="fp-result-row" style={{ marginTop: 10 }}>
            <span className="label">Interception Status</span>
            <span
              className={`risk-badge ${vState.badgeClass}`}
              style={result.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}
            >
              {vState.icon} {vState.text}
            </span>
          </div>

          <div className="fp-result-row">
            <span className="label">Risk Score</span>
            <span style={{ fontWeight: 700, color: vState.color }}>{result.riskScore} / 100</span>
          </div>

          <div className="fp-result-row">
            <span className="label">Destination</span>
            <span className="font-mono text-xs">{result.domain}</span>
          </div>

          {result.reasons.length > 0 && (
            <ul className="fp-reasons">
              {result.reasons.slice(0, 2).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}

          <div className="fp-actions">
            <button className="btn btn-small btn-primary" onClick={() => onDetails(result)}>
              Open Full Report
            </button>
            <button className="btn btn-small" onClick={onClose}>
              Dismiss
            </button>
          </div>
        </>
      )}
    </div>
  );
}
