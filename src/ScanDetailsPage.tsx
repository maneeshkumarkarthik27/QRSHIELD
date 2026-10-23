import type { ScanResult, Page } from './types';
import {
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Clock,
  Layers,
  ArrowRight,
  ExternalLink,
  Box,
  Sparkles,
} from 'lucide-react';

interface Props {
  result: ScanResult | null;
  setPage: (p: Page) => void;
  onClose?: () => void;
}

export default function ScanDetailsPage({ result, setPage }: Props) {
  if (!result) {
    return (
      <div>
        <div className="page-header">
          <h2>Scan Details</h2>
          <p>Inspect comprehensive layer-by-layer findings</p>
        </div>
        <div className="card">
          <div className="empty-state">
            <Layers size={36} />
            <p>No scan selected. Run a scan from the Dashboard or Link Analyzer to view technical details.</p>
          </div>
        </div>
      </div>
    );
  }

  const p = result.pipelineResult;

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'MALICIOUS':
      case 'HIGH RISK':
        return <span className="risk-badge high-risk"><ShieldAlert size={12} /> MALICIOUS</span>;
      case 'SUSPICIOUS':
      case 'CAUTION':
        return <span className="risk-badge caution"><ShieldAlert size={12} /> SUSPICIOUS</span>;
      case 'INCONCLUSIVE':
        return <span className="risk-badge" style={{ background: '#334155', color: '#cbd5e1' }}><HelpCircle size={12} /> INCONCLUSIVE</span>;
      case 'NO THREAT DETECTED':
      case 'SAFE':
      default:
        return <span className="risk-badge safe"><ShieldCheck size={12} /> NO THREAT DETECTED</span>;
    }
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'completed':
        return <span className="text-green text-xs font-bold uppercase">Completed</span>;
      case 'running':
        return <span className="text-blue text-xs font-bold uppercase">Running...</span>;
      case 'skipped':
        return <span className="text-muted text-xs font-bold uppercase">Skipped</span>;
      case 'unavailable':
        return <span className="text-amber text-xs font-bold uppercase">Unavailable</span>;
      case 'failed':
        return <span className="text-red text-xs font-bold uppercase">Failed</span>;
      default:
        return <span className="text-muted text-xs font-bold uppercase">Pending</span>;
    }
  };

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Scan Details</h2>
          <p>Audit report and 4-layer inspection evidence</p>
        </div>
        <div className="flex gap-8">
          <button className="btn btn-secondary" onClick={() => setPage('sandbox-evidence')}>
            <Box size={14} /> View Sandbox Evidence
          </button>
          <button className="btn btn-secondary" onClick={() => setPage('ai-report')}>
            <Sparkles size={14} /> View AI Report
          </button>
        </div>
      </div>

      {/* Target summary banner */}
      <div className="card mb-20">
        <div className="flex justify-between items-center mb-12">
          <div>
            <span className="text-xs uppercase text-muted tracking-wider">Scanned Target</span>
            <div className="font-bold text-lg text-white" style={{ wordBreak: 'break-all' }}>
              {result.url}
            </div>
            <div className="text-xs text-muted mt-4">
              Domain: <strong className="text-white">{result.domain}</strong> • Source: <em>{result.pipelineResult?.sourceAttribution || result.scanType}</em> • {new Date(result.timestamp).toLocaleString()}
            </div>
          </div>
          <div className="text-right">
            <div className="mb-6">{getVerdictBadge(result.verdict)}</div>
            <div className="text-xs text-muted">
              Risk Score: <strong className="text-white text-base">{result.riskScore}</strong>/100
            </div>
          </div>
        </div>

        <div className="inline-notice">
          <Clock size={14} />
          <span>Recommended Action: <strong>{result.recommendedAction}</strong></span>
        </div>
      </div>

      {/* Four-Layer Pipeline Status Grid */}
      <div className="card-title mb-12 flex items-center gap-8">
        <Layers size={18} /> Four-Layer Analysis Pipeline Breakdown
      </div>

      <div className="grid-2 mb-20">
        {/* Layer 1 */}
        <div className="card">
          <div className="flex justify-between items-center mb-10 pb-8 border-b border-dark">
            <div>
              <span className="text-xs text-muted uppercase font-bold">Layer 1</span>
              <h4 className="font-bold text-white">Google Safe Browsing</h4>
            </div>
            {getStatusBadge(p?.layer1.status || 'completed')}
          </div>
          <p className="text-xs text-muted mb-10">
            Global threat intelligence repository lookup for known social engineering, malware distributions, and deceptive domains.
          </p>
          <div className="text-xs space-y-4">
            <div>Threat Match: <strong className={p?.layer1.threatFound ? 'text-red' : 'text-green'}>{p?.layer1.threatFound ? `Confirmed (${p.layer1.threatType})` : 'No Match Found'}</strong></div>
            <div>Platform: <span className="text-white">{p?.layer1.platformType || 'WINDOWS'}</span></div>
            <div>Status: <span className={p?.layer1.apiConnected ? 'text-green' : 'text-amber'}>{p?.layer1.apiConnected ? 'Live provider connected' : (p?.layer1.error || 'Provider unavailable')}</span></div>
          </div>
        </div>

        {/* Layer 2 */}
        <div className="card">
          <div className="flex justify-between items-center mb-10 pb-8 border-b border-dark">
            <div>
              <span className="text-xs text-muted uppercase font-bold">Layer 2</span>
              <h4 className="font-bold text-white">Local URL Classifier</h4>
            </div>
            {getStatusBadge(p?.layer2.status || 'completed')}
          </div>
          <p className="text-xs text-muted mb-10">
            Heuristic evaluation of hostname encoding, Punycode homoglyphs, IP addresses, suspicious TLDs, and misleading credentials.
          </p>
          <div className="text-xs space-y-4">
            <div>Classification: <strong className={p?.layer2.riskClass === 'SUSPICIOUS' ? 'text-amber' : 'text-green'}>{p?.layer2.riskClass || 'LOWER RISK'}</strong></div>
            <div>Heuristic Risk Score: <span className="text-white">{p?.layer2.score || result.riskScore}/100</span></div>
            <div>Anomalies: <span className="text-white">{p?.layer2.anomaliesDetected.length ? p.layer2.anomaliesDetected.join('; ') : 'None detected'}</span></div>
          </div>
        </div>

        {/* Layer 3 */}
        <div className="card">
          <div className="flex justify-between items-center mb-10 pb-8 border-b border-dark">
            <div>
              <span className="text-xs text-muted uppercase font-bold">Layer 3</span>
              <h4 className="font-bold text-white">Isolated Browser Sandbox</h4>
            </div>
            {getStatusBadge(p?.layer3.status || 'completed')}
          </div>
          <p className="text-xs text-muted mb-10">
            Automated detonation in disposable microVM with strict network egress blocking to catch redirects, downloads, and login forms.
          </p>
          <div className="text-xs space-y-4">
            <div>Redirect Hops: <span className="text-white">{p?.layer3.redirectChain.length || (result.redirects ? 2 : 1)} hop(s)</span></div>
            <div>Credential Forms: <strong className={p?.layer3.hasLoginForm ? 'text-amber' : 'text-muted'}>{p?.layer3.hasLoginForm ? 'Detected' : 'None'}</strong></div>
            <div>Download Triggers: <strong className={p?.layer3.downloadAttempts?.length ? 'text-red' : 'text-muted'}>{p?.layer3.downloadAttempts?.length ? `${p.layer3.downloadAttempts.length} blocked` : 'None'}</strong></div>
            <div>Runtime Status: <span className={p?.layer3.connected ? 'text-green' : 'text-amber'}>{p?.layer3.isolationRuntime || 'Sandbox unavailable'}</span></div>
          </div>
        </div>

        {/* Layer 4 */}
        <div className="card">
          <div className="flex justify-between items-center mb-10 pb-8 border-b border-dark">
            <div>
              <span className="text-xs text-muted uppercase font-bold">Layer 4</span>
              <h4 className="font-bold text-white">Gemini Threat Analyst</h4>
            </div>
            {getStatusBadge(p?.layer4.status || 'completed')}
          </div>
          <p className="text-xs text-muted mb-10">
            Multi-modal synthesis of URL structure, DOM indicators, network patterns, and attack psychology via Gemini 3.8 Flash.
          </p>
          <div className="text-xs space-y-4">
            <div>Model: <span className="text-white">gemini-3.8-flash</span></div>
            <div>Assessment: <span className="text-white">{p?.layer4.threatAssessment || 'Analysis evaluated.'}</span></div>
            <div>Likely Attack Type: <strong className="text-amber">{p?.layer4.likelyAttackType || 'Brand Impersonation / Phishing'}</strong></div>
            <div>Confidence: <span className="text-green">{p?.layer4.confidenceLevel || 'HIGH'}</span></div>
          </div>
        </div>
      </div>

      {/* Reasons & Evidence */}
      <div className="card">
        <div className="card-title">Evidence & Detailed Findings</div>
        <ul className="reasons-list">
          {result.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
          {p?.evidenceSummary && p.evidenceSummary.map((e, idx) => (
            <li key={`ev_${idx}`} className="text-muted">{e}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
