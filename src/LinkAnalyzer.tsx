import { useState, useRef } from 'react';
import type { ScanResult, Page, ScanMode } from './types';
import { EXAMPLE_URLS, isValidUrl } from './mockData';
import { PipelineOrchestrator } from './services/pipeline/PipelineOrchestrator';
import {
  Search,
  Clipboard,
  X,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Globe,
  Lock,
  Unlock,
  ArrowRightLeft,
  Eye,
  Layers,
  Zap,
  Box,
  Sparkles,
  HelpCircle,
} from 'lucide-react';

interface Props {
  addToHistory: (r: ScanResult) => void;
  setDetailResult: (r: ScanResult | null) => void;
  showToast: (msg: string) => void;
  setPage?: (p: Page) => void;
}

export default function LinkAnalyzer({ addToHistory, setDetailResult, showToast, setPage }: Props) {
  const [url, setUrl] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('deep');
  const [error, setError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [activeLayer, setActiveLayer] = useState<number>(0);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const orchestrator = new PipelineOrchestrator();

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text);
      setError('');
    } catch {
      showToast('Unable to read clipboard.');
    }
  };

  const handleClear = () => {
    setUrl('');
    setError('');
    setResult(null);
    setProgress(0);
    setActiveLayer(0);
  };

  const handleAnalyze = async () => {
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a URL to analyze.');
      return;
    }
    if (!isValidUrl(trimmed)) {
      setError('Please enter a valid URL starting with http:// or https://');
      return;
    }
    setError('');
    setScanning(true);
    setResult(null);
    setProgress(10);
    setActiveLayer(1);

    try {
      const pResult = await orchestrator.runScan(trimmed, scanMode, 'Link Analyzer', (prog) => {
        setActiveLayer(prog.currentLayer);
        setProgress(Math.min(95, prog.currentLayer * 25));

        if ((window as any).qrshield?.sendScanProgress) {
          (window as any).qrshield.sendScanProgress(`Layer ${prog.currentLayer}`, trimmed, prog.currentLayer * 25);
        }
      });

      const legacyResult: ScanResult = {
        id: pResult.id,
        url: pResult.url,
        domain: pResult.domain,
        riskScore: pResult.riskScore,
        verdict: pResult.verdict,
        scanType: 'link',
        timestamp: pResult.startTime,
        https: pResult.url.startsWith('https://'),
        redirects: pResult.layer3.redirectChain.length > 1,
        misleadingDomain: pResult.layer2.anomaliesDetected.some((a) => a.toLowerCase().includes('misleading')),
        suspiciousPatterns: pResult.layer2.anomaliesDetected,
        reputation: pResult.verdict === 'MALICIOUS' ? 'poor' : pResult.verdict === 'SUSPICIOUS' ? 'unknown' : 'good',
        reasons: pResult.reasons,
        recommendedAction: pResult.recommendedAction,
        pipelineResult: pResult,
      };

      setProgress(100);
      setResult(legacyResult);
      addToHistory(legacyResult);

      if ((window as any).qrshield?.sendScanResult) {
        (window as any).qrshield.sendScanResult(pResult.verdict, pResult.riskScore, pResult.url);
      }
    } catch {
      setError('Pipeline execution error.');
    } finally {
      setScanning(false);
      setActiveLayer(0);
    }
  };

  const verdictIcon = (v: string) => {
    if (v === 'SAFE' || v === 'NO THREAT DETECTED') return <CheckCircle size={16} style={{ color: 'var(--green)' }} />;
    if (v === 'CAUTION' || v === 'SUSPICIOUS') return <AlertTriangle size={16} style={{ color: 'var(--amber)' }} />;
    if (v === 'INCONCLUSIVE') return <HelpCircle size={16} style={{ color: '#94a3b8' }} />;
    return <XCircle size={16} style={{ color: 'var(--red)' }} />;
  };

  const riskClass = (r: ScanResult) => {
    if (r.verdict === 'MALICIOUS' || r.verdict === 'HIGH RISK') return 'high-risk';
    if (r.verdict === 'SUSPICIOUS' || r.verdict === 'CAUTION') return 'caution';
    if (r.verdict === 'INCONCLUSIVE') return 'text-muted';
    return 'safe';
  };

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Link Analyzer</h2>
          <p>Inspect URLs using the Four-Layer Security Architecture</p>
        </div>
        <div className="sidebar-demo-badge" style={{ fontSize: 11 }}>
          DEMO MODE
        </div>
      </div>

      {/* Input & Mode Selection Card */}
      <div className="card mb-20">
        <div className="flex justify-between items-center mb-12">
          <span className="text-xs uppercase text-muted font-bold tracking-wider">Target URL</span>
          <div className="flex gap-6 items-center">
            <span className="text-xs text-muted">Analysis Depth:</span>
            <div className="flex gap-4">
              <button
                className={`btn btn-small ${scanMode === 'quick' ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 11, padding: '3px 10px' }}
                onClick={() => setScanMode('quick')}
              >
                <Zap size={12} /> Quick Scan (L1-L2)
              </button>
              <button
                className={`btn btn-small ${scanMode === 'deep' ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 11, padding: '3px 10px' }}
                onClick={() => setScanMode('deep')}
              >
                <Layers size={12} /> Deep Scan (L1-L4)
              </button>
            </div>
          </div>
        </div>

        <div className="flex gap-8 mb-12">
          <input
            ref={inputRef}
            className="input"
            placeholder="https://example.com/verify-identity..."
            value={url}
            onChange={(e) => { setUrl(e.target.value); setError(''); }}
            onKeyDown={(e) => { if (e.key === 'Enter') handleAnalyze(); }}
            aria-label="URL input"
          />
          <button className="btn" onClick={handlePaste} title="Paste from clipboard">
            <Clipboard size={14} />
          </button>
          <button className="btn" onClick={handleClear} title="Clear">
            <X size={14} />
          </button>
        </div>

        {error && (
          <div style={{ fontSize: 11.5, color: 'var(--red)', marginBottom: 10 }}>{error}</div>
        )}

        <div className="flex gap-8 mb-16">
          <button className="btn btn-primary" onClick={handleAnalyze} disabled={scanning}>
            <Search size={14} /> {scanning ? `Scanning Layer ${activeLayer}...` : `Analyze URL (${scanMode === 'deep' ? '4-Layer Deep' : 'Quick'})`}
          </button>
        </div>

        {/* Example URLs */}
        <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.6px', fontWeight: 600 }}>
          Test Presets (Phishing, Malware & Clean)
        </div>
        <div className="flex gap-8" style={{ flexWrap: 'wrap' }}>
          {EXAMPLE_URLS.map((eu) => (
            <button
              key={eu}
              className="btn btn-small"
              onClick={() => { setUrl(eu); setError(''); setResult(null); }}
            >
              {eu.length > 40 ? eu.slice(0, 37) + '…' : eu}
            </button>
          ))}
        </div>
      </div>

      {/* Real-time 4-layer progress during scan */}
      {scanning && (
        <div className="card mb-20">
          <div className="card-title scanning-pulse flex justify-between items-center">
            <span>Executing Four-Layer Inspection Pipeline...</span>
            <span className="text-xs text-muted">Layer {activeLayer} of {scanMode === 'deep' ? 4 : 2}</span>
          </div>
          <div className="progress-bar-track mb-12">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>

          <div className="grid-4 gap-8" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
            <div className={`p-8 rounded text-xs border ${activeLayer >= 1 ? 'border-red bg-dark text-white' : 'border-dark text-muted'}`}>
              <strong>1. Safe Browsing</strong>: {activeLayer === 1 ? 'Looking up...' : activeLayer > 1 ? 'Passed' : 'Pending'}
            </div>
            <div className={`p-8 rounded text-xs border ${activeLayer >= 2 ? 'border-red bg-dark text-white' : 'border-dark text-muted'}`}>
              <strong>2. URL Classifier</strong>: {activeLayer === 2 ? 'Analyzing...' : activeLayer > 2 ? 'Classified' : 'Pending'}
            </div>
            <div className={`p-8 rounded text-xs border ${activeLayer >= 3 ? 'border-red bg-dark text-white' : 'border-dark text-muted'}`}>
              <strong>3. Sandbox</strong>: {scanMode === 'quick' ? 'Skipped' : activeLayer === 3 ? 'Detonating...' : activeLayer > 3 ? 'Completed' : 'Pending'}
            </div>
            <div className={`p-8 rounded text-xs border ${activeLayer >= 4 ? 'border-red bg-dark text-white' : 'border-dark text-muted'}`}>
              <strong>4. Gemini AI</strong>: {scanMode === 'quick' ? 'Skipped' : activeLayer === 4 ? 'Reasoning...' : 'Pending'}
            </div>
          </div>
        </div>
      )}

      {/* Result Card */}
      {result && !scanning && (
        <div className="card mb-20">
          <div className="card-title flex justify-between items-center">
            <span>Scan Result & Verdict</span>
            <span className="text-xs text-muted font-mono">{result.pipelineResult?.scanMode.toUpperCase()} SCAN</span>
          </div>

          <div className="flex items-center gap-14 mb-16">
            <div className={`risk-score-circle ${riskClass(result)}`}>
              {result.riskScore}
            </div>
            <div>
              <div className="flex items-center gap-8 mb-4">
                {verdictIcon(result.verdict)}
                <span className={`risk-badge ${riskClass(result)}`} style={result.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}>
                  {result.verdict}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Computed Risk Score: <strong>{result.riskScore}</strong> / 100 {result.riskScore === 0 ? '(0 != guaranteed safe)' : ''}
              </div>
            </div>
          </div>

          {/* Details breakdown */}
          <div className="detail-section">
            <h4>Target Breakdown</h4>
            <div className="detail-row">
              <span className="label"><Globe size={12} style={{ marginRight: 4 }} />Domain</span>
              <span className="value font-mono">{result.domain}</span>
            </div>
            <div className="detail-row">
              <span className="label">{result.https ? <Lock size={12} style={{ marginRight: 4 }} /> : <Unlock size={12} style={{ marginRight: 4 }} />}HTTPS Scheme</span>
              <span className="value" style={{ color: result.https ? 'var(--green)' : 'var(--red)' }}>
                {result.https ? 'Secured' : 'Insecure (HTTP)'}
              </span>
            </div>
            <div className="detail-row">
              <span className="label"><ArrowRightLeft size={12} style={{ marginRight: 4 }} />Redirects</span>
              <span className="value" style={{ color: result.redirects ? 'var(--amber)' : 'var(--green)' }}>
                {result.redirects ? 'Multiple Hops Observed' : 'Direct Target'}
              </span>
            </div>
            <div className="detail-row">
              <span className="label"><Eye size={12} style={{ marginRight: 4 }} />Reputation Intelligence</span>
              <span className="value">{result.reputation.toUpperCase()}</span>
            </div>
          </div>

          {/* Analysis Reasons */}
          <div className="detail-section">
            <h4>Pipeline Reasons & Evidence</h4>
            <ul className="detail-reasons">
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          <div className="inline-notice mb-16">
            <AlertTriangle />
            <span>Recommended Action: <strong>{result.recommendedAction}</strong></span>
          </div>

          {/* Action buttons */}
          <div className="flex gap-8 flex-wrap">
            <button className="btn btn-primary" onClick={() => { setDetailResult(result); setPage?.('scan-details'); }}>
              <Layers size={14} /> Full 4-Layer Details
            </button>
            <button className="btn" onClick={() => { setDetailResult(result); setPage?.('sandbox-evidence'); }}>
              <Box size={14} /> Sandbox Evidence
            </button>
            <button className="btn" onClick={() => { setDetailResult(result); setPage?.('ai-report'); }}>
              <Sparkles size={14} /> Gemini Threat Report
            </button>
            <button className="btn btn-ghost" onClick={() => { setResult(null); handleAnalyze(); }}>
              <RefreshCw size={14} /> Scan Again
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
