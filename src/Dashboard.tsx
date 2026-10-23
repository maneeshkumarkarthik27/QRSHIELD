import { useState } from 'react';
import type { ScanResult, AppSettings, Page } from './types';
import { DEMO_LINKS } from './mockData';
import { PipelineOrchestrator } from './services/pipeline/PipelineOrchestrator';
import {
  Shield,
  ShieldOff,
  Link2,
  AlertTriangle,
  QrCode,
  Search,
  MousePointer2,
  ExternalLink,
  Clock,
  Layers,
  Cpu,
  HelpCircle,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';

interface Props {
  settings: AppSettings;
  updateSetting: <K extends keyof AppSettings>(k: K, v: AppSettings[K]) => void;
  history: ScanResult[];
  cursorActive: boolean;
  helperConnected: boolean;
  setPage: (p: Page) => void;
  setCursorActive: (v: boolean) => void;
  addToHistory: (r: ScanResult) => void;
  setFloatingResult: (r: ScanResult | null) => void;
  setFloatingPos: (p: { x: number; y: number }) => void;
  setFloatingScanning: (v: boolean) => void;
  setDetailResult: (r: ScanResult | null) => void;
  showToast: (msg: string) => void;
}

export default function Dashboard({
  settings,
  updateSetting,
  history,
  cursorActive,
  helperConnected,
  setPage,
  setCursorActive,
  addToHistory,
  setFloatingResult,
  setFloatingPos,
  setFloatingScanning,
  setDetailResult,
  showToast,
}: Props) {
  const [activePipelineLayer, setActivePipelineLayer] = useState<number>(0);
  const [isDemoScanning, setIsDemoScanning] = useState(false);

  const totalScans = history.length;
  const blockedLinks = history.filter((h) => h.verdict === 'MALICIOUS' || h.verdict === 'HIGH RISK').length;
  const inconclusive = history.filter((h) => h.verdict === 'INCONCLUSIVE').length;
  const suspiciousCount = history.filter((h) => h.verdict === 'SUSPICIOUS' || h.verdict === 'CAUTION').length;
  const safeCount = history.filter((h) => h.verdict === 'SAFE' || h.verdict === 'NO THREAT DETECTED').length;

  const orchestrator = new PipelineOrchestrator();

  /* handle demo link click */
  const handleLinkClick = async (e: React.MouseEvent, url: string) => {
    e.preventDefault();
    e.stopPropagation();

    if (!cursorActive && !settings.protectionEnabled) {
      showToast('Activate protection first to inspect links.');
      return;
    }

    const rect = (e.target as HTMLElement).getBoundingClientRect();
    const x = Math.min(rect.left, window.innerWidth - 360);
    const y = Math.min(rect.bottom + 8, window.innerHeight - 340);
    setFloatingPos({ x, y });
    setFloatingScanning(true);
    setFloatingResult(null);
    setIsDemoScanning(true);

    try {
      const result = await orchestrator.runScan(
        url,
        settings.defaultScanMode,
        'Dashboard Test Link',
        (prog) => {
          setActivePipelineLayer(prog.currentLayer);
          if ((window as any).qrshield?.sendScanProgress) {
            (window as any).qrshield.sendScanProgress(`Layer ${prog.currentLayer}`, url, prog.currentLayer * 25);
          }
        }
      );

      const legacyResult: ScanResult = {
        id: result.id,
        url: result.url,
        domain: result.domain,
        riskScore: result.riskScore,
        verdict: result.verdict,
        scanType: 'link',
        timestamp: result.startTime,
        https: result.url.startsWith('https://'),
        redirects: result.layer3.redirectChain.length > 1,
        misleadingDomain: result.layer2.anomaliesDetected.some((a) => a.toLowerCase().includes('misleading')),
        suspiciousPatterns: result.layer2.anomaliesDetected,
        reputation: result.verdict === 'MALICIOUS' ? 'poor' : result.verdict === 'SUSPICIOUS' ? 'unknown' : 'good',
        reasons: result.reasons,
        recommendedAction: result.recommendedAction,
        pipelineResult: result,
      };

      setFloatingScanning(false);
      setFloatingResult(legacyResult);
      addToHistory(legacyResult);

      if ((window as any).qrshield?.sendScanResult) {
        (window as any).qrshield.sendScanResult(result.verdict, result.riskScore, result.url);
      }
    } catch {
      setFloatingScanning(false);
      showToast('Scan pipeline encountered an issue.');
    } finally {
      setIsDemoScanning(false);
      setActivePipelineLayer(0);
    }
  };

  const recentFive = history.slice(0, 5);

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Dashboard</h2>
          <p>Global Windows security telemetry and 4-layer threat status</p>
        </div>
        <div className="flex gap-8 items-center">
          <span className="sidebar-demo-badge" style={{ fontSize: 11, padding: '4px 8px' }}>
            DEMO MODE — ALL RESULTS SIMULATED
          </span>
        </div>
      </div>

      {/* Main Protection & System Status Card */}
      <div className="card mb-20">
        <div className="protection-panel">
          <div className={`protection-shield ${settings.protectionEnabled ? 'on' : 'off'}`}>
            {settings.protectionEnabled ? <Shield size={28} /> : <ShieldOff size={28} />}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
              System Protection {settings.protectionEnabled ? 'ACTIVE' : 'DISABLED'}
              {settings.protectionEnabled && (
                <span className="risk-badge safe" style={{ fontSize: 10, padding: '2px 6px' }}>
                  HOLD-{settings.shortcutKey || '5'} ARMED
                </span>
              )}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {settings.protectionEnabled
                ? 'Low-level keyboard hook active. Hold 5 anywhere in Windows to invoke the red inspection cursor.'
                : 'Global monitoring is off. Normal keystrokes and mouse clicks proceed unmonitored.'}
            </div>
          </div>
          <button
            className="toggle-switch"
            style={settings.protectionEnabled ? { background: 'var(--red)' } : {}}
            onClick={() => updateSetting('protectionEnabled', !settings.protectionEnabled)}
            aria-label="Toggle protection"
          >
            <span className="toggle-knob" style={settings.protectionEnabled ? { transform: 'translateX(18px)' } : {}} />
          </button>
        </div>

        {/* Live system telemetry strip */}
        <div style={{ padding: '0 24px 16px', display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center', borderTop: '1px solid var(--card-border)', paddingTop: 12 }}>
          <div className="status-indicator">
            <span className={`status-dot ${helperConnected ? '' : 'off'}`} />
            <Cpu size={13} />
            <span style={{ fontSize: 11.5 }}>
              Windows Helper (.NET): <strong>{helperConnected ? 'Connected (IPC Pipe Active)' : 'Active (Simulated)'}</strong>
            </span>
          </div>

          <div className="status-indicator">
            <span className={`status-dot ${cursorActive ? 'cursor-active' : 'off'}`} />
            <MousePointer2 size={13} />
            <span style={{ fontSize: 11.5 }}>
              Global Cursor Mode: <strong>{cursorActive ? 'HOLDING 5 (Red Cursor Active)' : 'Idle'}</strong>
            </span>
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Inspection Mode:</span>
            <div className="flex gap-4">
              <button
                className={`btn btn-small ${settings.defaultScanMode === 'quick' ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 10, padding: '2px 8px' }}
                onClick={() => updateSetting('defaultScanMode', 'quick')}
              >
                <Zap size={10} /> Quick Scan
              </button>
              <button
                className={`btn btn-small ${settings.defaultScanMode === 'deep' ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 10, padding: '2px 8px' }}
                onClick={() => updateSetting('defaultScanMode', 'deep')}
              >
                <Layers size={10} /> Deep Scan
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Four-Layer Scanning Pipeline Visualizer */}
      <div className="card mb-20">
        <div className="card-title flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Layers size={16} /> Four-Layer Link Analysis Pipeline
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 400 }}>
            Active Mode: <strong>{(settings.defaultScanMode || 'deep').toUpperCase()}</strong> (L1 &rarr; L2 {(settings.defaultScanMode || 'deep') === 'deep' ? '&rarr; L3 &rarr; L4' : ''})
          </span>
        </div>

        <div className="grid-4 gap-12" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {/* L1 */}
          <div className={`p-12 rounded border ${activePipelineLayer === 1 ? 'border-red bg-dark' : 'border-dark bg-dark'}`} style={{ borderLeft: '3px solid var(--blue)' }}>
            <div className="text-xs font-bold text-muted uppercase mb-2">Layer 1</div>
            <div className="font-bold text-white text-xs mb-4">Google Safe Browsing</div>
            <div className="text-xs text-muted" style={{ fontSize: 11 }}>
              Reputation & Known Threat Blacklist
            </div>
            <div className="mt-8 text-xs text-amber font-mono" style={{ fontSize: 10 }}>
              DEMO (Mock Provider)
            </div>
          </div>

          {/* L2 */}
          <div className={`p-12 rounded border ${activePipelineLayer === 2 ? 'border-red bg-dark' : 'border-dark bg-dark'}`} style={{ borderLeft: '3px solid var(--green)' }}>
            <div className="text-xs font-bold text-muted uppercase mb-2">Layer 2</div>
            <div className="font-bold text-white text-xs mb-4">Local URL Classifier</div>
            <div className="text-xs text-muted" style={{ fontSize: 11 }}>
              Lexical Heuristics, Punycode & IP
            </div>
            <div className="mt-8 text-xs text-green font-mono" style={{ fontSize: 10 }}>
              Active (RuleHeuristics-v1.2)
            </div>
          </div>

          {/* L3 */}
          <div className={`p-12 rounded border ${activePipelineLayer === 3 ? 'border-red bg-dark' : 'border-dark bg-dark'}`} style={{ borderLeft: '3px solid var(--amber)' }}>
            <div className="text-xs font-bold text-muted uppercase mb-2">Layer 3</div>
            <div className="font-bold text-white text-xs mb-4">Browser Sandbox</div>
            <div className="text-xs text-muted" style={{ fontSize: 11 }}>
              Disposable MicroVM Detonation
            </div>
            <div className="mt-8 text-xs text-amber font-mono" style={{ fontSize: 10 }}>
              Simulated Telemetry
            </div>
          </div>

          {/* L4 */}
          <div className={`p-12 rounded border ${activePipelineLayer === 4 ? 'border-red bg-dark' : 'border-dark bg-dark'}`} style={{ borderLeft: '3px solid var(--red)' }}>
            <div className="text-xs font-bold text-muted uppercase mb-2">Layer 4</div>
            <div className="font-bold text-white text-xs mb-4">Gemini Threat Analyst</div>
            <div className="text-xs text-muted" style={{ fontSize: 11 }}>
              Gemini 3.8 Flash Reasoning
            </div>
            <div className="mt-8 text-xs text-amber font-mono" style={{ fontSize: 10 }}>
              Mock Analyst Response
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Row (Part 8 requirement: Total Scans, Blocked Links, Inconclusive Results) */}
      <div className="stats-row mb-20">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--blue-dim)', color: 'var(--blue)' }}>
            <Link2 size={16} />
          </div>
          <span className="stat-label">Total Scans Executed</span>
          <span className="stat-value">{totalScans}</span>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>
            <ShieldAlert size={16} />
          </div>
          <span className="stat-label">Blocked Malicious Links</span>
          <span className="stat-value">{blockedLinks}</span>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: '#334155', color: '#cbd5e1' }}>
            <HelpCircle size={16} />
          </div>
          <span className="stat-label">Inconclusive Results</span>
          <span className="stat-value">{inconclusive}</span>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'var(--amber-dim)', color: 'var(--amber)' }}>
            <AlertTriangle size={16} />
          </div>
          <span className="stat-label">Suspicious / Caution</span>
          <span className="stat-value">{suspiciousCount}</span>
        </div>
      </div>

      {/* Quick Action & Link Testbed */}
      <div className="grid-2 mb-20">
        <div className="card">
          <div className="card-title">Interactive Link Testbed</div>
          <p className="text-xs text-muted mb-12">
            Click any test link below while holding <strong>5</strong> to observe interception and pipeline execution:
          </p>
          <div className="cursor-test-links">
            {DEMO_LINKS.map((link) => (
              <a
                key={link.url}
                href={link.url}
                className={`test-link ${link.preset}`}
                onClick={(e) => handleLinkClick(e, link.url)}
              >
                <ExternalLink size={12} />
                {link.label}
              </a>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-title">Security Navigation</div>
          <div className="flex flex-col gap-8">
            <button className="btn" onClick={() => setPage('cursor')}>
              <MousePointer2 size={14} /> Cursor Protection Center
            </button>
            <button className="btn" onClick={() => setPage('link-analyzer')}>
              <Search size={14} /> Link Analyzer (Quick / Deep)
            </button>
            <button className="btn" onClick={() => setPage('qr-scanner')}>
              <QrCode size={14} /> QR Code Image Scanner
            </button>
            <button className="btn" onClick={() => setPage('settings')}>
              <Layers size={14} /> API Key Configuration Status
            </button>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="card">
        <div className="card-title flex justify-between items-center">
          <span>Recent Security Activity</span>
          {recentFive.length > 0 && (
            <button className="btn btn-small btn-ghost text-xs" onClick={() => setPage('history')}>
              View Full History ({history.length})
            </button>
          )}
        </div>
        {recentFive.length === 0 ? (
          <div className="empty-state">
            <Clock size={28} />
            <p>No link or QR scans recorded. Hold 5 and click a link to begin.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Destination Domain</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Source</th>
                <th>Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {recentFive.map((r) => (
                <tr key={r.id}>
                  <td className="font-mono text-xs">{r.domain}</td>
                  <td>
                    <span
                      className={`risk-badge ${
                        r.verdict === 'MALICIOUS' || r.verdict === 'HIGH RISK'
                          ? 'high-risk'
                          : r.verdict === 'SUSPICIOUS' || r.verdict === 'CAUTION'
                          ? 'caution'
                          : r.verdict === 'INCONCLUSIVE'
                          ? 'text-muted'
                          : 'safe'
                      }`}
                      style={r.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}
                    >
                      {r.verdict}
                    </span>
                  </td>
                  <td>
                    <strong>{r.riskScore}</strong>/100
                  </td>
                  <td className="text-xs text-muted">{r.pipelineResult?.sourceAttribution || r.scanType}</td>
                  <td className="text-xs text-muted">{new Date(r.timestamp).toLocaleTimeString()}</td>
                  <td>
                    <button
                      className="btn btn-small btn-ghost text-xs"
                      onClick={() => {
                        setDetailResult(r);
                        setPage('scan-details');
                      }}
                    >
                      Details &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
