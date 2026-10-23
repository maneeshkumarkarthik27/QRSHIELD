import { useState } from 'react';
import type { ScanResult, AppSettings, Page } from './types';
import { DEMO_LINKS } from './mockData';
import { PipelineOrchestrator } from './services/pipeline/PipelineOrchestrator';
import {
  MousePointer2,
  ExternalLink,
  AlertTriangle,
  Info,
  Monitor,
  Cpu,
  Layers,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';

interface Props {
  settings: AppSettings;
  cursorActive: boolean;
  helperConnected: boolean;
  setCursorActive: (v: boolean) => void;
  addToHistory: (r: ScanResult) => void;
  setFloatingResult: (r: ScanResult | null) => void;
  setFloatingPos: (p: { x: number; y: number }) => void;
  setFloatingScanning: (v: boolean) => void;
  setDetailResult: (r: ScanResult | null) => void;
  showToast: (msg: string) => void;
  setPage?: (p: Page) => void;
}

export default function CursorProtection({
  settings,
  cursorActive,
  helperConnected,
  setCursorActive,
  addToHistory,
  setFloatingResult,
  setFloatingPos,
  setFloatingScanning,
  setDetailResult,
  showToast,
  setPage,
}: Props) {
  const [manualCursor, setManualCursor] = useState(false);

  const orchestrator = new PipelineOrchestrator();

  const toggleManualCursor = () => {
    if (!settings.protectionEnabled) {
      showToast('Enable protection first from Dashboard or Settings.');
      return;
    }
    const next = !manualCursor;
    setManualCursor(next);
    setCursorActive(next);
  };

  const handleLinkClick = async (e: React.MouseEvent, url: string) => {
    e.preventDefault();
    e.stopPropagation();

    if (!cursorActive) {
      showToast('Activate cursor protection first — hold 5 or use the toggle above.');
      return;
    }

    const rect = (e.target as HTMLElement).getBoundingClientRect();
    const x = Math.min(rect.left, window.innerWidth - 360);
    const y = Math.min(rect.bottom + 8, window.innerHeight - 340);
    setFloatingPos({ x, y });
    setFloatingScanning(true);
    setFloatingResult(null);

    const pResult = await orchestrator.runScan(url, settings.defaultScanMode, 'Cursor Protection Testbed');

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

    setFloatingScanning(false);
    setFloatingResult(legacyResult);
    addToHistory(legacyResult);
  };

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Cursor Protection</h2>
          <p>System-wide Hold-5 inspection mode and transparent Windows overlay</p>
        </div>
        <div className="sidebar-demo-badge" style={{ fontSize: 11 }}>
          GLOBAL HOOKS ARMED
        </div>
      </div>

      {/* Status + toggle */}
      <div className="card mb-20">
        <div className="flex items-center justify-between mb-14">
          <div className="flex items-center gap-10">
            <MousePointer2 size={20} style={{ color: cursorActive ? 'var(--red)' : 'var(--text-muted)' }} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 700 }}>
                Inspection Reticle: {cursorActive ? 'ACTIVE (Inspecting)' : 'IDLE'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {cursorActive
                  ? 'Red crosshair overlay is tracking mouse pointer. Click links to intercept before browser navigation.'
                  : `Hold ${settings.shortcutKey || '5'} anywhere across Windows, or toggle manually below.`}
              </div>
            </div>
          </div>
          <button
            className="toggle-switch"
            style={cursorActive ? { background: 'var(--red)' } : {}}
            onClick={toggleManualCursor}
            aria-label="Toggle cursor mode"
          >
            <span className="toggle-knob" style={cursorActive ? { transform: 'translateX(18px)' } : {}} />
          </button>
        </div>

        {/* Keyboard hint */}
        <div className="keyboard-hint">
          <kbd>{settings.shortcutKey || '5'}</kbd>
          <span>Hold to activate system-wide inspection reticle (Digit 5 or Numpad 5)</span>
        </div>

        {!settings.protectionEnabled && (
          <div className="inline-notice mt-12">
            <AlertTriangle />
            <span>Protection is OFF. Global keyboard hook is disarmed. Enable protection to use cursor inspection.</span>
          </div>
        )}
      </div>

      {/* Windows Native Helper & Multi-Monitor Telemetry */}
      <div className="grid-2 mb-20">
        <div className="card">
          <div className="card-title flex items-center gap-8">
            <Cpu size={16} /> Native Windows Helper Status
          </div>
          <div className="text-xs space-y-8">
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Helper Architecture:</span>
              <span className="text-white font-mono">C# / .NET 4.8 (x64 Native)</span>
            </div>
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Low-Level Hooks:</span>
              <strong className={settings.protectionEnabled ? 'text-green' : 'text-muted'}>
                {settings.protectionEnabled ? 'WH_KEYBOARD_LL + WH_MOUSE_LL' : 'Disarmed'}
              </strong>
            </div>
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Local IPC Transport:</span>
              <span className="text-white font-mono">\\.\pipe\QRShieldPipe</span>
            </div>
            <div className="flex justify-between items-center py-4">
              <span className="text-muted">Process Safety:</span>
              <span className="text-green">Automatic cursor reset on exit / crash</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-title flex items-center gap-8">
            <Monitor size={16} /> Multi-Monitor Virtual Desktop
          </div>
          <div className="text-xs space-y-8">
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Virtual Screen Coverage:</span>
              <span className="text-white font-mono">VirtualScreen (All Monitors)</span>
            </div>
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Overlay Window Style:</span>
              <span className="text-white font-mono">WS_EX_TOPMOST | WS_EX_TRANSPARENT</span>
            </div>
            <div className="flex justify-between items-center py-4 border-b border-dark">
              <span className="text-muted">Focus Behavior:</span>
              <span className="text-green">Non-activating (WS_EX_NOACTIVATE)</span>
            </div>
            <div className="flex justify-between items-center py-4">
              <span className="text-muted">Typing Pass-through:</span>
              <span className="text-green">Normal '5' keystrokes preserved</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cursor test zone */}
      <div className="card mb-20">
        <div className="card-title">Cursor Test Zone</div>
        <div className="cursor-test-zone">
          <h4 className="text-xs font-bold text-muted mb-8 uppercase tracking-wider">
            Click any link while holding {settings.shortcutKey || '5'}
          </h4>
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
      </div>

      {/* Step by step guide */}
      <div className="card">
        <div className="card-title">Desktop Hold-5 Workflow</div>
        <div className="text-xs space-y-10 text-muted leading-relaxed">
          <div className="flex gap-8 items-start">
            <span className="risk-badge safe font-mono">1</span>
            <div><strong>Hold 5:</strong> Press and hold the top-row number 5 key (or numpad 5) anywhere in Windows. The high-visibility red crosshair overlay appears instantly.</div>
          </div>
          <div className="flex gap-8 items-start">
            <span className="risk-badge safe font-mono">2</span>
            <div><strong>Hover over any link:</strong> Move your pointer over any link in Edge, Chrome, Word, Outlook, or PDF documents.</div>
          </div>
          <div className="flex gap-8 items-start">
            <span className="risk-badge safe font-mono">3</span>
            <div><strong>Click to intercept:</strong> QRShield uses Windows UI Automation to extract the true destination URL and swallows the click before the browser navigates.</div>
          </div>
          <div className="flex gap-8 items-start">
            <span className="risk-badge safe font-mono">4</span>
            <div><strong>Four-Layer Detonation:</strong> The floating HUD displays real-time progress across Safe Browsing, URL Heuristics, Sandbox, and Gemini 3.8 Flash.</div>
          </div>
          <div className="flex gap-8 items-start">
            <span className="risk-badge safe font-mono">5</span>
            <div><strong>Release 5:</strong> Releasing the key instantly restores normal system cursor behavior. Normal typing in text inputs is never swallowed.</div>
          </div>
        </div>
      </div>
    </div>
  );
}
