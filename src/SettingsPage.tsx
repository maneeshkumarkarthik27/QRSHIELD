import { useState, useEffect } from 'react';
import type { AppSettings } from './types';
import {
  Shield,
  MousePointer2,
  PanelTop,
  ShieldAlert,
  Trash2,
  RotateCcw,
  Info,
  AlertTriangle,
  Key,
  Layers,
  Cpu,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Terminal,
} from 'lucide-react';

interface Props {
  settings: AppSettings;
  updateSetting: <K extends keyof AppSettings>(k: K, v: AppSettings[K]) => void;
  clearHistory: () => void;
  resetDemo: () => void;
  showToast: (msg: string) => void;
}

export default function SettingsPage({
  settings,
  updateSetting,
  clearHistory,
  resetDemo,
  showToast,
}: Props) {
  const [confirmClear, setConfirmClear] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [safeBrowsingInput, setSafeBrowsingInput] = useState('');
  const [geminiInput, setGeminiInput] = useState('');
  const [modelInput, setModelInput] = useState('gemini-3.8-flash');
  const [apiStatus, setApiStatus] = useState<{
    safeBrowsing: boolean;
    safeBrowsingMasked?: string;
    gemini: boolean;
    geminiMasked?: string;
    geminiModel?: string;
    sandbox: boolean;
  }>({
    safeBrowsing: false,
    gemini: false,
    sandbox: false,
  });

  useEffect(() => {
    let timer: number | undefined;
    const refreshStatus = () => {
      if ((window as any).qrshield?.getApiConfigStatus) {
        (window as any).qrshield.getApiConfigStatus().then((status: any) => {
        if (status) {
          setApiStatus(status);
          if (status.geminiModel) setModelInput(status.geminiModel);
        }
        });
      }
    };

    refreshStatus();
    if ((window as any).qrshield?.getSandboxStatus) {
      timer = window.setInterval(refreshStatus, 3000);
    }
    return () => {
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, []);

  const Toggle = ({ value, onChange }: { value: boolean; onChange: () => void }) => (
    <button
      className={`toggle-switch ${value ? 'on' : ''}`}
      onClick={onChange}
      aria-label="Toggle"
    >
      <span className="toggle-knob" style={value ? { transform: 'translateX(18px)' } : {}} />
    </button>
  );

  return (
    <div>
      <div className="page-header">
        <h2>Settings & Configuration</h2>
        <p>Configure QRShield system-wide protection, shortcuts, and backend API readiness</p>
      </div>

      {/* Global Protection settings */}
      <div className="card mb-20">
        <div className="card-title">Global Windows Protection</div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><Shield size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Master Protection Switch</h4>
            <p>Arm or disarm low-level input hooks and transparent desktop overlay across Windows.</p>
          </div>
          <Toggle
            value={settings.protectionEnabled}
            onChange={() => updateSetting('protectionEnabled', !settings.protectionEnabled)}
          />
        </div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><MousePointer2 size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Inspection Shortcut Trigger</h4>
            <p>Select which key activates inspection mode when held down.</p>
          </div>
          <div className="flex gap-6">
            {['5', '6', 'F1'].map((k) => (
              <button
                key={k}
                className={`btn btn-small ${(settings.shortcutKey || '5') === k ? 'btn-primary' : 'btn-ghost'}`}
                style={{ minWidth: 44, fontWeight: 700 }}
                onClick={() => {
                  updateSetting('shortcutKey', k);
                  showToast(`Activation shortcut set to Hold-${k}`);
                  if ((window as any).qrshield?.setProtectionConfig) {
                    (window as any).qrshield.setProtectionConfig({ shortcut: k });
                  }
                }}
              >
                {k === '5' ? '5 (Default)' : k}
              </button>
            ))}
          </div>
        </div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><Layers size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Default Pipeline Mode</h4>
            <p>Choose default analysis depth when links or QR codes are inspected.</p>
          </div>
          <div className="flex gap-6">
            <button
              className={`btn btn-small ${settings.defaultScanMode === 'quick' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => updateSetting('defaultScanMode', 'quick')}
            >
              Quick Scan (L1-L2)
            </button>
            <button
              className={`btn btn-small ${settings.defaultScanMode === 'deep' ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => updateSetting('defaultScanMode', 'deep')}
            >
              Deep Scan (L1-L4 Full)
            </button>
          </div>
        </div>
      </div>

      {/* Part 7: API Key Configuration Screen */}
      <div className="card mb-20">
        <div className="card-title flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Key size={16} /> API Integration & Provider Readiness
          </div>
          <span className="text-xs text-muted font-mono">SECRETS MASKED</span>
        </div>

        <p className="text-xs text-muted mb-16 leading-relaxed">
          QRShield uses a decoupled provider architecture. Production credentials are stored securely in <code>backend/.env</code> and are NEVER bundled in renderer code or installer binaries. You can configure credentials below or edit <code>backend/.env</code> directly.
        </p>

        <div className="space-y-12">
          {/* Safe Browsing */}
          <div className="p-12 bg-dark rounded border border-dark">
            <div className="flex justify-between items-center mb-8">
              <div>
                <div className="text-white text-xs font-bold mb-2">Layer 1: Google Safe Browsing API</div>
                <div className="text-muted text-xs font-mono">GOOGLE_SAFE_BROWSING_API_KEY</div>
              </div>
              <div className="flex items-center gap-8">
                {apiStatus.safeBrowsing ? (
                  <span className="risk-badge safe text-xs"><CheckCircle2 size={12} /> CONFIGURED {apiStatus.safeBrowsingMasked && `(${apiStatus.safeBrowsingMasked})`}</span>
                ) : (
                  <span className="risk-badge caution text-xs"><XCircle size={12} /> UNCONFIGURED (DEMO MOCK ACTIVE)</span>
                )}
              </div>
            </div>
            <div className="flex gap-8 mt-6">
              <input
                type="password"
                placeholder={apiStatus.safeBrowsingMasked || "Paste Google Safe Browsing API key"}
                value={safeBrowsingInput}
                onChange={(e) => setSafeBrowsingInput(e.target.value)}
                className="input-field text-xs font-mono flex-1"
                style={{ padding: '6px 10px', height: 32 }}
              />
              <button
                className="btn btn-small btn-ghost"
                onClick={async () => {
                  if (!safeBrowsingInput.trim()) return;
                  if ((window as any).qrshield?.saveApiKeys) {
                    await (window as any).qrshield.saveApiKeys({ safeBrowsingKey: safeBrowsingInput.trim() });
                    setSafeBrowsingInput('');
                    showToast('Safe Browsing API Key saved to backend/.env');
                    const updated = await (window as any).qrshield.getApiConfigStatus();
                    if (updated) setApiStatus(updated);
                  } else {
                    showToast('Saved (Demo browser preview mode)');
                    setApiStatus(prev => ({ ...prev, safeBrowsing: true }));
                  }
                }}
              >
                Save L1 Key
              </button>
            </div>
          </div>

          {/* Gemini */}
          <div className="p-12 bg-dark rounded border border-dark">
            <div className="flex justify-between items-center mb-8">
              <div>
                <div className="text-white text-xs font-bold mb-2">Layer 4: Google Gemini Threat Analyst</div>
                <div className="text-muted text-xs font-mono">GEMINI_API_KEY (Model: {apiStatus.geminiModel || 'gemini-3.8-flash'})</div>
              </div>
              <div className="flex items-center gap-8">
                {apiStatus.gemini ? (
                  <span className="risk-badge safe text-xs"><CheckCircle2 size={12} /> CONFIGURED {apiStatus.geminiMasked && `(${apiStatus.geminiMasked})`}</span>
                ) : (
                  <span className="risk-badge caution text-xs"><XCircle size={12} /> UNCONFIGURED (DEMO MOCK ACTIVE)</span>
                )}
              </div>
            </div>
            <div className="flex gap-8 mt-6">
              <input
                type="password"
                placeholder={apiStatus.geminiMasked || "Paste Gemini API key (AQ... or AIza...)"}
                value={geminiInput}
                onChange={(e) => setGeminiInput(e.target.value)}
                className="input-field text-xs font-mono flex-1"
                style={{ padding: '6px 10px', height: 32 }}
              />
              <select
                value={modelInput}
                onChange={(e) => setModelInput(e.target.value)}
                className="input-field text-xs font-mono"
                style={{ padding: '4px 8px', height: 32, width: 160 }}
              >
                <option value="gemini-3.8-flash">gemini-3.8-flash</option>
                <option value="gemini-3.7-flash">gemini-3.7-flash</option>
                <option value="gemini-3.5-flash">gemini-3.5-flash</option>
                <option value="gemini-flash-latest">gemini-flash-latest</option>
              </select>
              <button
                className="btn btn-small btn-primary"
                onClick={async () => {
                  if (!geminiInput.trim() && modelInput === apiStatus.geminiModel) return;
                  if ((window as any).qrshield?.saveApiKeys) {
                    await (window as any).qrshield.saveApiKeys({
                      geminiKey: geminiInput.trim() || undefined,
                      modelName: modelInput
                    });
                    setGeminiInput('');
                    showToast('Gemini configuration saved to backend/.env');
                    const updated = await (window as any).qrshield.getApiConfigStatus();
                    if (updated) setApiStatus(updated);
                  } else {
                    showToast('Gemini credentials saved (Demo browser preview mode)');
                    setApiStatus(prev => ({ ...prev, gemini: true, geminiModel: modelInput }));
                  }
                }}
              >
                Save L4 Config
              </button>
            </div>
          </div>

          {/* Sandbox */}
          <div className="p-12 bg-dark rounded border border-dark flex justify-between items-center">
            <div>
              <div className="text-white text-xs font-bold mb-2">Layer 3: Isolated MicroVM Sandbox Orchestrator</div>
              <div className="text-muted text-xs font-mono">SANDBOX_CONTAINER_RUNTIME=docker</div>
            </div>
            <div className="flex items-center gap-8">
              <span className="risk-badge" style={{ background: '#334155', color: '#cbd5e1', fontSize: 11 }}>
                <HelpCircle size={12} /> FUTURE BACKEND PHASE
              </span>
            </div>
          </div>
        </div>

        <div className="inline-notice mt-16">
          <Terminal size={14} />
          <span>
            Backend environment file: <code>backend/.env</code>. Keys are validated and kept locally on this workstation.
          </span>
        </div>
      </div>

      {/* Display & Safety Preferences */}
      <div className="card mb-20">
        <div className="card-title">Interception & Interface Preferences</div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><PanelTop size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Floating HUD at Pointer</h4>
            <p>Show scanning reticle and live analysis card near the mouse pointer.</p>
          </div>
          <Toggle
            value={settings.floatingPanelEnabled}
            onChange={() => updateSetting('floatingPanelEnabled', !settings.floatingPanelEnabled)}
          />
        </div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><ShieldAlert size={14} style={{ marginRight: 6, verticalAlign: -2 }} />High-Risk Click Interception</h4>
            <p>Automatically block clicks on confirmed malicious destinations.</p>
          </div>
          <Toggle
            value={settings.highRiskBlocking}
            onChange={() => updateSetting('highRiskBlocking', !settings.highRiskBlocking)}
          />
        </div>
      </div>

      {/* Data & Reset */}
      <div className="card mb-20">
        <div className="card-title">Data Management</div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><Trash2 size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Clear Local Audit Trail</h4>
            <p>Remove all cached scan records and verdicts from this machine.</p>
          </div>
          <button className="btn btn-small" onClick={() => setConfirmClear(true)}>
            Clear History
          </button>
        </div>

        <div className="settings-row">
          <div className="setting-info">
            <h4><RotateCcw size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Reset Demo State</h4>
            <p>Restore default toggles, clean sample history, and reset pipeline.</p>
          </div>
          <button className="btn btn-small" onClick={() => setConfirmReset(true)}>
            Reset All
          </button>
        </div>
      </div>

      {/* Part 9: Installation & Startup Disclosure */}
      <div className="card">
        <div className="card-title flex items-center gap-8">
          <Cpu size={16} /> Windows Integration & Transparency Disclosure
        </div>
        <div className="about-block">
          <h4>QRShield Windows Desktop v1.0.0</h4>
          <p>Architecture: Electron 35 + React 19 + C# .NET 4.8 Helper (x64 NSIS)</p>
        </div>
        <div className="inline-notice">
          <Info />
          <span>
            <strong>Global Input Monitoring Disclosure:</strong> QRShield uses standard Win32 low-level hooks (<code>WH_KEYBOARD_LL</code> and <code>WH_MOUSE_LL</code>) strictly to detect the configured Hold-5 shortcut and intercept hyperlink navigation. Keystrokes are never logged, recorded, or transmitted. Protection is opt-in and can be deactivated anytime.
          </span>
        </div>
      </div>

      {/* Confirm clear */}
      {confirmClear && (
        <div className="modal-overlay" onClick={() => setConfirmClear(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()} style={{ width: 380 }}>
            <div className="confirm-dialog">
              <AlertTriangle size={32} style={{ color: 'var(--amber)', marginBottom: 12 }} />
              <h3>Clear Scan History?</h3>
              <p>All recorded scan telemetry will be erased.</p>
              <div className="btn-row">
                <button className="btn" onClick={() => setConfirmClear(false)}>Cancel</button>
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    clearHistory();
                    setConfirmClear(false);
                    showToast('Scan history erased.');
                  }}
                >
                  Clear
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Confirm reset */}
      {confirmReset && (
        <div className="modal-overlay" onClick={() => setConfirmReset(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()} style={{ width: 380 }}>
            <div className="confirm-dialog">
              <AlertTriangle size={32} style={{ color: 'var(--amber)', marginBottom: 12 }} />
              <h3>Reset Demo Data?</h3>
              <p>Restores all settings, shortcuts, and scan modes to initial factory defaults.</p>
              <div className="btn-row">
                <button className="btn" onClick={() => setConfirmReset(false)}>Cancel</button>
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    resetDemo();
                    setConfirmReset(false);
                  }}
                >
                  Reset
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
