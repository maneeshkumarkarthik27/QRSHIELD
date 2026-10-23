import { useState, useEffect, useCallback, useRef } from 'react';
import type { Page, ScanResult, AppSettings } from './types';
import Sidebar from './Sidebar';
import StatusBar from './StatusBar';
import Dashboard from './Dashboard';
import CursorProtection from './CursorProtection';
import LinkAnalyzer from './LinkAnalyzer';
import QRScanner from './QRScanner';
import ScanHistory from './ScanHistoryPage';
import ScanDetailsPage from './ScanDetailsPage';
import SandboxEvidencePage from './SandboxEvidencePage';
import AITreatReportPage from './AITreatReportPage';
import SettingsPage from './SettingsPage';
import DetailModal from './DetailModal';
import FloatingPanel from './FloatingPanel';
import Toast from './Toast';
import { PipelineOrchestrator } from './services/pipeline/PipelineOrchestrator';

/* ---------- localStorage helpers ---------- */
function loadHistory(): ScanResult[] {
  try {
    const raw = localStorage.getItem('qrshield_history');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveHistory(h: ScanResult[]) {
  try {
    localStorage.setItem('qrshield_history', JSON.stringify(h));
  } catch { }
}

function loadSettings(): AppSettings {
  const defaults: AppSettings = {
    protectionEnabled: true,
    cursorShortcutEnabled: true,
    floatingPanelEnabled: true,
    highRiskBlocking: true,
    defaultScanMode: 'deep',
    shortcutKey: '5',
  };
  try {
    const raw = localStorage.getItem('qrshield_settings');
    if (raw) {
      const parsed = JSON.parse(raw);
      return { ...defaults, ...parsed };
    }
  } catch { /* ignore */ }
  return defaults;
}

function saveSettings(s: AppSettings) {
  try {
    localStorage.setItem('qrshield_settings', JSON.stringify(s));
  } catch { }
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [settings, setSettings] = useState<AppSettings>(loadSettings);
  const [history, setHistory] = useState<ScanResult[]>(loadHistory);
  const [cursorActive, setCursorActive] = useState(false);
  const [helperConnected, setHelperConnected] = useState(false);
  const [detailResult, setDetailResult] = useState<ScanResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  /* floating panel state */
  const [floatingResult, setFloatingResult] = useState<ScanResult | null>(null);
  const [floatingPos, setFloatingPos] = useState({ x: 0, y: 0 });
  const [floatingScanning, setFloatingScanning] = useState(false);

  const orchestratorRef = useRef(new PipelineOrchestrator());

  /* persist settings */
  useEffect(() => { saveSettings(settings); }, [settings]);
  useEffect(() => { saveHistory(history); }, [history]);

  /* add result to history */
  const addToHistory = useCallback((result: ScanResult) => {
    setHistory((prev) => [result, ...prev]);
  }, []);

  /* clear history */
  const clearHistory = useCallback(() => {
    setHistory([]);
  }, []);

  /* reset demo data */
  const resetDemo = useCallback(() => {
    setHistory([]);
    setSettings({
      protectionEnabled: true,
      cursorShortcutEnabled: true,
      floatingPanelEnabled: true,
      highRiskBlocking: true,
      defaultScanMode: 'deep',
      shortcutKey: '5',
    });
    setToast('Demo data and settings have been reset.');
  }, []);

  /* show toast */
  const showToast = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  /* toggle single setting */
  const updateSetting = useCallback(<K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings((prev) => {
      const updated = { ...prev, [key]: value };
      if ((window as any).qrshield?.setProtectionConfig) {
        (window as any).qrshield.setProtectionConfig({
          protectionEnabled: updated.protectionEnabled,
          shortcut: updated.shortcutKey,
          highRiskBlocking: updated.highRiskBlocking,
        });
      }
      return updated;
    });
  }, []);

  /* ---- Electron & Native Windows Helper IPC Integration ---- */
  useEffect(() => {
    const electronApi = (window as any).qrshield;
    if (!electronApi) {
      // In web browser dev preview
      setHelperConnected(false);
      return;
    }

    // Check helper initial status
    electronApi.getHelperStatus?.().then((status: any) => {
      if (status) {
        setHelperConnected(status.connected);
      }
    });

    // Listen for global Hold-5 inspection mode changes from Windows Helper
    const unsubMode = electronApi.onInspectionModeChanged?.((active: boolean) => {
      setCursorActive(active);
    });

    // Listen for link interception events from UI Automation
    const unsubIntercept = electronApi.onLinkIntercepted?.(async (link: any) => {
      showToast(`Intercepted link: ${link.url}`);
      setFloatingPos({ x: link.x || 300, y: link.y || 300 });
      setFloatingScanning(true);
      setFloatingResult(null);

      try {
        const pResult = await orchestratorRef.current.runScan(
          link.url,
          settings.defaultScanMode,
          `Global Interception (${link.appName || 'Windows'})`,
          (prog) => {
            electronApi.sendScanProgress?.(`Layer ${prog.currentLayer}`, link.url, prog.currentLayer * 25);
          }
        );

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
        setDetailResult(legacyResult);

        electronApi.sendScanResult?.(pResult.verdict, pResult.riskScore, pResult.url);
      } catch {
        setFloatingScanning(false);
      }
    });

    // Listen for unavailable links
    const unsubUnavailable = electronApi.onLinkUnavailable?.((data: any) => {
      showToast('Link destination unavailable — not inspected');
    });

    return () => {
      unsubMode?.();
      unsubIntercept?.();
      unsubUnavailable?.();
    };
  }, [settings.defaultScanMode, addToHistory, showToast]);

  /* ---- cursor-mode class on body ---- */
  useEffect(() => {
    if (cursorActive) {
      document.body.classList.add('cursor-red-active');
    } else {
      document.body.classList.remove('cursor-red-active');
    }
    return () => { document.body.classList.remove('cursor-red-active'); };
  }, [cursorActive]);

  /* ---- fallback in-window keyboard handling for hold 5 ---- */
  useEffect(() => {
    if (!settings.protectionEnabled || !settings.cursorShortcutEnabled) {
      setCursorActive(false);
      return;
    }

    const targetKey = settings.shortcutKey || '5';

    const onKeyDown = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target as HTMLElement).isContentEditable) return;

      const isMatch =
        (targetKey === '5' && (e.key === '5' || e.code === 'Digit5' || e.code === 'Numpad5')) ||
        (targetKey === '6' && (e.key === '6' || e.code === 'Digit6' || e.code === 'Numpad6')) ||
        (targetKey === 'F1' && e.key === 'F1');

      if (isMatch && !e.repeat) {
        setCursorActive(true);
      }
    };

    const onKeyUp = (e: KeyboardEvent) => {
      const isMatch =
        (targetKey === '5' && (e.key === '5' || e.code === 'Digit5' || e.code === 'Numpad5')) ||
        (targetKey === '6' && (e.key === '6' || e.code === 'Digit6' || e.code === 'Numpad6')) ||
        (targetKey === 'F1' && e.key === 'F1');

      if (isMatch) {
        setCursorActive(false);
      }
    };

    const onBlur = () => {
      setCursorActive(false);
    };

    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keyup', onKeyUp);
    window.addEventListener('blur', onBlur);

    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keyup', onKeyUp);
      window.removeEventListener('blur', onBlur);
      setCursorActive(false);
    };
  }, [settings.protectionEnabled, settings.cursorShortcutEnabled, settings.shortcutKey]);

  /* ---- render page ---- */
  function renderPage() {
    switch (page) {
      case 'dashboard':
        return (
          <Dashboard
            settings={settings}
            updateSetting={updateSetting}
            history={history}
            cursorActive={cursorActive}
            helperConnected={helperConnected}
            setPage={setPage}
            setCursorActive={setCursorActive}
            addToHistory={addToHistory}
            setFloatingResult={setFloatingResult}
            setFloatingPos={setFloatingPos}
            setFloatingScanning={setFloatingScanning}
            setDetailResult={setDetailResult}
            showToast={showToast}
          />
        );
      case 'cursor':
        return (
          <CursorProtection
            settings={settings}
            cursorActive={cursorActive}
            helperConnected={helperConnected}
            setCursorActive={setCursorActive}
            addToHistory={addToHistory}
            setFloatingResult={setFloatingResult}
            setFloatingPos={setFloatingPos}
            setFloatingScanning={setFloatingScanning}
            setDetailResult={setDetailResult}
            showToast={showToast}
            setPage={setPage}
          />
        );
      case 'link-analyzer':
        return (
          <LinkAnalyzer
            addToHistory={addToHistory}
            setDetailResult={setDetailResult}
            showToast={showToast}
            setPage={setPage}
          />
        );
      case 'qr-scanner':
        return (
          <QRScanner
            addToHistory={addToHistory}
            setDetailResult={setDetailResult}
            showToast={showToast}
            setPage={setPage}
          />
        );
      case 'history':
        return (
          <ScanHistory
            history={history}
            clearHistory={clearHistory}
            setDetailResult={setDetailResult}
            setPage={setPage}
          />
        );
      case 'scan-details':
        return (
          <ScanDetailsPage
            result={detailResult}
            setPage={setPage}
            onClose={() => setPage('dashboard')}
          />
        );
      case 'sandbox-evidence':
        return (
          <SandboxEvidencePage
            result={detailResult}
            setPage={setPage}
          />
        );
      case 'ai-report':
        return (
          <AITreatReportPage
            result={detailResult}
            setPage={setPage}
          />
        );
      case 'settings':
        return (
          <SettingsPage
            settings={settings}
            updateSetting={updateSetting}
            clearHistory={clearHistory}
            resetDemo={resetDemo}
            showToast={showToast}
          />
        );
    }
  }

  return (
    <div className="app-layout">
      <Sidebar page={page} setPage={setPage} />
      <div className="main-area">
        <StatusBar
          protectionOn={settings.protectionEnabled}
          cursorActive={cursorActive}
          cursorShortcutEnabled={settings.cursorShortcutEnabled}
          helperConnected={helperConnected}
          shortcutKey={settings.shortcutKey}
        />
        <div className="content">
          {renderPage()}
        </div>
      </div>

      {/* floating scan panel */}
      {(floatingScanning || floatingResult) && settings.floatingPanelEnabled && (
        <FloatingPanel
          pos={floatingPos}
          scanning={floatingScanning}
          result={floatingResult}
          onClose={() => { setFloatingResult(null); setFloatingScanning(false); }}
          onDetails={(r) => {
            setDetailResult(r);
            setFloatingResult(null);
            setFloatingScanning(false);
            setPage('scan-details');
          }}
        />
      )}

      {/* detail modal */}
      {detailResult && page !== 'scan-details' && (
        <DetailModal
          result={detailResult}
          onClose={() => setDetailResult(null)}
          showToast={showToast}
          onViewFullReport={() => {
            setPage('scan-details');
          }}
        />
      )}

      {/* toast */}
      {toast && <Toast message={toast} onDone={() => setToast(null)} />}
    </div>
  );
}
