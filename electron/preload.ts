import { contextBridge, ipcRenderer } from 'electron';

export interface HelperStatus {
  connected: boolean;
  protectionEnabled: boolean;
  isHolding: boolean;
  version: string;
}

export interface InterceptedLink {
  url: string;
  appName: string;
  controlType: string;
  x: number;
  y: number;
}

export interface UnavailableLink {
  reason: string;
  appName: string;
  x: number;
  y: number;
}

// Expose safe, validated APIs to renderer process
contextBridge.exposeInMainWorld('qrshield', {
  getHelperStatus: (): Promise<HelperStatus> => ipcRenderer.invoke('qrshield:get-helper-status'),

  setProtectionConfig: (config: { protectionEnabled?: boolean; shortcut?: string; highRiskBlocking?: boolean }) =>
    ipcRenderer.invoke('qrshield:set-config', config),

  sendScanProgress: (stage: string, url: string, progress: number) =>
    ipcRenderer.invoke('qrshield:send-scan-progress', { stage, url, progress }),

  sendScanResult: (verdict: string, riskScore: number, url: string) =>
    ipcRenderer.invoke('qrshield:send-scan-result', { verdict, riskScore, url }),

  openExternal: (url: string) => ipcRenderer.invoke('qrshield:open-external', url),

  getApiConfigStatus: () => ipcRenderer.invoke('qrshield:get-api-config-status'),

  lookupSafeBrowsing: (url: string) => ipcRenderer.invoke('qrshield:lookup-safe-browsing', url),

  saveApiKeys: (keys: { geminiKey?: string; safeBrowsingKey?: string; modelName?: string }) =>
    ipcRenderer.invoke('qrshield:save-api-keys', keys),

  analyzeWithGemini: (evidence: any) => ipcRenderer.invoke('qrshield:analyze-gemini', evidence),

  getSandboxStatus: () => ipcRenderer.invoke('qrshield:get-sandbox-status'),

  analyzeSandbox: (url: string) => ipcRenderer.invoke('qrshield:analyze-sandbox', url),

  onInspectionModeChanged: (callback: (active: boolean) => void) => {
    const listener = (_event: any, active: boolean) => callback(active);
    ipcRenderer.on('qrshield:inspection-mode-changed', listener);
    return () => ipcRenderer.removeListener('qrshield:inspection-mode-changed', listener);
  },

  onLinkIntercepted: (callback: (data: InterceptedLink) => void) => {
    const listener = (_event: any, data: InterceptedLink) => callback(data);
    ipcRenderer.on('qrshield:link-intercepted', listener);
    return () => ipcRenderer.removeListener('qrshield:link-intercepted', listener);
  },

  onLinkUnavailable: (callback: (data: UnavailableLink) => void) => {
    const listener = (_event: any, data: UnavailableLink) => callback(data);
    ipcRenderer.on('qrshield:link-unavailable', listener);
    return () => ipcRenderer.removeListener('qrshield:link-unavailable', listener);
  },
});
