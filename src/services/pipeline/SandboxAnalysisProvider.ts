import type { SandboxResult } from './types';

export interface SandboxAnalysisProvider {
  analyzeUrl(url: string): Promise<SandboxResult>;
}

export class ElectronSandboxProvider implements SandboxAnalysisProvider {
  async analyzeUrl(url: string): Promise<SandboxResult> {
    const electronApi = typeof window !== 'undefined' ? (window as any).qrshield : null;
    if (electronApi?.analyzeSandbox) {
      try {
        return await electronApi.analyzeSandbox(url);
      } catch (error) {
        return this.unavailable(url, error instanceof Error ? error.message : 'Sandbox request failed.');
      }
    }

    return this.unavailable(url, 'Docker sandbox is available only in the Electron application.');
  }

  private unavailable(url: string, error: string): SandboxResult {
    return {
      status: 'unavailable',
      redirectChain: [],
      finalDestination: url,
      pageTitle: '',
      textSnippet: '',
      hasLoginForm: false,
      hasPasswordField: false,
      downloadAttempts: [],
      suspiciousNetworkCalls: [],
      domainTransitions: [],
      executionTimeMs: 0,
      isolationRuntime: 'Not configured',
      egressEnforced: false,
      connected: false,
      demoMode: false,
      error,
    };
  }
}
