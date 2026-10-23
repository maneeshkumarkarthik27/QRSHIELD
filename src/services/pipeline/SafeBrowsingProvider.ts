import type { SafeBrowsingResult } from './types';

export interface SafeBrowsingProvider {
  lookupUrl(url: string): Promise<SafeBrowsingResult>;
}

export class ElectronSafeBrowsingProvider implements SafeBrowsingProvider {
  async lookupUrl(url: string): Promise<SafeBrowsingResult> {
    const electronApi = typeof window !== 'undefined' ? (window as any).qrshield : null;
    if (!electronApi?.lookupSafeBrowsing) {
      return {
        status: 'unavailable',
        threatFound: false,
        apiConnected: false,
        demoMode: false,
        error: 'Google Safe Browsing is available only in the Electron application.',
      };
    }

    try {
      const result = await electronApi.lookupSafeBrowsing(url);
      return result ?? {
        status: 'unavailable',
        threatFound: false,
        apiConnected: false,
        demoMode: false,
        error: 'Google Safe Browsing returned no result.',
      };
    } catch (error) {
      return {
        status: 'failed',
        threatFound: false,
        apiConnected: false,
        demoMode: false,
        error: error instanceof Error ? error.message : 'Google Safe Browsing request failed.',
      };
    }
  }
}
