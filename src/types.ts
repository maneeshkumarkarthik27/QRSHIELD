/* ============================================================
   QRShield — Application Type Definitions
   ============================================================ */

import type { PipelineScanResult, ScanMode } from './services/pipeline/types';

export type { ScanMode };
export type Verdict = 'SAFE' | 'CAUTION' | 'HIGH RISK' | 'MALICIOUS' | 'SUSPICIOUS' | 'INCONCLUSIVE' | 'NO THREAT DETECTED';
export type ScanType = 'link' | 'qr';

export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  riskScore: number;
  verdict: Verdict;
  scanType: ScanType;
  timestamp: number;
  https: boolean;
  redirects: boolean;
  misleadingDomain: boolean;
  suspiciousPatterns: string[];
  reputation: 'good' | 'unknown' | 'poor';
  reasons: string[];
  recommendedAction: string;
  pipelineResult?: PipelineScanResult;
}

export interface AppSettings {
  protectionEnabled: boolean;
  cursorShortcutEnabled: boolean;
  floatingPanelEnabled: boolean;
  highRiskBlocking: boolean;
  defaultScanMode: ScanMode;
  shortcutKey: string; // '5' | '6' | 'F1'
}

export type Page =
  | 'dashboard'
  | 'cursor'
  | 'link-analyzer'
  | 'qr-scanner'
  | 'history'
  | 'scan-details'
  | 'sandbox-evidence'
  | 'ai-report'
  | 'settings';
