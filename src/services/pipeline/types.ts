/* ============================================================
   QRShield — Four-Layer Pipeline Type Definitions
   ============================================================ */

export type ScanVerdict = 'MALICIOUS' | 'SUSPICIOUS' | 'INCONCLUSIVE' | 'NO THREAT DETECTED';
export type ScanMode = 'quick' | 'deep';
export type LayerExecutionStatus = 'skipped' | 'pending' | 'running' | 'completed' | 'unavailable' | 'failed';

// Layer 1: Google Safe Browsing
export interface SafeBrowsingResult {
  status: LayerExecutionStatus;
  threatFound: boolean;
  threatType?: 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE' | 'POTENTIALLY_HARMFUL_APPLICATION';
  platformType?: string;
  cacheDurationSeconds?: number;
  apiConnected: boolean;
  demoMode: boolean;
  error?: string;
}

// Layer 2: Local URL Classifier
export type LocalRiskClass = 'LOWER RISK' | 'SUSPICIOUS' | 'INSUFFICIENT EVIDENCE';

export interface UrlFeatures {
  hasIpAddress: boolean;
  isPunycode: boolean;
  subdomainCount: number;
  hasSuspiciousTld: boolean;
  hasUserInfo: boolean;
  hasUnusualPort: boolean;
  suspiciousKeywords: string[];
  entropyScore: number;
  urlLength: number;
}

export interface LocalClassifierResult {
  status: LayerExecutionStatus;
  riskClass: LocalRiskClass;
  score: number; // 0-100
  features: UrlFeatures;
  anomaliesDetected: string[];
  modelType: string; // e.g. "RuleHeuristics-v1.2"
}

// Layer 3: Sandbox Analysis
export interface RedirectHop {
  url: string;
  statusCode: number;
  timestamp: number;
}

export interface DownloadAttempt {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256Hash: string;
  blocked: boolean;
}

export interface SandboxResult {
  status: LayerExecutionStatus;
  redirectChain: RedirectHop[];
  finalDestination: string;
  pageTitle: string;
  textSnippet: string;
  hasLoginForm: boolean;
  hasPasswordField: boolean;
  downloadAttempts: DownloadAttempt[];
  suspiciousNetworkCalls: string[];
  domainTransitions: string[];
  executionTimeMs: number;
  isolationRuntime: string; // e.g. "Disposable MicroVM (Mock/Demo)"
  egressEnforced: boolean;
  connected: boolean;
  demoMode: boolean;
  error?: string;
}

// Layer 4: Gemini AI Threat Analyst
export interface GeminiAnalystResult {
  status: LayerExecutionStatus;
  model: string;
  threatAssessment: string;
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  explanation: string;
  likelyAttackType: 'Credential Phishing' | 'Drive-by Malware' | 'Tech Support Scam' | 'Brand Impersonation' | 'Benign' | 'Uncertain';
  importantUncertainties: string[];
  recommendedUserAction: string;
  demoMode: boolean;
  connected: boolean;
  error?: string;
}

// Aggregate Scan Result
export interface PipelineScanResult {
  id: string;
  url: string;
  domain: string;
  startTime: number;
  endTime?: number;
  scanMode: ScanMode;
  currentLayer: number; // 1, 2, 3, 4
  status: 'running' | 'completed' | 'failed' | 'inconclusive';
  verdict: ScanVerdict;
  riskScore: number; // 0-100 (0 != guaranteed safe)
  reasons: string[];
  recommendedAction: string;
  sourceAttribution: string; // "Global Cursor (Hold-5)" | "Link Analyzer" | "QR Scanner" | "Testbed"
  layer1: SafeBrowsingResult;
  layer2: LocalClassifierResult;
  layer3: SandboxResult;
  layer4: GeminiAnalystResult;
  evidenceSummary: string[];
}
