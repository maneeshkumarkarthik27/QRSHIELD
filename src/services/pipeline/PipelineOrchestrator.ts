import type {
  PipelineScanResult,
  ScanMode,
  SafeBrowsingResult,
  LocalClassifierResult,
  SandboxResult,
  GeminiAnalystResult,
} from './types';
import type { SafeBrowsingProvider } from './SafeBrowsingProvider';
import { ElectronSafeBrowsingProvider } from './SafeBrowsingProvider';
import type { LocalUrlClassifier } from './LocalUrlClassifier';
import { RuleBasedUrlClassifier } from './LocalUrlClassifier';
import type { SandboxAnalysisProvider } from './SandboxAnalysisProvider';
import { ElectronSandboxProvider } from './SandboxAnalysisProvider';
import type { GeminiThreatAnalyst } from './GeminiThreatAnalyst';
import { ElectronGeminiThreatAnalyst } from './GeminiThreatAnalyst';

export type PipelineProgressCallback = (current: PipelineScanResult) => void;

export class PipelineOrchestrator {
  private safeBrowsing: SafeBrowsingProvider;
  private urlClassifier: LocalUrlClassifier;
  private sandbox: SandboxAnalysisProvider;
  private gemini: GeminiThreatAnalyst;

  constructor(
    sbProvider?: SafeBrowsingProvider,
    classifier?: LocalUrlClassifier,
    sandboxProvider?: SandboxAnalysisProvider,
    analyst?: GeminiThreatAnalyst
  ) {
    this.safeBrowsing = sbProvider ?? new ElectronSafeBrowsingProvider();
    this.urlClassifier = classifier ?? new RuleBasedUrlClassifier();
    this.sandbox = sandboxProvider ?? new ElectronSandboxProvider();
    this.gemini = analyst ?? new ElectronGeminiThreatAnalyst();
  }

  async runScan(
    url: string,
    mode: ScanMode = 'deep',
    source: string = 'Link Analyzer',
    onProgress?: PipelineProgressCallback
  ): Promise<PipelineScanResult> {
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    let domain = 'unknown';
    try {
      const parsed = new URL(url.startsWith('http') ? url : 'https://' + url);
      domain = parsed.hostname;
    } catch {
      domain = url;
    }

    const defaultL1: SafeBrowsingResult = {
      status: 'pending',
      threatFound: false,
      apiConnected: false,
      demoMode: false,
    };
    const defaultL2: LocalClassifierResult = {
      status: 'pending',
      riskClass: 'INSUFFICIENT EVIDENCE',
      score: 15,
      features: {
        hasIpAddress: false,
        isPunycode: false,
        subdomainCount: 0,
        hasSuspiciousTld: false,
        hasUserInfo: false,
        hasUnusualPort: false,
        suspiciousKeywords: [],
        entropyScore: 0,
        urlLength: url.length,
      },
      anomaliesDetected: [],
      modelType: 'RuleHeuristics-v1.2',
    };
    const defaultL3: SandboxResult = {
      status: mode === 'quick' ? 'skipped' : 'pending',
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
      isolationRuntime: 'Not invoked',
      egressEnforced: true,
      connected: false,
      demoMode: false,
    };
    const defaultL4: GeminiAnalystResult = {
      status: mode === 'quick' ? 'skipped' : 'pending',
      model: 'gemini-3-flash-preview',
      threatAssessment: 'Pending analysis',
      confidenceLevel: 'LOW',
      explanation: 'Analysis has not commenced',
      likelyAttackType: 'Uncertain',
      importantUncertainties: [],
      recommendedUserAction: 'Wait for scan completion',
      demoMode: false,
      connected: false,
    };

    const state: PipelineScanResult = {
      id: scanId,
      url,
      domain,
      startTime: Date.now(),
      scanMode: mode,
      currentLayer: 1,
      status: 'running',
      verdict: 'INCONCLUSIVE',
      riskScore: 20,
      reasons: [],
      recommendedAction: 'Scanning in progress...',
      sourceAttribution: source,
      layer1: defaultL1,
      layer2: defaultL2,
      layer3: defaultL3,
      layer4: defaultL4,
      evidenceSummary: [],
    };

    // Emit initial
    onProgress?.({ ...state });

    // ==========================================
    // LAYER 1: GOOGLE SAFE BROWSING
    // ==========================================
    state.currentLayer = 1;
    state.layer1.status = 'running';
    onProgress?.({ ...state });

    const l1Result = await this.safeBrowsing.lookupUrl(url);
    state.layer1 = l1Result;

    const layer1Unavailable = l1Result.status === 'failed' || l1Result.status === 'unavailable';
    if (layer1Unavailable) {
      state.reasons.push(l1Result.error ?? 'Safe Browsing did not complete.');
      state.evidenceSummary.push('Layer 1 Safe Browsing: unavailable');
    }

    if (l1Result.threatFound) {
      state.verdict = 'MALICIOUS';
      state.riskScore = 95;
      state.reasons = [
        `Google Safe Browsing confirmed threat: ${l1Result.threatType ?? 'MALWARE/PHISHING'}`,
        'Destination recognized on global threat database',
      ];
      state.recommendedAction = 'Navigation blocked immediately. Do not visit this address.';
      state.evidenceSummary.push(`Layer 1 match: ${l1Result.threatType}`);
      state.status = 'completed';
      state.endTime = Date.now();
      onProgress?.({ ...state });
      return state;
    }

    state.evidenceSummary.push('Layer 1 Safe Browsing: No known threat match (Unconfirmed safe)');
    onProgress?.({ ...state });

    // ==========================================
    // LAYER 2: LOCAL URL CLASSIFIER
    // ==========================================
    state.currentLayer = 2;
    state.layer2.status = 'running';
    onProgress?.({ ...state });

    const l2Result = await this.urlClassifier.classify(url);
    state.layer2 = l2Result;

    if (l2Result.anomaliesDetected.length > 0) {
      state.reasons.push(...l2Result.anomaliesDetected);
      state.evidenceSummary.push(`Layer 2 Heuristics: ${l2Result.anomaliesDetected.join('; ')}`);
    } else {
      state.evidenceSummary.push('Layer 2 Heuristics: Standard URL structure observed');
    }

    // In QUICK SCAN mode, finish after Layer 2
    if (mode === 'quick') {
      state.endTime = Date.now();
      state.status = 'completed';

      if (layer1Unavailable) {
        state.verdict = 'INCONCLUSIVE';
        state.riskScore = 50;
        state.recommendedAction = 'Do not open this URL until live threat intelligence is available.';
      } else if (l2Result.riskClass === 'SUSPICIOUS') {
        state.verdict = 'SUSPICIOUS';
        state.riskScore = Math.max(65, l2Result.score);
        state.recommendedAction = 'Proceed with extreme caution. Suspicious structural patterns detected.';
      } else if (l2Result.riskClass === 'INSUFFICIENT EVIDENCE') {
        state.verdict = 'INCONCLUSIVE';
        state.riskScore = 45;
        state.recommendedAction = 'Insufficient evidence in Quick Scan. Run Deep Scan for sandbox & AI evaluation.';
      } else {
        state.verdict = 'NO THREAT DETECTED';
        state.riskScore = Math.max(15, l2Result.score); // 0 never means guaranteed safe
        state.recommendedAction = 'No obvious threat detected in Quick Scan. Remember to verify destination identity.';
      }

      onProgress?.({ ...state });
      return state;
    }

    // ==========================================
    // LAYER 3: ISOLATED BROWSER SANDBOX (DEEP SCAN)
    // ==========================================
    state.currentLayer = 3;
    state.layer3.status = 'running';
    onProgress?.({ ...state });

    const l3Result = await this.sandbox.analyzeUrl(url);
    state.layer3 = l3Result;

    if (l3Result.status === 'unavailable' || l3Result.status === 'failed') {
      state.status = 'inconclusive';
      state.verdict = 'INCONCLUSIVE';
      state.riskScore = 50;
      state.reasons.push(l3Result.error ?? 'Sandbox analysis did not complete.');
      state.recommendedAction = 'Do not open this URL until isolated page analysis is available.';
      state.endTime = Date.now();
      onProgress?.({ ...state });
      return state;
    }

    if (l3Result.downloadAttempts.length > 0) {
      state.evidenceSummary.push(`Layer 3 Sandbox: Intercepted download (${l3Result.downloadAttempts[0].filename})`);
      state.reasons.push(`Automatic binary download triggered: ${l3Result.downloadAttempts[0].filename}`);
    }
    if (l3Result.hasPasswordField || l3Result.hasLoginForm) {
      state.evidenceSummary.push('Layer 3 Sandbox: Password or login authentication form identified');
      state.reasons.push('Login/credential entry inputs present on target page');
    }
    if (l3Result.redirectChain.length > 1) {
      state.evidenceSummary.push(`Layer 3 Sandbox: ${l3Result.redirectChain.length} HTTP redirects observed`);
    }

    onProgress?.({ ...state });

    // ==========================================
    // LAYER 4: GEMINI AI THREAT ANALYST (DEEP SCAN)
    // ==========================================
    state.currentLayer = 4;
    state.layer4.status = 'running';
    onProgress?.({ ...state });

    const l4Result = await this.gemini.analyzeThreat({
      url,
      layer1: state.layer1,
      layer2: state.layer2,
      layer3: state.layer3,
    });
    state.layer4 = l4Result;
    state.evidenceSummary.push(`Layer 4 Gemini 3.8 Flash: ${l4Result.threatAssessment}`);

    // ==========================================
    // FINAL POLICY VERDICT SYNTHESIS
    // ==========================================
    state.endTime = Date.now();
    state.status = 'completed';

    // Policy Rule 1: High risk downloads or severe credential harvest
    const hasMalwareDownload = l3Result.downloadAttempts.length > 0;
    const isPhishingHarvest = (l3Result.hasPasswordField || l3Result.hasLoginForm) && l2Result.riskClass === 'SUSPICIOUS';

    if (hasMalwareDownload) {
      state.verdict = 'MALICIOUS';
      state.riskScore = 92;
      state.recommendedAction = l4Result.recommendedUserAction || 'Block download and close connection.';
    } else if (isPhishingHarvest) {
      state.verdict = 'MALICIOUS';
      state.riskScore = 88;
      state.recommendedAction = l4Result.recommendedUserAction || 'Do not provide account credentials.';
    } else if (l2Result.riskClass === 'SUSPICIOUS' || l4Result.confidenceLevel === 'HIGH' && l4Result.likelyAttackType !== 'Benign') {
      state.verdict = 'SUSPICIOUS';
      state.riskScore = Math.max(68, l2Result.score);
      state.recommendedAction = l4Result.recommendedUserAction || 'Carefully verify authenticity before proceeding.';
    } else if (l2Result.riskClass === 'INSUFFICIENT EVIDENCE') {
      state.verdict = 'INCONCLUSIVE';
      state.riskScore = 50;
      state.recommendedAction = 'Telemetry incomplete. Avoid sharing credentials on this destination.';
    } else {
      state.verdict = 'NO THREAT DETECTED';
      state.riskScore = Math.min(25, Math.max(10, l2Result.score)); // A score of 0 must not mean guaranteed safety
      state.recommendedAction = 'No known or heuristic threats found. Standard cautious browsing advised.';
    }

    if (state.reasons.length === 0) {
      state.reasons.push(l4Result.threatAssessment);
    }

    onProgress?.({ ...state });
    return state;
  }
}
