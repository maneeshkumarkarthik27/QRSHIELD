import type {
  GeminiAnalystResult,
  SafeBrowsingResult,
  LocalClassifierResult,
  SandboxResult,
} from './types';

export interface ThreatEvidenceInput {
  url: string;
  layer1: SafeBrowsingResult;
  layer2: LocalClassifierResult;
  layer3?: SandboxResult;
}

export interface GeminiThreatAnalyst {
  analyzeThreat(evidence: ThreatEvidenceInput): Promise<GeminiAnalystResult>;
}

export class ElectronGeminiThreatAnalyst implements GeminiThreatAnalyst {
  async analyzeThreat(evidence: ThreatEvidenceInput): Promise<GeminiAnalystResult> {
    const electronApi = typeof window !== 'undefined' ? (window as any).qrshield : null;
    if (!electronApi?.analyzeWithGemini) {
      return {
        status: 'unavailable',
        model: 'configured model',
        threatAssessment: 'Gemini analysis is unavailable outside the Electron application.',
        confidenceLevel: 'LOW',
        explanation: 'No live Gemini provider is connected.',
        likelyAttackType: 'Uncertain',
        importantUncertainties: ['Gemini provider unavailable'],
        recommendedUserAction: 'Do not treat this scan as proof that the destination is safe.',
        demoMode: false,
        connected: false,
      };
    }

    try {
      return await electronApi.analyzeWithGemini(evidence);
    } catch (error) {
      return {
        status: 'failed',
        model: 'configured model',
        threatAssessment: 'Gemini analysis failed.',
        confidenceLevel: 'LOW',
        explanation: error instanceof Error ? error.message : 'Gemini request failed.',
        likelyAttackType: 'Uncertain',
        importantUncertainties: ['AI analysis failed'],
        recommendedUserAction: 'Rely on deterministic findings and treat the result as inconclusive.',
        demoMode: false,
        connected: false,
      };
    }
  }
}
