import { describe, it, expect } from 'vitest';
import { RuleBasedUrlClassifier } from '../services/pipeline/LocalUrlClassifier';
import { ElectronSafeBrowsingProvider } from '../services/pipeline/SafeBrowsingProvider';
import { PipelineOrchestrator } from '../services/pipeline/PipelineOrchestrator';

describe('QRShield Four-Layer Security Pipeline Tests', () => {
  it('Layer 2: LocalUrlClassifier detects IP address hostnames', async () => {
    const classifier = new RuleBasedUrlClassifier();
    const res = await classifier.classify('http://192.168.1.100/admin');
    expect(res.features.hasIpAddress).toBe(true);
    expect(res.riskClass).toBe('SUSPICIOUS');
    expect(res.anomaliesDetected.some((a) => a.includes('IP address'))).toBe(true);
  });

  it('Layer 2: LocalUrlClassifier detects Punycode and homoglyphs', async () => {
    const classifier = new RuleBasedUrlClassifier();
    const res = await classifier.classify('https://xn--pple-43d.com/login');
    expect(res.features.isPunycode).toBe(true);
    expect(res.riskClass).toBe('SUSPICIOUS');
  });

  it('Layer 2: LocalUrlClassifier detects misleading brand impersonation in subdomains', async () => {
    const classifier = new RuleBasedUrlClassifier();
    const res = await classifier.classify('https://chase-bank.secure-login.suspicious-auth.xyz/verify');
    expect(res.features.hasSuspiciousTld).toBe(true);
    expect(res.anomaliesDetected.some((a) => a.includes('Misleading domain'))).toBe(true);
    expect(res.riskClass).toBe('SUSPICIOUS');
  });

  it('Layer 1: SafeBrowsingProvider reports unavailable without Electron IPC', async () => {
    const orchestrator = new PipelineOrchestrator();
    const res = await orchestrator.runScan('https://testsafebrowsing.appspot.com/s/phishing.html', 'deep');
    expect(res.verdict).toBe('INCONCLUSIVE');
    expect(res.layer1.status).toBe('unavailable');
    expect(res.layer3.status).toBe('unavailable');
  });

  it('Verdict Policy: Quick Scan vs Deep Scan exhibit distinct behaviors', async () => {
    const orchestrator = new PipelineOrchestrator();
    const testUrl = 'https://docs.github.com/en';

    const quickRes = await orchestrator.runScan(testUrl, 'quick');
    expect(quickRes.scanMode).toBe('quick');
    expect(quickRes.layer3.status).toBe('skipped');
    expect(quickRes.layer4.status).toBe('skipped');

    const deepRes = await orchestrator.runScan(testUrl, 'deep');
    expect(deepRes.scanMode).toBe('deep');
    expect(deepRes.verdict).toBe('INCONCLUSIVE');
    expect(deepRes.layer3.status).toBe('unavailable');
  });

  it('Safety Constraint: Score of 0 must not mean guaranteed safety', async () => {
    const orchestrator = new PipelineOrchestrator();
    const res = await orchestrator.runScan('https://www.google.com', 'deep');
    expect(res.riskScore).toBeGreaterThan(0);
    expect(res.verdict).toBe('INCONCLUSIVE');
  });

  it('Safety Constraint: Missing credentials produce configuration status rather than false safe', async () => {
    const provider = new ElectronSafeBrowsingProvider();
    const result = await provider.lookupUrl('https://example-unregistered-threat.com');
    expect(result.demoMode).toBe(false);
    expect(result.apiConnected).toBe(false);
    expect(result.status).toBe('unavailable');
  });
});
