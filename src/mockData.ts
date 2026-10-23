/* ============================================================
   QRShield — Mock data & simulated scanning logic
   ============================================================ */

import type { ScanResult, Verdict } from './types';

/* ---------- preset demo links ---------- */
export const DEMO_LINKS = [
  {
    url: 'https://example.com/login',
    label: 'example.com/login',
    preset: 'safe' as const,
  },
  {
    url: 'http://examp1e-secure.com/verify?token=abc',
    label: 'examp1e-secure.com/verify',
    preset: 'caution' as const,
  },
  {
    url: 'http://free-prizes-winner.xyz/claim?id=9182',
    label: 'free-prizes-winner.xyz/claim',
    preset: 'danger' as const,
  },
];

/* ---------- mock result database ---------- */
const MOCK_RESULTS: Record<string, Omit<ScanResult, 'id' | 'timestamp'>> = {
  'https://example.com/login': {
    url: 'https://example.com/login',
    domain: 'example.com',
    riskScore: 8,
    verdict: 'SAFE',
    scanType: 'link',
    https: true,
    redirects: false,
    misleadingDomain: false,
    suspiciousPatterns: [],
    reputation: 'good',
    reasons: [
      'Domain is well-known and trusted.',
      'Uses HTTPS with a valid certificate.',
      'No suspicious redirects detected.',
      'URL structure is standard.',
    ],
    recommendedAction: 'This link appears safe. You may proceed.',
  },
  'http://examp1e-secure.com/verify?token=abc': {
    url: 'http://examp1e-secure.com/verify?token=abc',
    domain: 'examp1e-secure.com',
    riskScore: 46,
    verdict: 'CAUTION',
    scanType: 'link',
    https: false,
    redirects: true,
    misleadingDomain: true,
    suspiciousPatterns: ['Homograph / typo-squatting domain', 'Token parameter in URL'],
    reputation: 'unknown',
    reasons: [
      'Domain resembles "example-secure.com" but uses the digit "1" — possible typo-squatting.',
      'Connection is not encrypted (HTTP only).',
      'A redirect was detected before reaching the final page.',
      'Domain reputation is unknown.',
    ],
    recommendedAction: 'Proceed with caution. Verify the domain carefully before entering credentials.',
  },
  'http://free-prizes-winner.xyz/claim?id=9182': {
    url: 'http://free-prizes-winner.xyz/claim?id=9182',
    domain: 'free-prizes-winner.xyz',
    riskScore: 92,
    verdict: 'HIGH RISK',
    scanType: 'link',
    https: false,
    redirects: true,
    misleadingDomain: true,
    suspiciousPatterns: [
      'Prize / reward scam keywords',
      'Suspicious TLD (.xyz)',
      'Tracking parameter in URL',
      'Multiple redirects',
    ],
    reputation: 'poor',
    reasons: [
      'Domain contains common scam keywords ("free", "prizes", "winner").',
      'Uses a suspicious top-level domain (.xyz).',
      'Connection is not encrypted.',
      'Multiple redirects detected — possible cloaking.',
      'Domain has a poor reputation score.',
    ],
    recommendedAction: 'Do NOT visit this link. It shows strong indicators of a phishing or scam website.',
  },
};

/* ---------- QR demo result ---------- */
export const QR_DEMO_RESULT: Omit<ScanResult, 'id' | 'timestamp'> = {
  url: 'http://examp1e-secure.com/verify?token=abc',
  domain: 'examp1e-secure.com',
  riskScore: 46,
  verdict: 'CAUTION',
  scanType: 'qr',
  https: false,
  redirects: true,
  misleadingDomain: true,
  suspiciousPatterns: ['Homograph / typo-squatting domain', 'Token parameter in URL'],
  reputation: 'unknown',
  reasons: [
    'QR code decoded to a suspicious URL.',
    'Domain resembles "example-secure.com" but uses the digit "1".',
    'No HTTPS detected.',
    'Unknown domain reputation.',
  ],
  recommendedAction: 'Verify the domain before interacting. The QR code may lead to a phishing page.',
};

/* ---------- generate a unique id ---------- */
let _counter = 0;
export function uid(): string {
  _counter += 1;
  return `scan-${Date.now()}-${_counter}`;
}

/* ---------- simulate a scan (returns after a delay) ---------- */
export function simulateScan(
  url: string,
  scanType: 'link' | 'qr' = 'link',
): Promise<ScanResult> {
  return new Promise((resolve) => {
    const delay = 1200 + Math.random() * 800; // 1.2 – 2 s
    setTimeout(() => {
      const known = MOCK_RESULTS[url];
      if (known) {
        resolve({ ...known, scanType, id: uid(), timestamp: Date.now() });
        return;
      }
      // For any unknown URL, generate a random-ish result
      const result = generateRandomResult(url, scanType);
      resolve(result);
    }, delay);
  });
}

function generateRandomResult(url: string, scanType: 'link' | 'qr'): ScanResult {
  const hasHttps = url.startsWith('https');
  let score = Math.floor(Math.random() * 60) + 10; // 10-69
  if (!hasHttps) score += 15;
  if (url.includes('.xyz') || url.includes('.tk') || url.includes('.ml')) score += 20;
  if (url.includes('free') || url.includes('win') || url.includes('prize')) score += 25;
  score = Math.min(score, 99);

  let verdict: Verdict = 'SAFE';
  if (score >= 60) verdict = 'HIGH RISK';
  else if (score >= 30) verdict = 'CAUTION';

  let domain = '';
  try {
    domain = new URL(url).hostname;
  } catch {
    domain = url.split('/')[2] || url;
  }

  return {
    id: uid(),
    url,
    domain,
    riskScore: score,
    verdict,
    scanType,
    timestamp: Date.now(),
    https: hasHttps,
    redirects: score > 40,
    misleadingDomain: score > 50,
    suspiciousPatterns: score > 40 ? ['Heuristic patterns detected'] : [],
    reputation: score > 60 ? 'poor' : score > 30 ? 'unknown' : 'good',
    reasons: [
      hasHttps ? 'Uses HTTPS.' : 'Does not use HTTPS — connection is unencrypted.',
      score > 50 ? 'Domain has suspicious characteristics.' : 'Domain appears standard.',
      `Simulated risk score: ${score}/100.`,
    ],
    recommendedAction:
      verdict === 'SAFE'
        ? 'Link appears safe to visit.'
        : verdict === 'CAUTION'
          ? 'Proceed with caution — verify the domain.'
          : 'Avoid this link. High risk indicators found.',
  };
}

/* ---------- URL validation ---------- */
export function isValidUrl(str: string): boolean {
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

/* ---------- example URLs for the Link Analyzer page ---------- */
export const EXAMPLE_URLS = [
  'https://example.com/login',
  'http://examp1e-secure.com/verify?token=abc',
  'http://free-prizes-winner.xyz/claim?id=9182',
  'https://docs.example.org/guide',
];
