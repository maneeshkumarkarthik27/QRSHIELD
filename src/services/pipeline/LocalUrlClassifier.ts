import type { LocalClassifierResult, LocalRiskClass, UrlFeatures } from './types';

export interface LocalUrlClassifier {
  classify(url: string): Promise<LocalClassifierResult>;
}

export class RuleBasedUrlClassifier implements LocalUrlClassifier {
  private static readonly SUSPICIOUS_TLDS = new Set([
    'top', 'xyz', 'click', 'loan', 'work', 'gq', 'cf', 'tk', 'ml', 'ga', 'fit', 'buzz', 'surf', 'rest', 'icu'
  ]);

  private static readonly FINANCIAL_BRANDS = [
    'paypal', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'steam', 'coinbase', 'binance'
  ];

  async classify(url: string): Promise<LocalClassifierResult> {
    // Simulate brief synchronous processing
    await new Promise((r) => setTimeout(r, 120));

    const anomalies: string[] = [];
    let score = 15; // Baseline caution; score of 0 does not mean guaranteed safe

    let parsed: URL | null = null;
    let rawUrl = url.trim();
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
      rawUrl = 'https://' + rawUrl;
    }

    try {
      parsed = new URL(rawUrl);
    } catch {
      return {
        status: 'completed',
        riskClass: 'INSUFFICIENT EVIDENCE',
        score: 65,
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
        anomaliesDetected: ['Malformed or unparseable URL structure'],
        modelType: 'RuleHeuristics-v1.2',
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const search = parsed.search.toLowerCase();

    // 1. Check IP address as hostname
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIpv4) {
      anomalies.push('Direct IP address hostname instead of domain name');
      score += 40;
    }

    // 2. Check Punycode / Internationalized domain names (Homograph attacks)
    const isPunycode = hostname.includes('xn--') || /[^\u0000-\u007F]/.test(hostname);
    if (isPunycode) {
      anomalies.push('Punycode / non-ASCII character representation in domain');
      score += 35;
    }

    // 3. Userinfo in URL (e.g. https://google.com@evil.com)
    const hasUserInfo = parsed.username !== '' || parsed.password !== '';
    if (hasUserInfo) {
      anomalies.push('Embedded user credentials / @ sign in URL authority');
      score += 45;
    }

    // 4. Unusual Port
    const port = parsed.port;
    const hasUnusualPort = port !== '' && port !== '80' && port !== '443';
    if (hasUnusualPort) {
      anomalies.push(`Non-standard service port specified (:${port})`);
      score += 25;
    }

    // 5. Subdomain depth and deceptive brand impersonation
    const parts = hostname.split('.');
    const subdomainCount = Math.max(0, parts.length - 2);
    if (subdomainCount >= 3) {
      anomalies.push(`Excessive subdomain nesting (${subdomainCount} levels deep)`);
      score += 20;
    }

    // Check if reputable brand appears in subdomain while main domain is different
    const matchedBrand = RuleBasedUrlClassifier.FINANCIAL_BRANDS.find((brand) =>
      hostname.includes(brand)
    );
    if (matchedBrand) {
      const rootDomain = parts.slice(-2).join('.');
      if (!rootDomain.includes(matchedBrand)) {
        anomalies.push(`Misleading domain: brand '${matchedBrand}' found in subdomain, actual registrar is '${rootDomain}'`);
        score += 45;
      }
    }

    // 6. Suspicious Top-Level Domains (TLDs)
    const tld = parts[parts.length - 1];
    const hasSuspiciousTld = RuleBasedUrlClassifier.SUSPICIOUS_TLDS.has(tld);
    if (hasSuspiciousTld) {
      anomalies.push(`High-abuse Top Level Domain (.${tld})`);
      score += 25;
    }

    // 7. Suspicious Keywords in Path/Query
    const suspiciousWords = ['verify', 'login', 'update', 'banking', 'secure', 'password', 'wallet', 'confirm', 'billing', 'recover'];
    const foundKeywords = suspiciousWords.filter((w) => pathname.includes(w) || search.includes(w));
    if (foundKeywords.length >= 2) {
      anomalies.push(`High density of credential-harvesting keywords: [${foundKeywords.join(', ')}]`);
      score += 20;
    }

    // 8. Open Redirect / Nested URL parameters
    if (search.includes('redirect=') || search.includes('url=http') || search.includes('next=http')) {
      anomalies.push('Open redirect parameter detected in URL query');
      score += 25;
    }

    // Compute final class
    score = Math.min(100, score);

    let riskClass: LocalRiskClass = 'LOWER RISK';
    if (score >= 60 || anomalies.length >= 2) {
      riskClass = 'SUSPICIOUS';
    } else if (anomalies.length === 1 && score >= 40) {
      riskClass = 'SUSPICIOUS';
    } else if (parts.length <= 1) {
      riskClass = 'INSUFFICIENT EVIDENCE';
    }

    const features: UrlFeatures = {
      hasIpAddress: isIpv4,
      isPunycode,
      subdomainCount,
      hasSuspiciousTld,
      hasUserInfo,
      hasUnusualPort,
      suspiciousKeywords: foundKeywords,
      entropyScore: Math.round(score * 0.8),
      urlLength: url.length,
    };

    return {
      status: 'completed',
      riskClass,
      score,
      features,
      anomaliesDetected: anomalies,
      modelType: 'RuleHeuristics-v1.2',
    };
  }
}
