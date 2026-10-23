import http from 'node:http';
import { URL } from 'node:url';
import { chromium } from 'playwright';

const port = Number(process.env.SANDBOX_PORT || 4892);
const timeoutMs = Math.min(Number(process.env.SANDBOX_TIMEOUT_MS || 15000), 30000);

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase();
  if (host === 'localhost' || host === '::1' || host.endsWith('.local')) return true;
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return false;
  const [a, b] = parts;
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function validateTarget(value) {
  const target = new URL(value);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if (isPrivateHost(target.hostname)) throw new Error('Private and loopback destinations are not permitted.');
  return target.toString();
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function analyze(url) {
  const target = validateTarget(url);
  const started = Date.now();
  const redirectChain = [];
  const suspiciousNetworkCalls = [];
  const domainTransitions = [];
  const downloadAttempts = [];
  let currentDomain = new URL(target).hostname;
  const browser = await chromium.launch({ headless: true });

  try {
    const context = await browser.newContext({ acceptDownloads: true, ignoreHTTPSErrors: false });
    const page = await context.newPage();
    await page.route('**/*', async (route) => {
      try {
        const requestUrl = new URL(route.request().url());
        if (['http:', 'https:'].includes(requestUrl.protocol) && isPrivateHost(requestUrl.hostname)) {
          await route.abort('blockedbyclient');
          return;
        }
      } catch {
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
    page.on('request', (request) => {
      const requestUrl = request.url();
      if (request.resourceType() === 'document' || request.resourceType() === 'xhr' || request.resourceType() === 'fetch') {
        suspiciousNetworkCalls.push(`${request.method()} ${requestUrl}`.slice(0, 500));
      }
    });
    page.on('response', (response) => {
      const responseUrl = response.url();
      try {
        const domain = new URL(responseUrl).hostname;
        if (domain !== currentDomain) {
          domainTransitions.push(`${currentDomain} -> ${domain}`);
          currentDomain = domain;
        }
        if (response.status() >= 300 && response.status() < 400) {
          redirectChain.push({ url: responseUrl, statusCode: response.status(), timestamp: Date.now() });
        }
      } catch { }
    });
    page.on('download', async (download) => {
      downloadAttempts.push({
        filename: download.suggestedFilename(),
        mimeType: '',
        sizeBytes: 0,
        sha256Hash: '',
        blocked: true,
      });
      await download.cancel().catch(() => {});
    });

    await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    await page.waitForTimeout(Math.min(1500, timeoutMs / 3));
    const finalDestination = page.url();
    const textSnippet = (await page.locator('body').innerText({ timeout: 2000 }).catch(() => '')).slice(0, 2000);
    const pageTitle = await page.title().catch(() => '');
    const hasPasswordField = await page.locator('input[type="password"]').count() > 0;
    const hasLoginForm = hasPasswordField || await page.locator('form').evaluateAll((forms) =>
      forms.some((form) => /login|sign.?in|password|authenticate/i.test(form.textContent || ''))
    ).catch(() => false);

    return {
      status: 'completed',
      redirectChain: redirectChain.slice(0, 30),
      finalDestination,
      pageTitle,
      textSnippet,
      hasLoginForm,
      hasPasswordField,
      downloadAttempts,
      suspiciousNetworkCalls: suspiciousNetworkCalls.slice(0, 100),
      domainTransitions: [...new Set(domainTransitions)].slice(0, 30),
      executionTimeMs: Date.now() - started,
      isolationRuntime: 'Docker Playwright disposable container',
      egressEnforced: false,
      connected: true,
      demoMode: false,
    };
  } finally {
    await browser.close();
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    json(res, 200, { ok: true, runtime: 'docker-playwright' });
    return;
  }
  if (req.method !== 'POST' || req.url !== '/analyze') {
    json(res, 404, { error: 'Not found' });
    return;
  }

  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 10000) req.destroy();
  });
  req.on('end', async () => {
    try {
      const input = JSON.parse(body);
      const result = await analyze(input.url);
      json(res, 200, result);
    } catch (error) {
      json(res, 422, {
        status: 'failed',
        error: error instanceof Error ? error.message : 'Sandbox analysis failed.',
      });
    }
  });
});

server.listen(port, '0.0.0.0');
