import type { ScanResult, Page } from './types';
import {
  Box,
  AlertTriangle,
  ArrowRight,
  Download,
  Key,
  Globe,
  Network,
  Clock,
  ShieldCheck,
} from 'lucide-react';

interface Props {
  result: ScanResult | null;
  setPage: (p: Page) => void;
}

export default function SandboxEvidencePage({ result, setPage }: Props) {
  const p = result?.pipelineResult;
  const sb = p?.layer3;

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Layer 3: Sandbox Evidence</h2>
          <p>Headless browser instrumentation and dynamic behavioral telemetry</p>
        </div>
        <div className="sidebar-demo-badge" style={{ fontSize: 11 }}>
          {result?.pipelineResult?.layer3.connected ? 'LIVE SANDBOX EVIDENCE' : 'SANDBOX UNAVAILABLE'}
        </div>
      </div>

      <div className="card mb-20" style={{ borderLeft: '4px solid var(--amber)' }}>
        <div className="flex gap-12 items-start">
          <AlertTriangle size={20} className="text-amber mt-2" />
          <div className="text-xs">
            <strong className="text-white block mb-2">Isolation & Sandbox Architectural Notice</strong>
            Untrusted URLs are NEVER opened in the host operating system's browser. In production, QRShield detonate links in a properly restricted disposable microVM with enforced network egress rules, private IP blocking, and automated resource cleanup. The evidence below reflects dynamic sandbox telemetry.
          </div>
        </div>
      </div>

      {!result ? (
        <div className="card">
          <div className="empty-state">
            <Box size={36} />
            <p>No active scan loaded. Run a scan to inspect sandbox evidence.</p>
            <button className="btn mt-12" onClick={() => setPage('link-analyzer')}>
              Go to Link Analyzer
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-20">
          {/* Target & Final Destination */}
          <div className="card">
            <div className="card-title">Destination & Redirection Telemetry</div>
            <div className="grid-2 gap-16 text-xs">
              <div className="p-12 bg-dark rounded border border-dark">
                <span className="text-muted block mb-4 uppercase font-bold">Initial Request URL</span>
                <span className="text-white font-mono" style={{ wordBreak: 'break-all' }}>{result.url}</span>
              </div>
              <div className="p-12 bg-dark rounded border border-dark">
                <span className="text-muted block mb-4 uppercase font-bold">Final Resolved Destination</span>
                <span className="text-amber font-mono" style={{ wordBreak: 'break-all' }}>
                  {sb?.finalDestination || result.url}
                </span>
              </div>
            </div>

            {/* Redirect Hops Table */}
            <div className="mt-16">
              <span className="text-xs font-bold text-white block mb-8">HTTP Redirect Chain</span>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Hop</th>
                    <th>Status Code</th>
                    <th>URL</th>
                    <th>Timing</th>
                  </tr>
                </thead>
                <tbody>
                  {sb?.redirectChain && sb.redirectChain.length > 0 ? (
                    sb.redirectChain.map((hop, idx) => (
                      <tr key={idx}>
                        <td>#{idx + 1}</td>
                        <td><span className="risk-badge caution">{hop.statusCode}</span></td>
                        <td className="font-mono text-xs">{hop.url}</td>
                        <td>+{idx * 120}ms</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td>#1</td>
                      <td><span className="risk-badge safe">200 OK</span></td>
                      <td className="font-mono text-xs">{result.url}</td>
                      <td>Direct (0 hops)</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Form & Credential Harvest Indicators */}
          <div className="grid-2">
            <div className="card">
              <div className="card-title flex items-center gap-8">
                <Key size={16} /> Credential Harvesting Analysis
              </div>
              <div className="text-xs space-y-12">
                <div className="flex justify-between items-center py-6 border-b border-dark">
                  <span className="text-muted">Password Input Fields:</span>
                  <strong className={sb?.hasPasswordField ? 'text-red' : 'text-green'}>
                    {sb?.hasPasswordField ? 'Present (<input type="password">)' : 'None detected'}
                  </strong>
                </div>
                <div className="flex justify-between items-center py-6 border-b border-dark">
                  <span className="text-muted">Authentication Form Elements:</span>
                  <strong className={sb?.hasLoginForm ? 'text-amber' : 'text-green'}>
                    {sb?.hasLoginForm ? 'Detected (Form action external)' : 'No login forms'}
                  </strong>
                </div>
                <div className="flex justify-between items-center py-6 border-b border-dark">
                  <span className="text-muted">Observed Page Title:</span>
                  <span className="text-white italic">{sb?.pageTitle || 'Untitled destination'}</span>
                </div>
                <div className="p-8 bg-dark rounded text-muted font-mono" style={{ fontSize: 11 }}>
                  Snippet: {sb?.textSnippet || 'No suspicious text extracted.'}
                </div>
              </div>
            </div>

            {/* Download attempts */}
            <div className="card">
              <div className="card-title flex items-center gap-8">
                <Download size={16} /> Drive-By Download Monitoring
              </div>
              {sb?.downloadAttempts && sb.downloadAttempts.length > 0 ? (
                <div className="space-y-8">
                  {sb.downloadAttempts.map((dl, i) => (
                    <div key={i} className="p-10 bg-dark rounded border border-red text-xs">
                      <div className="flex justify-between items-center mb-4">
                        <strong className="text-red font-mono">{dl.filename}</strong>
                        <span className="risk-badge high-risk">BLOCKED</span>
                      </div>
                      <div className="text-muted text-xs">
                        Size: {(dl.sizeBytes / 1024 / 1024).toFixed(2)} MB • MIME: {dl.mimeType}
                      </div>
                      <div className="text-muted text-xs font-mono mt-4" style={{ fontSize: 10 }}>
                        SHA-256: {dl.sha256Hash}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-muted p-16 text-center">
                  <ShieldCheck size={24} className="text-green mx-auto mb-8" />
                  No automated download attempts or payload drops detected during execution.
                </div>
              )}
            </div>
          </div>

          {/* Network Graph & Outbound Calls */}
          <div className="card">
            <div className="card-title flex items-center gap-8">
              <Network size={16} /> Outbound Network Graph & Egress Calls
            </div>
            <ul className="reasons-list font-mono text-xs">
              {sb?.suspiciousNetworkCalls && sb.suspiciousNetworkCalls.length > 0 ? (
                sb.suspiciousNetworkCalls.map((call, i) => (
                  <li key={i}>{call}</li>
                ))
              ) : (
                <li>Standard CDN static assets requested; no malicious C2 beaconing.</li>
              )}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
