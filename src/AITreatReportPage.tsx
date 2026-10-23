import type { ScanResult, Page } from './types';
import {
  Sparkles,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  Lock,
  ExternalLink,
} from 'lucide-react';

interface Props {
  result: ScanResult | null;
  setPage: (p: Page) => void;
}

export default function AITreatReportPage({ result, setPage }: Props) {
  const p = result?.pipelineResult;
  const ai = p?.layer4;

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>Layer 4: Gemini AI Threat Analyst</h2>
          <p>Multi-modal threat reasoning powered by Gemini 3.8 Flash</p>
        </div>
        <div
          className="risk-badge"
          style={{
            fontSize: 11,
            background: ai?.connected ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            color: ai?.connected ? '#34d399' : '#f87171',
            border: `1px solid ${ai?.connected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            padding: '4px 10px',
            borderRadius: 6,
            fontWeight: 700,
          }}
        >
          {ai?.connected ? (
            <>
              <CheckCircle2 size={12} />
              GEMINI 3.8 FLASH CONNECTED
            </>
          ) : (
            <>
              <HelpCircle size={12} />
              DEMO — SIMULATED REASONING
            </>
          )}
        </div>
      </div>

      {/* Security Architecture Alert */}
      <div className="card mb-20" style={{ borderLeft: '4px solid var(--blue)' }}>
        <div className="flex gap-12 items-start">
          <Lock size={20} className="text-blue mt-2" />
          <div className="text-xs">
            <strong className="text-white block mb-2">Prompt Injection & Untrusted Data Isolation</strong>
            All website text, DOM elements, and sandbox telemetry are treated strictly as <em>untrusted data</em>. The threat analyst model (<code>gemini-3.8-flash</code>) cannot execute arbitrary commands, browse the web without supervision, or override a confirmed threat match from Layer 1.
          </div>
        </div>
      </div>

      {!result ? (
        <div className="card">
          <div className="empty-state">
            <Sparkles size={36} />
            <p>No scan selected. Run a scan to generate an AI threat intelligence assessment.</p>
            <button className="btn mt-12" onClick={() => setPage('link-analyzer')}>
              Scan a Link Now
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-20">
          {/* Executive Threat Assessment Card */}
          <div className="card">
            <div className="flex justify-between items-center mb-16 pb-12 border-b border-dark">
              <div>
                <span className="text-xs uppercase text-muted font-bold">Threat Evaluation Engine</span>
                <div className="font-bold text-lg text-white flex items-center gap-8 mt-2">
                  <Sparkles size={18} className="text-blue" />
                  Gemini 3.8 Flash Threat Assessment
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs uppercase text-muted font-bold block mb-4">Analyst Confidence</span>
                <span className={`risk-badge ${ai?.confidenceLevel === 'HIGH' ? 'high-risk' : ai?.confidenceLevel === 'MEDIUM' ? 'caution' : 'safe'}`}>
                  {ai?.confidenceLevel || 'HIGH'} CONFIDENCE
                </span>
              </div>
            </div>

            <div className="p-16 bg-dark rounded border border-dark mb-16">
              <span className="text-xs uppercase text-muted font-bold block mb-4">Core Verdict & Summary</span>
              <p className="text-white text-sm font-medium leading-relaxed">
                {ai?.threatAssessment || result.reasons[0] || 'Standard risk heuristics verified.'}
              </p>
            </div>

            <div className="grid-2 gap-16 text-xs">
              <div className="p-12 bg-dark rounded border border-dark">
                <span className="text-muted block mb-4 uppercase font-bold">Classified Attack Vector</span>
                <strong className="text-amber text-sm font-bold">
                  {ai?.likelyAttackType || 'Brand Impersonation / Credential Phishing'}
                </strong>
              </div>
              <div className="p-12 bg-dark rounded border border-dark">
                <span className="text-muted block mb-4 uppercase font-bold">Evaluation Model Target</span>
                <strong className="text-white text-sm font-mono">
                  {ai?.model || 'gemini-3.8-flash'}
                </strong>
              </div>
            </div>
          </div>

          {/* Explanation of Evidence */}
          <div className="card">
            <div className="card-title">Evidence Synthesis & Attack Logic</div>
            <p className="text-xs text-muted mb-12 leading-relaxed">
              {ai?.explanation || 'The model synthesized telemetry from Google Safe Browsing, local URL lexical heuristics, and dynamic sandbox form indicators to assess deceptive intent.'}
            </p>
            <ul className="reasons-list text-xs">
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          {/* Important Uncertainties */}
          <div className="card">
            <div className="card-title flex items-center gap-8">
              <HelpCircle size={16} /> Key Uncertainties & Visibility Boundaries
            </div>
            <p className="text-xs text-muted mb-8">
              Reliable security requires documenting what cannot be proven:
            </p>
            <ul className="reasons-list text-xs">
              {ai?.importantUncertainties && ai.importantUncertainties.length > 0 ? (
                ai.importantUncertainties.map((u, i) => (
                  <li key={i} className="text-muted">{u}</li>
                ))
              ) : (
                <li className="text-muted">Zero-hour campaigns may bypass blacklist telemetry prior to global community indexing.</li>
              )}
            </ul>
          </div>

          {/* Recommended User Action */}
          <div className="card" style={{ borderLeft: '4px solid var(--green)' }}>
            <div className="card-title flex items-center gap-8 text-white">
              <CheckCircle2 size={16} className="text-green" /> Recommended Protective Action
            </div>
            <p className="text-white text-sm font-semibold mb-8">
              {ai?.recommendedUserAction || result.recommendedAction}
            </p>
            <p className="text-xs text-muted">
              QRShield blocks high-risk URLs automatically when protection mode is enabled.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
