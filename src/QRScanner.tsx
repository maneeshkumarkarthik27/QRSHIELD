import { useState, useRef } from 'react';
import jsQR from 'jsqr';
import type { ScanResult, Page } from './types';
import { PipelineOrchestrator } from './services/pipeline/PipelineOrchestrator';
import {
  QrCode,
  Upload,
  X,
  Search,
  AlertTriangle,
  Image,
  Zap,
  Layers,
  Box,
  Sparkles,
} from 'lucide-react';

interface Props {
  addToHistory: (r: ScanResult) => void;
  setDetailResult: (r: ScanResult | null) => void;
  showToast: (msg: string) => void;
  setPage?: (p: Page) => void;
}

export default function QRScanner({ addToHistory, setDetailResult, showToast, setPage }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const orchestrator = new PipelineOrchestrator();

  const handleFile = (f: File) => {
    if (!f.type.startsWith('image/')) {
      showToast('Please upload an image file.');
      return;
    }
    setFile(f);
    setResult(null);
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target?.result as string);
    reader.readAsDataURL(f);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const runPipelineOnUrl = async (qrUrl: string) => {
    setScanning(true);
    setProgress(15);
    setResult(null);

    try {
      const pResult = await orchestrator.runScan(qrUrl, 'deep', 'QR Scanner', (prog) => {
        setProgress(Math.min(95, prog.currentLayer * 25));
      });

      const legacyResult: ScanResult = {
        id: pResult.id,
        url: pResult.url,
        domain: pResult.domain,
        riskScore: pResult.riskScore,
        verdict: pResult.verdict,
        scanType: 'qr',
        timestamp: pResult.startTime,
        https: pResult.url.startsWith('https://'),
        redirects: pResult.layer3.redirectChain.length > 1,
        misleadingDomain: pResult.layer2.anomaliesDetected.some((a) => a.toLowerCase().includes('misleading')),
        suspiciousPatterns: pResult.layer2.anomaliesDetected,
        reputation: pResult.verdict === 'MALICIOUS' ? 'poor' : pResult.verdict === 'SUSPICIOUS' ? 'unknown' : 'good',
        reasons: pResult.reasons,
        recommendedAction: pResult.recommendedAction,
        pipelineResult: pResult,
      };

      setProgress(100);
      setResult(legacyResult);
      addToHistory(legacyResult);
    } catch {
      showToast('Error during QR pipeline inspection.');
    } finally {
      setScanning(false);
    }
  };

  const handleScan = async () => {
    if (!file) return;

    try {
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement('canvas');
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Unable to create an image decoding context.');

      context.drawImage(bitmap, 0, 0);
      const imageData = context.getImageData(0, 0, bitmap.width, bitmap.height);
      const decoded = jsQR(imageData.data, imageData.width, imageData.height);
      bitmap.close();

      if (!decoded?.data) {
        showToast('No QR code could be decoded from this image.');
        return;
      }

      let decodedUrl: URL;
      try {
        decodedUrl = new URL(decoded.data);
      } catch {
        showToast('The QR code does not contain a valid URL.');
        return;
      }

      if (decodedUrl.protocol !== 'http:' && decodedUrl.protocol !== 'https:') {
        showToast('Only HTTP and HTTPS QR destinations are supported.');
        return;
      }

      await runPipelineOnUrl(decodedUrl.toString());
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Unable to decode the QR image.');
    }
  };

  const clearAll = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    setProgress(0);
  };

  const removeImage = () => {
    setFile(null);
    setPreview(null);
  };

  const riskClass = (r: ScanResult) => {
    if (r.verdict === 'MALICIOUS' || r.verdict === 'HIGH RISK') return 'high-risk';
    if (r.verdict === 'SUSPICIOUS' || r.verdict === 'CAUTION') return 'caution';
    if (r.verdict === 'INCONCLUSIVE') return 'text-muted';
    return 'safe';
  };

  return (
    <div>
      <div className="page-header flex justify-between items-center">
        <div>
          <h2>QR Scanner</h2>
          <p>Inspect physical & digital QR codes for embedded malicious payloads</p>
        </div>
        <div className="sidebar-demo-badge" style={{ fontSize: 11 }}>
          LIVE QR DECODING
        </div>
      </div>

      <div className="grid-2 mb-20">
        {/* Upload area */}
        <div className="card">
          <div className="card-title">Upload QR Code Image</div>

          {!preview ? (
            <div
              className={`drop-zone ${dragOver ? 'drag-over' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload size={28} />
              <p>Drag & drop a QR image here<br />or click to browse local files</p>
            </div>
          ) : (
            <div className="image-preview mb-12">
              <img src={preview} alt="QR preview" />
              <button className="remove-btn" onClick={removeImage} aria-label="Remove image">
                <X size={14} />
              </button>
            </div>
          )}

          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            style={{ display: 'none' }}
            onChange={(e) => {
              if (e.target.files?.[0]) handleFile(e.target.files[0]);
            }}
          />

          <div className="flex gap-8 mt-12">
            <button className="btn" onClick={() => fileInputRef.current?.click()}>
              <Image size={14} /> Browse Image
            </button>
            <button
              className="btn btn-primary"
              onClick={handleScan}
              disabled={!file || scanning}
            >
              <Search size={14} /> Scan Uploaded QR
            </button>
          </div>

          <div className="inline-notice mt-12">
            <AlertTriangle />
            <span>
              The image is decoded locally. Only the decoded HTTP(S) URL is sent to the live inspection pipeline.
            </span>
          </div>
        </div>

        {/* Decoder information */}
        <div className="card">
          <div className="card-title">Safe QR Handling</div>
          <div className="qr-scanner-frame mb-16">
            <div className="corner tl" />
            <div className="corner tr" />
            <div className="corner bl" />
            <div className="corner br" />
            <QrCode size={48} style={{ color: 'var(--text-muted)' }} />
          </div>
          <div style={{ textAlign: 'center' }}>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              QR content is never opened automatically. It is inspected before any navigation.
            </p>
          </div>
        </div>
      </div>

      {/* Progress */}
      {scanning && (
        <div className="card mb-20">
          <div className="card-title scanning-pulse">Decoding & Running Four-Layer Pipeline…</div>
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 8 }}>
            Decoding QR matrix pattern &rarr; Checking Safe Browsing &rarr; Evaluating URL Heuristics &rarr; Sandbox Detonation &rarr; Gemini Reasoning...
          </div>
        </div>
      )}

      {/* Result */}
      {result && !scanning && (
        <div className="card">
          <div className="card-title flex justify-between items-center">
            <span>Decoded QR Result & Four-Layer Findings</span>
            <span className="text-xs text-muted font-mono">SIMULATED QR TARGET</span>
          </div>

          <div className="flex items-center gap-10 mb-16">
            <div className={`risk-score-circle ${riskClass(result)}`}>
              {result.riskScore}
            </div>
            <div>
              <div className="flex items-center gap-8 mb-4">
                <span className={`risk-badge ${riskClass(result)}`} style={result.verdict === 'INCONCLUSIVE' ? { background: '#334155', color: '#cbd5e1' } : {}}>
                  {result.verdict}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 2 }}>
                Threat Risk Score: <strong>{result.riskScore}</strong> / 100
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                Extracted URL: <span className="font-mono text-amber">{result.url}</span>
              </div>
            </div>
          </div>

          <div className="detail-section">
            <h4>Pipeline Findings</h4>
            <ul className="detail-reasons">
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          <div className="flex gap-8 flex-wrap">
            <button className="btn btn-primary" onClick={() => { setDetailResult(result); setPage?.('scan-details'); }}>
              <Layers size={14} /> View 4-Layer Details
            </button>
            <button className="btn" onClick={() => { setDetailResult(result); setPage?.('sandbox-evidence'); }}>
              <Box size={14} /> Sandbox Evidence
            </button>
            <button className="btn" onClick={() => { setDetailResult(result); setPage?.('ai-report'); }}>
              <Sparkles size={14} /> Gemini Threat Report
            </button>
            <button className="btn btn-ghost" onClick={clearAll}>
              <X size={14} /> Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
