# QRShield System Architecture

## 1. Overview
QRShield is a Windows desktop cybersecurity application designed to prevent phishing, drive-by malware, and credential-harvesting attacks initiated via QR codes and hyperlinks. It provides an immediate, desktop-wide **Hold-5 Inspection Mode**, a high-visibility red cursor overlay, and an automated **Four-Layer Link Analysis Pipeline**.

```
+-----------------------------------------------------------------------------------+
|                              Windows Desktop OS                                   |
|   (Browsers: Chrome / Edge, Word, Outlook, PDF Readers, Chat, Desktop Icons)      |
+-----------------------------------------------------------------------------------+
       |                                                               |
  [WH_KEYBOARD_LL] (Hold "5")                                  [WH_MOUSE_LL] (Click)
       |                                                               |
       v                                                               v
+-----------------------------------------------------------------------------------+
|               QRShield Native Windows Helper (C# / .NET WinForms / WPF)           |
|                                                                                   |
|  - Global Keyboard Hook (Digit 5 / Numpad 5 detection, debounce, pass-through)     |
|  - Global Mouse Hook & Virtual Screen Tracker (Multi-monitor support)             |
|  - System-wide Layered Transparent Overlay (Non-activating, topmost, click-thru)  |
|  - Windows UI Automation (UIA) & IAccessible Hyperlink Extraction Engine         |
|  - Local Named Pipe Server (\\\\.\\pipe\\QRShieldPipe - Local Security ACL)       |
+-----------------------------------------------------------------------------------+
       |                                                               ^
       | Bidirectional Local IPC (Named Pipe JSON Messages)            |
       v                                                               |
+-----------------------------------------------------------------------------------+
|                         Electron Main Process (Node.js)                           |
|                                                                                   |
|  - Process Lifecycle & Helper Supervisor (Spawn, healthcheck, clean exit)         |
|  - Tray Icon & Notification Management                                            |
|  - Secure Preload Bridge (`contextIsolation: true`, `nodeIntegration: false`)     |
|  - IPC Relay & Origin Sanitization                                                |
+-----------------------------------------------------------------------------------+
       |
       | contextBridge.exposeInMainWorld ('qrshield')
       v
+-----------------------------------------------------------------------------------+
|                         Desktop UI (React + TypeScript)                           |
|                                                                                   |
|  - Dashboard & Protection Controls                                                |
|  - 4-Layer Pipeline Visualizer                                                    |
|  - Floating Inspection Panel                                                      |
|  - QR Code Image Analyzer & Camera Feed                                           |
|  - Sandbox Evidence Viewer & Gemini Threat Analyst Report                         |
|  - Settings & Credential Configuration View                                       |
+-----------------------------------------------------------------------------------+
       |
       v
+-----------------------------------------------------------------------------------+
|                     Four-Layer Analysis Pipeline (Provider Architecture)          |
|                                                                                   |
|  [Layer 1] SafeBrowsingProvider    --> Google Safe Browsing / Web Risk            |
|  [Layer 2] LocalUrlClassifier      --> Punycode, Hostname Heuristics, IP Check   |
|  [Layer 3] SandboxAnalysisProvider --> Docker Playwright Disposable Container     |
|  [Layer 4] GeminiThreatAnalyst     --> Multi-Modal Evidence Reasoning (3.8-Flash) |
+-----------------------------------------------------------------------------------+
```

---

## 2. Component Responsibilities

### A. Desktop UI (React + TypeScript)
- **Role**: Presentation and interaction layer.
- **Pages**:
  1. `Dashboard`: Core system telemetry, protection toggle, quick/deep scan switch, four-layer pipeline monitor, recent scan logs, DEMO status badge.
  2. `Cursor Protection`: Instructions for the Hold-5 shortcut, multi-monitor configuration display, interactive link testbed, helper connection diagnostic.
  3. `Link Analyzer`: Manual URL inspection with real-time layer-by-layer step progress.
  4. `QR Scanner`: Upload, drag-and-drop, and simulated camera decode feeding into the 4-layer pipeline.
  5. `Scan History`: Persistent audit log with verdict filters (MALICIOUS, SUSPICIOUS, INCONCLUSIVE, NO THREAT DETECTED).
  6. `Scan Details`: Deep dive into layer timings, HTTP redirects, and technical metadata.
  7. `Sandbox Evidence`: DOM indicators, credential harvest forms, download detection, and network graph.
  8. `AI Threat Report`: Gemini 3.8 Flash analysis report detailing confidence score, attack vectors, uncertainties, and mitigation.
  9. `Settings`: Shortcut customization, auto-blocking policies, and API key configuration checklist.

### B. Electron Main Process
- **Role**: Application lifecycle manager, secure container, and native process supervisor.
- **Security Posture**:
  - `contextIsolation: true`: Prevents renderer scripts from tampering with Electron internals.
  - `nodeIntegration: false`: Restricts Node.js runtime access exclusively to the main process.
  - `sandbox: true`: Standard Chromium sandbox enforced on all renderer windows.
  - No arbitrary command execution: Renderer communicates strictly via strongly typed IPC channels (`qrshield:get-status`, `qrshield:set-config`, `qrshield:run-scan`).
- **Helper Supervision**:
  - Spawns `QRShieldHelper.exe` upon application boot.
  - Monitored via heartbeat messages over the Named Pipe.
  - Implements guaranteed clean shutdown: terminating the main process terminates the helper and resets cursor state immediately.

### C. Native Windows Helper (C# / .NET)
- **Role**: System-wide input interception, multi-monitor transparent rendering, and accessible link extraction.
- **Key Modules**:
  1. `LowLevelHooks`: Installs `WH_KEYBOARD_LL` and `WH_MOUSE_LL` hooks. Filters key repeats, detects hold state of top-row `5` (VK_5 = 0x35) and numpad `5` (VK_NUMPAD5 = 0x65), passes keystrokes through to active applications so normal typing is never blocked.
  2. `VirtualScreenOverlay`: Win32 layered, transparent, topmost window spanning `GetSystemMetrics(SM_XVIRTUALSCREEN)` to `(SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN)`. Never steals keyboard focus (`WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT`). Renders high-visibility animated red reticle and floating status card.
  3. `UIAutomationLinkExtractor`: Inspects destination coordinates on click. Leverages `UIAutomationClient` (`ValuePattern`, `LegacyIAccessiblePattern`, `HyperlinkControlTypeId`, `AddressBandRoot`) to identify true destination URLs before host browser launch.
  4. `NamedPipeServer`: IPC interface over `\\.\pipe\QRShieldPipe` secured with local user DACL (disallowing network or cross-session access).

### D. Four-Layer Link Analysis Pipeline
- **Layer 1: Google Safe Browsing**:
  - Interface: `SafeBrowsingProvider`
  - Distinguishes confirmed threat matches, no-matches, quota errors, and missing credentials.
  - Immediate short-circuit block on confirmed threat.
- **Layer 2: Local URL Classifier**:
  - Interface: `LocalUrlClassifier`
  - Heuristic analysis of IP addresses, Punycode/homoglyphs, URL parameter entropy, multiple subdomains, userinfo bypass attempts, and malicious TLD patterns.
  - Emits: `LOWER RISK`, `SUSPICIOUS`, or `INSUFFICIENT EVIDENCE`.
- **Layer 3: Isolated Browser Sandbox**:
  - Interface: `SandboxAnalysisProvider`
  - Executes links in a disposable Docker Playwright container with a read-only filesystem, dropped Linux capabilities, no-new-privileges, and explicit private-network request blocking.
  - The service blocks loopback/private destinations and cancels downloads after collecting metadata.
  - Collects redirect chains, credential input forms, file download triggers, network requests, and DOM state.
  - If Docker is unavailable, the pipeline returns `INCONCLUSIVE`; it never creates simulated evidence.
- **Layer 4: Gemini AI Threat Analyst**:
  - Interface: `GeminiThreatAnalyst`
  - Evaluates multi-modal evidence from Layers 1-3 using the configured Gemini model (default: `gemini-3-flash-preview`).
  - Determines attack intent, confidence rating, uncertainties, and user safety advice.

### E. Configuration & Secrets Management
- Secrets template in `backend/.env.example`.
- Development credentials may be stored in `backend/.env`; installed builds use `%APPDATA%\QRShield\.env`.
- Installer resources include only sandbox source files, never `backend/.env`.
- No secrets are ever packaged in renderer bundles or committed to Git.
- UI displays provider readiness (Configured vs Missing) without exposing raw keys.

---

## 3. Communication Protocol (Named Pipe IPC)

The Electron application and C# Windows Helper communicate over a bi-directional local named pipe: `\\.\pipe\QRShieldPipe`.

### Messages from Helper to Electron:
```json
{
  "type": "INSPECTION_MODE_CHANGED",
  "active": true,
  "timestamp": 1729792000000
}
```
```json
{
  "type": "LINK_INTERCEPTED",
  "url": "https://secure-login-chase.com.suspicious-auth.xyz/verify",
  "sourceApp": "msedge.exe",
  "controlType": "Hyperlink",
  "x": 450,
  "y": 620
}
```
```json
{
  "type": "LINK_UNAVAILABLE",
  "reason": "Control does not expose accessible URL pattern",
  "sourceApp": "notepad.exe",
  "x": 300,
  "y": 400
}
```

### Messages from Electron to Helper:
```json
{
  "type": "SET_CONFIG",
  "protectionEnabled": true,
  "shortcutKey": "5",
  "highRiskBlocking": true
}
```
```json
{
  "type": "SCAN_PROGRESS",
  "layer": 2,
  "stageName": "Local URL Classification",
  "progress": 50
}
```
```json
{
  "type": "SCAN_COMPLETED",
  "verdict": "MALICIOUS",
  "riskScore": 92,
  "reasons": ["Known credential phishing domain", "Punycode spoofing detected"]
}
```
