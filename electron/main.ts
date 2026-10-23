import { app, BrowserWindow, ipcMain, shell, Tray, Menu } from 'electron';
import * as path from 'path';
import * as net from 'net';
import * as fs from 'fs';
import { spawn, ChildProcess } from 'child_process';

let mainWindow: BrowserWindow | null = null;
let helperProcess: ChildProcess | null = null;
let pipeClient: net.Socket | null = null;
let tray: Tray | null = null;
let sandboxReady = false;
let sandboxStarting = false;

let isHoldingMode = false;
let helperConnected = false;

function getConfigPath(): string {
  const userConfigPath = path.join(app.getPath('userData'), '.env');
  const developmentPath = path.join(app.getAppPath(), 'backend/.env');
  return process.env.NODE_ENV === 'development' && fs.existsSync(developmentPath)
    ? developmentPath
    : userConfigPath;
}

function getSandboxComposePath(): string {
  const packagedPath = path.join(process.resourcesPath, 'sandbox', 'docker-compose.yml');
  const developmentPath = path.join(app.getAppPath(), 'backend', 'docker-compose.yml');
  return fs.existsSync(packagedPath) ? packagedPath : developmentPath;
}

function runDockerCompose(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const composePath = getSandboxComposePath();
    if (!fs.existsSync(composePath)) {
      reject(new Error(`Sandbox compose file not found: ${composePath}`));
      return;
    }

    const child = spawn('docker', ['compose', '-f', composePath, ...args], {
      cwd: path.dirname(composePath),
      windowsHide: true,
      stdio: 'ignore',
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Docker Compose exited with code ${code ?? 'unknown'}.`));
    });
  });
}

async function startSandboxService() {
  if (sandboxStarting || sandboxReady) return;
  sandboxStarting = true;
  try {
    await runDockerCompose(['up', '-d', '--build']);
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        const response = await fetch('http://127.0.0.1:4892/health');
        if (response.ok) {
          sandboxReady = true;
          console.log('[QRShield Main] Docker sandbox is ready');
          return;
        }
      } catch { }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    console.warn('[QRShield Main] Docker sandbox did not become ready');
  } catch (error) {
    console.warn('[QRShield Main] Docker sandbox unavailable:', error);
  } finally {
    sandboxStarting = false;
  }
}

// Resolve helper path
function getHelperExecutablePath(): string {
  // In development: windows-helper/bin/Release/QRShieldHelper.exe
  const devPath = path.join(__dirname, '../../windows-helper/bin/Release/QRShieldHelper.exe');
  if (fs.existsSync(devPath)) return devPath;

  const altDevPath = path.join(app.getAppPath(), 'windows-helper/bin/Release/QRShieldHelper.exe');
  if (fs.existsSync(altDevPath)) return altDevPath;

  // In production installer extraResources
  const prodPath = path.join(process.resourcesPath, 'bin', 'QRShieldHelper.exe');
  if (fs.existsSync(prodPath)) return prodPath;

  return devPath;
}

// Spawn the C# Windows Helper process
function startWindowsHelper() {
  const helperExe = getHelperExecutablePath();

  if (!fs.existsSync(helperExe)) {
    console.warn('[QRShield Main] Helper executable not found at:', helperExe);
    return;
  }

  try {
    console.log('[QRShield Main] Launching helper executable:', helperExe);
    helperProcess = spawn(helperExe, [], {
      detached: false,
      stdio: 'ignore',
    });

    ipcMain.handle('qrshield:get-sandbox-status', () => ({
      connected: sandboxReady,
      starting: sandboxStarting,
      endpoint: 'http://127.0.0.1:4892',
    }));

    ipcMain.handle('qrshield:analyze-sandbox', async (_event, url: string) => {
      if (!sandboxReady) {
        await startSandboxService();
      }
      if (!sandboxReady) {
        return {
          status: 'unavailable',
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
          isolationRuntime: 'Docker sandbox unavailable',
          egressEnforced: false,
          connected: false,
          demoMode: false,
          error: 'Docker Desktop is not running or the sandbox image could not start.',
        };
      }

      try {
        const response = await fetch('http://127.0.0.1:4892/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
          signal: AbortSignal.timeout(20000),
        });
        const result = await response.json() as { error?: string };
        if (!response.ok) {
          return {
            status: 'failed',
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
            isolationRuntime: 'Docker Playwright disposable container',
            egressEnforced: false,
            connected: true,
            demoMode: false,
            error: result?.error || `Sandbox returned HTTP ${response.status}.`,
          };
        }
        return result;
      } catch (error) {
        sandboxReady = false;
        return {
          status: 'failed',
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
          isolationRuntime: 'Docker Playwright disposable container',
          egressEnforced: false,
          connected: false,
          demoMode: false,
          error: error instanceof Error ? error.message : 'Sandbox request failed.',
        };
      }
    });

    helperProcess.on('error', (err) => {
      console.error('[QRShield Main] Helper process error:', err);
      helperConnected = false;
    });

    helperProcess.on('exit', (code) => {
      console.log('[QRShield Main] Helper process exited with code:', code);
      helperConnected = false;
    });

    // Connect to Named Pipe after short delay
    setTimeout(connectToNamedPipe, 1200);
  } catch (err) {
    console.error('[QRShield Main] Failed to spawn helper:', err);
  }
}

// Connect to C# Named Pipe Server
function connectToNamedPipe() {
  const pipePath = '\\\\.\\pipe\\QRShieldPipe';
  console.log('[QRShield Main] Connecting to Named Pipe:', pipePath);

  pipeClient = net.connect(pipePath, () => {
    console.log('[QRShield Main] Successfully connected to QRShieldPipe');
    helperConnected = true;
  });

  let buffer = '';

  pipeClient.on('data', (data) => {
    buffer += data.toString('utf8');
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line.trim());
        handleHelperMessage(msg);
      } catch (e) {
        console.error('[QRShield Main] Invalid IPC message from helper:', line);
      }
    }
  });

  pipeClient.on('error', (err) => {
    helperConnected = false;
    // Attempt retry
    setTimeout(connectToNamedPipe, 3000);
  });

  pipeClient.on('close', () => {
    helperConnected = false;
  });
}

function handleHelperMessage(msg: any) {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  switch (msg.type) {
    case 'INSPECTION_MODE_CHANGED':
      isHoldingMode = !!msg.active;
      mainWindow.webContents.send('qrshield:inspection-mode-changed', isHoldingMode);
      break;

    case 'LINK_INTERCEPTED':
      mainWindow.webContents.send('qrshield:link-intercepted', {
        url: msg.url,
        appName: msg.appName,
        controlType: msg.controlType,
        x: msg.x,
        y: msg.y,
      });
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
      break;

    case 'LINK_UNAVAILABLE':
      mainWindow.webContents.send('qrshield:link-unavailable', {
        reason: msg.reason,
        appName: msg.appName,
        x: msg.x,
        y: msg.y,
      });
      break;

    case 'STATUS':
      helperConnected = !!msg.connected;
      break;
  }
}

function sendToHelper(jsonObj: any) {
  if (pipeClient && helperConnected && !pipeClient.destroyed) {
    pipeClient.write(JSON.stringify(jsonObj) + '\n');
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#090d16',
    title: 'QRShield — Windows Link & QR Protection',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.removeMenu();

  const distPath = path.join(__dirname, '../dist/index.html');
  const isDev = process.env.NODE_ENV === 'development';

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else if (fs.existsSync(distPath)) {
    mainWindow.loadFile(distPath);
  } else {
    mainWindow.loadURL('http://localhost:5173');
  }

  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    console.error(`[QRShield Main] Failed to load URL ${validatedURL}: ${errorDescription} (${errorCode})`);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// IPC Handlers from Renderer
ipcMain.handle('qrshield:get-helper-status', () => {
  return {
    connected: helperConnected,
    protectionEnabled: true,
    isHolding: isHoldingMode,
    version: '1.0.0',
  };
});

ipcMain.handle('qrshield:set-config', (_event, config) => {
  sendToHelper({
    type: 'SET_CONFIG',
    ...config,
  });
});

ipcMain.handle('qrshield:send-scan-progress', (_event, { stage, url, progress }) => {
  sendToHelper({
    type: 'SCAN_PROGRESS',
    stage,
    url,
    progress,
  });
});

ipcMain.handle('qrshield:send-scan-result', (_event, { verdict, riskScore, url }) => {
  sendToHelper({
    type: 'SCAN_RESULT',
    verdict,
    riskScore,
    url,
  });
});

ipcMain.handle('qrshield:open-external', (_event, url: string) => {
  if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
    shell.openExternal(url);
  }
});

ipcMain.handle('qrshield:get-api-config-status', () => {
  // Check backend/.env
  const envPath = getConfigPath();
  let hasSafeBrowsing = false;
  let hasGemini = false;
  let geminiMasked = '';
  let safeBrowsingMasked = '';
  let modelName = 'gemini-3-flash-preview';

  if (fs.existsSync(envPath)) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      const sbMatch = content.match(/GOOGLE_SAFE_BROWSING_API_KEY=([^\r\n]*)/);
      if (sbMatch && sbMatch[1].trim()) {
        hasSafeBrowsing = true;
        const v = sbMatch[1].trim();
        safeBrowsingMasked = v.length > 8 ? `${v.slice(0, 4)}...${v.slice(-4)}` : '••••••••';
      }

      const geminiMatch = content.match(/GEMINI_API_KEY=([^\r\n]*)/);
      if (geminiMatch && geminiMatch[1].trim()) {
        hasGemini = true;
        const v = geminiMatch[1].trim();
        geminiMasked = v.length > 8 ? `${v.slice(0, 6)}...${v.slice(-4)}` : '••••••••';
      }

      const modelMatch = content.match(/GEMINI_MODEL=([^\r\n]*)/);
      if (modelMatch && modelMatch[1].trim()) {
        modelName = modelMatch[1].trim();
      }
    } catch { }
  }

  return {
    safeBrowsing: hasSafeBrowsing,
    safeBrowsingMasked,
    gemini: hasGemini,
    geminiMasked,
    geminiModel: modelName,
    sandbox: sandboxReady,
  };
});

ipcMain.handle('qrshield:save-api-keys', (_event, { geminiKey, safeBrowsingKey, modelName }: { geminiKey?: string; safeBrowsingKey?: string; modelName?: string }) => {
  try {
    const envPath = getConfigPath();
    let content = '';
    if (fs.existsSync(envPath)) {
      content = fs.readFileSync(envPath, 'utf8');
    } else {
      content = `# QRShield local configuration\n# Keep this file private and never commit it.\n\nGOOGLE_SAFE_BROWSING_API_KEY=\nGEMINI_API_KEY=\nGEMINI_MODEL=gemini-3-flash-preview\n`;
    }

    if (geminiKey !== undefined) {
      if (/GEMINI_API_KEY=/.test(content)) {
        content = content.replace(/GEMINI_API_KEY=[^\r\n]*/, `GEMINI_API_KEY=${geminiKey.trim()}`);
      } else {
        content += `\nGEMINI_API_KEY=${geminiKey.trim()}`;
      }
    }

    if (safeBrowsingKey !== undefined) {
      if (/GOOGLE_SAFE_BROWSING_API_KEY=/.test(content)) {
        content = content.replace(/GOOGLE_SAFE_BROWSING_API_KEY=[^\r\n]*/, `GOOGLE_SAFE_BROWSING_API_KEY=${safeBrowsingKey.trim()}`);
      } else {
        content += `\nGOOGLE_SAFE_BROWSING_API_KEY=${safeBrowsingKey.trim()}`;
      }
    }

    if (modelName !== undefined) {
      if (/GEMINI_MODEL=/.test(content)) {
        content = content.replace(/GEMINI_MODEL=[^\r\n]*/, `GEMINI_MODEL=${modelName.trim()}`);
      } else {
        content += `\nGEMINI_MODEL=${modelName.trim()}`;
      }
    }

    fs.mkdirSync(path.dirname(envPath), { recursive: true });
    fs.writeFileSync(envPath, content, { encoding: 'utf8', mode: 0o600 });
    return { success: true };
  } catch (err: any) {
    console.error('[QRShield Main] Failed to write backend/.env:', err);
    return { success: false, error: err?.message };
  }
});

ipcMain.handle('qrshield:lookup-safe-browsing', async (_event, url: string) => {
  const envPath = getConfigPath();
  let sbKey = '';

  if (fs.existsSync(envPath)) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      const keyMatch = content.match(/GOOGLE_SAFE_BROWSING_API_KEY=([^\r\n]+)/);
      if (keyMatch && keyMatch[1].trim()) {
        sbKey = keyMatch[1].trim();
      }
    } catch { }
  }

  if (!sbKey) {
    return {
      status: 'unavailable',
      threatFound: false,
      apiConnected: false,
      demoMode: false,
      error: 'Google Safe Browsing API key is not configured.',
    };
  }

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${sbKey}`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'qrshield-windows',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['WINDOWS', 'ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });

    if (res.ok) {
      const data = (await res.json()) as any;
      const matches = data.matches || [];
      if (matches.length > 0) {
        return {
          status: 'completed',
          threatFound: true,
          threatType: matches[0].threatType || 'MALWARE',
          platformType: matches[0].platformType || 'WINDOWS',
          cacheDurationSeconds: 300,
          apiConnected: true,
          demoMode: false,
        };
      }
      return {
        status: 'completed',
        threatFound: false,
        apiConnected: true,
        demoMode: false,
      };
    } else {
      const errText = await res.text();
      console.warn('[QRShield Main] Safe Browsing API error response:', errText);
      return {
        status: 'failed',
        threatFound: false,
        apiConnected: false,
        demoMode: false,
        error: `Safe Browsing API returned HTTP ${res.status}: ${errText.slice(0, 200)}`,
      };
    }
  } catch (err: any) {
    console.error('[QRShield Main] Safe Browsing fetch failure:', err);
    return {
      status: 'failed',
      threatFound: false,
      apiConnected: false,
      demoMode: false,
      error: err?.message || 'Safe Browsing request failed.',
    };
  }
});

ipcMain.handle('qrshield:analyze-gemini', async (_event, evidence) => {
  const envPath = getConfigPath();
  let geminiKey = '';
  let modelName = 'gemini-3-flash-preview';

  if (fs.existsSync(envPath)) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      const keyMatch = content.match(/GEMINI_API_KEY=([^\r\n]+)/);
      if (keyMatch && keyMatch[1].trim()) {
        geminiKey = keyMatch[1].trim();
      }
      const modelMatch = content.match(/GEMINI_MODEL=([^\r\n]+)/);
      if (modelMatch && modelMatch[1].trim()) {
        modelName = modelMatch[1].trim();
      }
    } catch { }
  }

  if (!geminiKey) {
    return {
      status: 'completed',
      model: modelName,
      threatAssessment: 'Gemini analysis is unavailable because no API key is configured.',
      confidenceLevel: 'LOW',
      explanation: 'No Gemini API key was found in the local configuration.',
      likelyAttackType: 'Uncertain',
      importantUncertainties: ['API key missing'],
      recommendedUserAction: 'Configure GEMINI_API_KEY in backend/.env',
      demoMode: false,
      connected: false,
    };
  }

  try {
    const prompt = `You are QRShield's AI Threat Analyst. Analyze the target URL and evidence:
URL: ${evidence.url}
Layer 1 Safe Browsing Threat: ${evidence.layer1?.threatFound ? evidence.layer1.threatType : 'No blacklist match'}
Layer 2 Heuristic Anomalies: ${(evidence.layer2?.anomaliesDetected || []).join('; ')}
Layer 3 Sandbox Login Form: ${evidence.layer3?.hasLoginForm ? 'Yes' : 'No'}
Layer 3 Sandbox Downloads: ${(evidence.layer3?.downloadAttempts || []).map((d: any) => d.filename).join(', ') || 'None'}

Respond strictly with valid JSON with keys:
"threatAssessment": string,
"confidenceLevel": "HIGH" | "MEDIUM" | "LOW",
"likelyAttackType": "Credential Phishing" | "Drive-by Malware" | "Tech Support Scam" | "Brand Impersonation" | "Benign",
"explanation": string,
"importantUncertainties": string[],
"recommendedUserAction": string`;

    const modelsToTry = [...new Set([modelName, 'gemini-3-flash-preview', 'gemini-3.1-flash-lite'])];
    let lastError = '';
    let responseJson: any = null;

    for (const m of modelsToTry) {
      try {
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${geminiKey}`;
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: 0.1,
              responseMimeType: 'application/json'
            }
          })
        });

        if (res.ok) {
          const data = (await res.json()) as any;
          const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            responseJson = JSON.parse(text);
            modelName = m;
            break;
          }
        } else {
          lastError = await res.text();
        }
      } catch (err: any) {
        lastError = err?.message || String(err);
      }
    }

    if (responseJson) {
      return {
        status: 'completed',
        model: modelName,
        threatAssessment: responseJson.threatAssessment || 'AI threat evaluation completed.',
        confidenceLevel: responseJson.confidenceLevel || 'HIGH',
        explanation: responseJson.explanation || 'Analyzed structured indicators.',
        likelyAttackType: responseJson.likelyAttackType || 'Brand Impersonation',
        importantUncertainties: responseJson.importantUncertainties || [],
        recommendedUserAction: responseJson.recommendedUserAction || 'Proceed with caution.',
        demoMode: false,
        connected: true,
      };
    }

    return {
      status: 'failed',
      model: modelName,
      threatAssessment: 'Gemini returned no structured assessment.',
      confidenceLevel: 'LOW',
      explanation: 'The Gemini response did not contain valid structured analysis.',
      likelyAttackType: 'Uncertain',
      importantUncertainties: ['Invalid Gemini response'],
      recommendedUserAction: 'Treat this scan as inconclusive and do not enter credentials.',
      demoMode: false,
      connected: true,
      error: lastError || 'Gemini response did not contain valid JSON.',
    };
  } catch (err: any) {
    return {
      status: 'failed',
      model: modelName,
      threatAssessment: 'Analysis error: ' + (err?.message || 'Unknown'),
      confidenceLevel: 'LOW',
      explanation: 'Failed to complete AI threat assessment.',
      likelyAttackType: 'Uncertain',
      importantUncertainties: ['Inference request failed'],
      recommendedUserAction: 'Rely on Layer 1-3 findings.',
      demoMode: false,
      connected: true,
      error: err?.message,
    };
  }
});

// Clean shutdown
function cleanupAndQuit() {
  sendToHelper({ type: 'SHUTDOWN' });
  if (pipeClient) {
    pipeClient.destroy();
    pipeClient = null;
  }
  if (helperProcess && !helperProcess.killed) {
    helperProcess.kill();
    helperProcess = null;
  }
}

app.whenReady().then(() => {
  createWindow();
  startWindowsHelper();
  void startSandboxService();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', cleanupAndQuit);
app.on('window-all-closed', () => {
  cleanupAndQuit();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
