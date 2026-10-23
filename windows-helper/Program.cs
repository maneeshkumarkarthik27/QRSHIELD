using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace QRShieldHelper
{
    internal static class Program
    {
        private static Mutex _singleInstanceMutex;
        private static OverlayWindow _overlay;
        private static LowLevelHooks _hooks;
        private static IpcServer _ipc;

        [STAThread]
        private static void Main(string[] args)
        {
            // Ensure single running instance of helper
            bool createdNew;
            _singleInstanceMutex = new Mutex(true, "QRShieldHelper_SingleInstanceMutex", out createdNew);
            if (!createdNew)
            {
                // Already running
                return;
            }

            // Set high DPI awareness
            try
            {
                SetProcessDPIAware();
            }
            catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Setup overlay window
            _overlay = new OverlayWindow();

            // Setup IPC server
            _ipc = new IpcServer();
            _ipc.MessageReceived += OnIpcMessageReceived;
            _ipc.ClientConnected += OnIpcClientConnected;
            _ipc.ClientDisconnected += OnIpcClientDisconnected;
            _ipc.Start();

            // Setup low level keyboard and mouse hooks
            _hooks = new LowLevelHooks(
                _overlay,
                delegate(bool active)
                {
                    long ts = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds;
                    _ipc.SendJson(string.Format("{{\"type\":\"INSPECTION_MODE_CHANGED\",\"active\":{0},\"timestamp\":{1}}}",
                        active.ToString().ToLower(), ts));
                },
                delegate(LinkInspectionResult result, int x, int y)
                {
                    if (!string.IsNullOrEmpty(result.Url))
                    {
                        string escapedUrl = EscapeJson(result.Url);
                        string escapedApp = EscapeJson(result.ApplicationName);
                        string escapedCtrl = EscapeJson(result.ControlType);

                        _overlay.SetScanState(true, "Intercepted link! Scanning destination...", result.Url, 15);

                        _ipc.SendJson(string.Format("{{\"type\":\"LINK_INTERCEPTED\",\"url\":\"{0}\",\"appName\":\"{1}\",\"controlType\":\"{2}\",\"x\":{3},\"y\":{4}}}",
                            escapedUrl, escapedApp, escapedCtrl, x, y));
                    }
                    else
                    {
                        string reason = EscapeJson(result.FailureReason ?? "Link destination unavailable — not inspected");
                        string escapedApp = EscapeJson(result.ApplicationName);

                        _overlay.SetScanState(false, "Link destination unavailable — not inspected", "", 0);

                        _ipc.SendJson(string.Format("{{\"type\":\"LINK_UNAVAILABLE\",\"reason\":\"{0}\",\"appName\":\"{1}\",\"x\":{2},\"y\":{3}}}",
                            reason, escapedApp, x, y));
                    }
                });

            // Clean shutdown handlers
            AppDomain.CurrentDomain.ProcessExit += delegate { ShutdownClean(); };
            Application.ApplicationExit += delegate { ShutdownClean(); };
            AppDomain.CurrentDomain.UnhandledException += delegate { ShutdownClean(); };

            // Run application loop
            Application.Run();
        }

        private static void OnIpcClientConnected()
        {
            SendStatus();
        }

        private static void OnIpcClientDisconnected()
        {
            // Reset overlay and hooks if electron disconnected
            if (_hooks != null)
            {
                _hooks.ResetInspectionMode();
            }
        }

        private static void SendStatus()
        {
            bool prot = _hooks != null && _hooks.ProtectionEnabled;
            bool holding = _hooks != null && _hooks.IsHolding5;
            _ipc.SendJson(string.Format("{{\"type\":\"STATUS\",\"connected\":true,\"protectionEnabled\":{0},\"isHolding\":{1},\"version\":\"1.0.0\"}}",
                prot.ToString().ToLower(), holding.ToString().ToLower()));
        }

        private static void OnIpcMessageReceived(string json)
        {
            try
            {
                if (string.IsNullOrEmpty(json)) return;

                if (json.Contains("\"SET_CONFIG\""))
                {
                    if (json.Contains("\"protectionEnabled\":false"))
                    {
                        if (_hooks != null)
                        {
                            _hooks.ProtectionEnabled = false;
                            _hooks.ResetInspectionMode();
                        }
                    }
                    else if (json.Contains("\"protectionEnabled\":true"))
                    {
                        if (_hooks != null) _hooks.ProtectionEnabled = true;
                    }

                    // Check shortcut key if provided
                    Match matchKey = Regex.Match(json, "\"shortcut\"\\s*:\\s*\"([^\"]+)\"");
                    if (matchKey.Success)
                    {
                        string keyStr = matchKey.Groups[1].Value.Trim().ToUpperInvariant();
                        if (keyStr == "5") _hooks.ShortcutVkCode = 0x35;
                        else if (keyStr == "6") _hooks.ShortcutVkCode = 0x36;
                        else if (keyStr == "F1") _hooks.ShortcutVkCode = 0x70;
                    }

                    SendStatus();
                }
                else if (json.Contains("\"SCAN_PROGRESS\""))
                {
                    Match stageMatch = Regex.Match(json, "\"stage\"\\s*:\\s*\"([^\"]+)\"");
                    Match urlMatch = Regex.Match(json, "\"url\"\\s*:\\s*\"([^\"]+)\"");
                    Match progMatch = Regex.Match(json, "\"progress\"\\s*:\\s*([0-9]+)");

                    string stage = stageMatch.Success ? stageMatch.Groups[1].Value : "Scanning...";
                    string url = urlMatch.Success ? urlMatch.Groups[1].Value : "";
                    int prog = progMatch.Success ? int.Parse(progMatch.Groups[1].Value) : 50;

                    _overlay.SetScanState(true, stage, url, prog);
                }
                else if (json.Contains("\"SCAN_RESULT\""))
                {
                    Match verdMatch = Regex.Match(json, "\"verdict\"\\s*:\\s*\"([^\"]+)\"");
                    Match scoreMatch = Regex.Match(json, "\"riskScore\"\\s*:\\s*([0-9]+)");
                    Match urlMatch = Regex.Match(json, "\"url\"\\s*:\\s*\"([^\"]+)\"");

                    string verdict = verdMatch.Success ? verdMatch.Groups[1].Value : "INCONCLUSIVE";
                    int score = scoreMatch.Success ? int.Parse(scoreMatch.Groups[1].Value) : 0;
                    string url = urlMatch.Success ? urlMatch.Groups[1].Value : "";

                    _overlay.SetScanResult(verdict, score, url);
                }
                else if (json.Contains("\"RESET\""))
                {
                    if (_hooks != null) _hooks.ResetInspectionMode();
                }
                else if (json.Contains("\"PING\""))
                {
                    SendStatus();
                }
                else if (json.Contains("\"SHUTDOWN\""))
                {
                    ShutdownClean();
                    Application.Exit();
                }
            }
            catch { }
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }

        private static void ShutdownClean()
        {
            try
            {
                if (_hooks != null)
                {
                    _hooks.ResetInspectionMode();
                    _hooks.Dispose();
                }
                if (_overlay != null) _overlay.Dispose();
                if (_ipc != null) _ipc.Dispose();
                if (_singleInstanceMutex != null)
                {
                    _singleInstanceMutex.ReleaseMutex();
                    _singleInstanceMutex.Dispose();
                }
            }
            catch { }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();
    }
}
