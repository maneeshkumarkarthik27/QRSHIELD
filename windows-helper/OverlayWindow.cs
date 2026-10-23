using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace QRShieldHelper
{
    public class OverlayWindow : Form
    {
        private const int WS_EX_TOPMOST = 0x00000008;
        private const int WS_EX_TOOLWINDOW = 0x00000080;
        private const int WS_EX_NOACTIVATE = 0x08000000;
        private const int WS_EX_TRANSPARENT = 0x00000020;
        private const int WS_EX_LAYERED = 0x00080000;

        private Point _cursorPos = new Point(-100, -100);
        private bool _isActive = false;
        private string _stageText = "Hold-5 Active: Click link to inspect";
        private string _urlText = "";
        private string _verdictText = "";
        private int _riskScore = 0;
        private bool _isScanning = false;
        private int _scanProgress = 0;
        private readonly Timer _animTimer;
        private float _animAngle = 0f;

        public OverlayWindow()
        {
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.StartPosition = FormStartPosition.Manual;
            this.TopMost = true;
            this.BackColor = Color.Magenta;
            this.TransparencyKey = Color.Magenta;
            this.DoubleBuffered = true;

            // Cover full virtual screen across all monitors
            Rectangle virtualScreen = SystemInformation.VirtualScreen;
            this.Bounds = virtualScreen;

            _animTimer = new Timer();
            _animTimer.Interval = 25; // ~40 FPS
            _animTimer.Tick += delegate(object s, EventArgs e)
            {
                if (_isActive)
                {
                    _animAngle = (_animAngle + 8f) % 360f;
                    this.Invalidate();
                }
            };
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ExStyle |= WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED;
                return cp;
            }
        }

        protected override bool ShowWithoutActivation
        {
            get { return true; }
        }

        public void ActivateOverlay()
        {
            if (InvokeRequired)
            {
                this.BeginInvoke(new Action(ActivateOverlay));
                return;
            }

            Rectangle vs = SystemInformation.VirtualScreen;
            if (this.Bounds != vs)
            {
                this.Bounds = vs;
            }

            _isActive = true;
            _isScanning = false;
            _verdictText = "";
            _stageText = "Hold-5 Active: Click link to inspect";
            _urlText = "";
            this.Visible = true;
            _animTimer.Start();
            this.Invalidate();
        }

        public void DeactivateOverlay()
        {
            if (InvokeRequired)
            {
                this.BeginInvoke(new Action(DeactivateOverlay));
                return;
            }

            _isActive = false;
            _isScanning = false;
            _animTimer.Stop();
            this.Visible = false;
        }

        public void UpdateCursor(int x, int y)
        {
            _cursorPos = new Point(x, y);
            if (_isActive && this.Visible)
            {
                this.Invalidate();
            }
        }

        public void SetScanState(bool scanning, string stage, string url, int progress)
        {
            if (InvokeRequired)
            {
                this.BeginInvoke(new Action(delegate { SetScanState(scanning, stage, url, progress); }));
                return;
            }

            _isScanning = scanning;
            _stageText = stage;
            _urlText = url;
            _scanProgress = progress;
            this.Invalidate();
        }

        public void SetScanResult(string verdict, int riskScore, string url)
        {
            if (InvokeRequired)
            {
                this.BeginInvoke(new Action(delegate { SetScanResult(verdict, riskScore, url); }));
                return;
            }

            _isScanning = false;
            _verdictText = verdict;
            _riskScore = riskScore;
            _urlText = url;
            this.Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            if (!_isActive) return;

            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Convert screen coordinates to Form client coordinates
            Point clientPt = this.PointToClient(_cursorPos);
            int cx = clientPt.X;
            int cy = clientPt.Y;

            // Draw System-wide Red Inspection Reticle
            DrawReticle(g, cx, cy);

            // Draw Floating Inspection Panel near pointer
            DrawInspectionHud(g, cx, cy);
        }

        private void DrawReticle(Graphics g, int cx, int cy)
        {
            int baseRadius = 24;
            int pulseRadius = (int)(baseRadius + 4 * Math.Sin(_animAngle * Math.PI / 180.0));

            // Outer soft glow
            using (Pen glowPen = new Pen(Color.FromArgb(80, 244, 63, 94), 4))
            {
                g.DrawEllipse(glowPen, cx - pulseRadius, cy - pulseRadius, pulseRadius * 2, pulseRadius * 2);
            }

            // High-visibility crisp red ring
            using (Pen ringPen = new Pen(Color.FromArgb(230, 239, 68, 68), 2.5f))
            {
                g.DrawArc(ringPen, cx - baseRadius, cy - baseRadius, baseRadius * 2, baseRadius * 2, _animAngle, 80);
                g.DrawArc(ringPen, cx - baseRadius, cy - baseRadius, baseRadius * 2, baseRadius * 2, _animAngle + 120, 80);
                g.DrawArc(ringPen, cx - baseRadius, cy - baseRadius, baseRadius * 2, baseRadius * 2, _animAngle + 240, 80);
            }

            // Crosshair lines
            using (Pen crosshairPen = new Pen(Color.FromArgb(240, 255, 255, 255), 1.5f))
            {
                g.DrawLine(crosshairPen, cx - 12, cy, cx - 4, cy);
                g.DrawLine(crosshairPen, cx + 4, cy, cx + 12, cy);
                g.DrawLine(crosshairPen, cx, cy - 12, cx, cy - 4);
                g.DrawLine(crosshairPen, cx, cy + 4, cx, cy + 12);
            }

            // Center red dot
            using (SolidBrush dotBrush = new SolidBrush(Color.FromArgb(245, 239, 68, 68)))
            {
                g.FillEllipse(dotBrush, cx - 3, cy - 3, 6, 6);
            }
        }

        private void DrawInspectionHud(Graphics g, int cx, int cy)
        {
            int hudWidth = 320;
            int hudHeight = 96;
            int offsetX = 28;
            int offsetY = 20;

            int hudX = cx + offsetX;
            int hudY = cy + offsetY;

            // Keep within current form bounds
            if (hudX + hudWidth > this.Width - 20) hudX = cx - hudWidth - 20;
            if (hudY + hudHeight > this.Height - 20) hudY = cy - hudHeight - 20;
            if (hudX < 10) hudX = 10;
            if (hudY < 10) hudY = 10;

            Rectangle hudRect = new Rectangle(hudX, hudY, hudWidth, hudHeight);

            // Draw HUD Background (Glassmorphism dark slate)
            using (GraphicsPath path = RoundedRect(hudRect, 10))
            {
                using (SolidBrush bgBrush = new SolidBrush(Color.FromArgb(235, 15, 23, 42)))
                {
                    g.FillPath(bgBrush, path);
                }
                using (Pen borderPen = new Pen(Color.FromArgb(160, 239, 68, 68), 1.5f))
                {
                    g.DrawPath(borderPen, path);
                }
            }

            // Header: QRShield Logo & Mode Title
            using (Font titleFont = new Font("Segoe UI", 9.5f, FontStyle.Bold))
            using (SolidBrush titleBrush = new SolidBrush(Color.FromArgb(248, 250, 252)))
            {
                g.DrawString("QRShield Inspection", titleFont, titleBrush, hudX + 12, hudY + 8);
            }

            // Status Badge
            string statusPill = "ACTIVE";
            Color pillBg = Color.FromArgb(180, 220, 38, 38);
            if (_verdictText == "MALICIOUS")
            {
                statusPill = "BLOCKED";
                pillBg = Color.FromArgb(220, 220, 38, 38);
            }
            else if (_verdictText == "SUSPICIOUS")
            {
                statusPill = "SUSPICIOUS";
                pillBg = Color.FromArgb(220, 217, 119, 6);
            }
            else if (_verdictText == "NO THREAT DETECTED")
            {
                statusPill = "ALLOWED";
                pillBg = Color.FromArgb(220, 16, 185, 129);
            }
            else if (_verdictText == "INCONCLUSIVE")
            {
                statusPill = "INCONCLUSIVE";
                pillBg = Color.FromArgb(220, 100, 116, 139);
            }

            using (GraphicsPath pillPath = RoundedRect(new Rectangle(hudX + hudWidth - 92, hudY + 8, 80, 18), 4))
            {
                using (SolidBrush pillBrush = new SolidBrush(pillBg))
                {
                    g.FillPath(pillBrush, pillPath);
                }
                using (Font pillFont = new Font("Segoe UI", 7.5f, FontStyle.Bold))
                using (SolidBrush textBrush = new SolidBrush(Color.White))
                {
                    StringFormat sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                    g.DrawString(statusPill, pillFont, textBrush, new RectangleF(hudX + hudWidth - 92, hudY + 8, 80, 18), sf);
                }
            }

            // Stage or Message Line
            using (Font subFont = new Font("Segoe UI", 8.5f, FontStyle.Regular))
            using (SolidBrush subBrush = new SolidBrush(Color.FromArgb(203, 213, 225)))
            {
                string displayStage = _stageText ?? "";
                if (displayStage.Length > 42) displayStage = displayStage.Substring(0, 39) + "...";
                g.DrawString(displayStage, subFont, subBrush, hudX + 12, hudY + 34);
            }

            // URL Line (Truncated if long)
            using (Font urlFont = new Font("Segoe UI", 8f, FontStyle.Regular))
            using (SolidBrush urlBrush = new SolidBrush(Color.FromArgb(148, 163, 184)))
            {
                string displayUrl = string.IsNullOrEmpty(_urlText) ? "Target: (Hover & click link to intercept)" : _urlText;
                if (displayUrl.Length > 46) displayUrl = displayUrl.Substring(0, 43) + "...";
                g.DrawString(displayUrl, urlFont, urlBrush, hudX + 12, hudY + 52);
            }

            // Progress Bar or Verdict Info
            if (_isScanning)
            {
                int barWidth = hudWidth - 24;
                int barHeight = 4;
                int barY = hudY + 76;
                using (SolidBrush trackBrush = new SolidBrush(Color.FromArgb(51, 65, 85)))
                {
                    g.FillRectangle(trackBrush, hudX + 12, barY, barWidth, barHeight);
                }
                int fillWidth = Math.Max(8, (barWidth * _scanProgress) / 100);
                using (SolidBrush fillBrush = new SolidBrush(Color.FromArgb(239, 68, 68)))
                {
                    g.FillRectangle(fillBrush, hudX + 12, barY, fillWidth, barHeight);
                }
            }
            else if (!string.IsNullOrEmpty(_verdictText))
            {
                using (Font resFont = new Font("Segoe UI", 8f, FontStyle.Bold))
                using (SolidBrush resBrush = new SolidBrush(Color.FromArgb(226, 232, 240)))
                {
                    string info = string.Format("Risk Score: {0}/100 - See QRShield for full details", _riskScore);
                    g.DrawString(info, resFont, resBrush, hudX + 12, hudY + 74);
                }
            }
            else
            {
                using (Font hintFont = new Font("Segoe UI", 7.5f, FontStyle.Italic))
                using (SolidBrush hintBrush = new SolidBrush(Color.FromArgb(100, 116, 139)))
                {
                    g.DrawString("Release [5] to return to normal cursor", hintFont, hintBrush, hudX + 12, hudY + 74);
                }
            }
        }

        private static GraphicsPath RoundedRect(Rectangle bounds, int radius)
        {
            int diameter = radius * 2;
            Size size = new Size(diameter, diameter);
            Rectangle arc = new Rectangle(bounds.Location, size);
            GraphicsPath path = new GraphicsPath();

            if (radius == 0)
            {
                path.AddRectangle(bounds);
                return path;
            }

            path.AddArc(arc, 180, 90);
            arc.X = bounds.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = bounds.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = bounds.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_animTimer != null) _animTimer.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
