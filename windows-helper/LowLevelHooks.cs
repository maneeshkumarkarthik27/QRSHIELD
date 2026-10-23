using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace QRShieldHelper
{
    public class LowLevelHooks : IDisposable
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;

        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_SYSKEYUP = 0x0105;

        private const int WM_MOUSEMOVE = 0x0200;
        private const int WM_LBUTTONDOWN = 0x0201;
        private const int WM_LBUTTONUP = 0x0202;

        private const int VK_5 = 0x35;
        private const int VK_NUMPAD5 = 0x65;

        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        private IntPtr _keyboardHookId = IntPtr.Zero;
        private IntPtr _mouseHookId = IntPtr.Zero;

        private HookProc _keyboardProc;
        private HookProc _mouseProc;

        private readonly OverlayWindow _overlay;
        private readonly Action<bool> _onInspectionModeChanged;
        private readonly Action<LinkInspectionResult, int, int> _onLinkIntercepted;

        public bool ProtectionEnabled { get; set; }
        public int ShortcutVkCode { get; set; }
        public bool SupportNumpad5 { get; set; }

        public bool IsHolding5 { get; private set; }

        public LowLevelHooks(
            OverlayWindow overlay,
            Action<bool> onInspectionModeChanged,
            Action<LinkInspectionResult, int, int> onLinkIntercepted)
        {
            _overlay = overlay;
            _onInspectionModeChanged = onInspectionModeChanged;
            _onLinkIntercepted = onLinkIntercepted;

            ProtectionEnabled = true;
            ShortcutVkCode = VK_5;
            SupportNumpad5 = true;
            IsHolding5 = false;

            _keyboardProc = KeyboardHookCallback;
            _mouseProc = MouseHookCallback;

            InstallHooks();
        }

        private void InstallHooks()
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                IntPtr moduleHandle = GetModuleHandle(curModule.ModuleName);
                _keyboardHookId = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, moduleHandle, 0);
                _mouseHookId = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, moduleHandle, 0);
            }
        }

        public void ResetInspectionMode()
        {
            if (IsHolding5)
            {
                IsHolding5 = false;
                _overlay.DeactivateOverlay();
                if (_onInspectionModeChanged != null) _onInspectionModeChanged(false);
            }
        }

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = wParam.ToInt32();
                var kbd = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
                int vk = (int)kbd.vkCode;

                bool isTargetKey = (vk == ShortcutVkCode) || (SupportNumpad5 && vk == VK_NUMPAD5);

                if (isTargetKey && ProtectionEnabled)
                {
                    if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
                    {
                        if (!IsHolding5)
                        {
                            IsHolding5 = true;
                            _overlay.ActivateOverlay();
                            if (_onInspectionModeChanged != null) _onInspectionModeChanged(true);
                        }
                    }
                    else if (msg == WM_KEYUP || msg == WM_SYSKEYUP)
                    {
                        if (IsHolding5)
                        {
                            IsHolding5 = false;
                            _overlay.DeactivateOverlay();
                            if (_onInspectionModeChanged != null) _onInspectionModeChanged(false);
                        }
                    }

                    // The inspection shortcut is a control key, not normal text input.
                    // Suppress both transitions so the host application never receives
                    // the shortcut as a typed character while inspection is armed.
                    return (IntPtr)1;
                }
            }

            return CallNextHookEx(_keyboardHookId, nCode, wParam, lParam);
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = wParam.ToInt32();
                var mouse = (MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(MSLLHOOKSTRUCT));

                if (msg == WM_MOUSEMOVE)
                {
                    if (IsHolding5)
                    {
                        _overlay.UpdateCursor(mouse.pt.x, mouse.pt.y);
                    }
                }
                else if (msg == WM_LBUTTONDOWN)
                {
                    if (IsHolding5 && ProtectionEnabled)
                    {
                        // Inspect the control at (mouse.pt.x, mouse.pt.y)
                        var result = LinkInspector.InspectPoint(mouse.pt.x, mouse.pt.y);

                        if (result.IsHyperlink)
                        {
                            // Hyperlink control identified: Intercept the click!
                            // Do not let the browser or host app navigate before inspection
                            if (_onLinkIntercepted != null) _onLinkIntercepted(result, mouse.pt.x, mouse.pt.y);
                            return (IntPtr)1; // Swallows click
                        }
                        else
                        {
                            // Not a hyperlink - allow ordinary desktop clicks to proceed normally
                        }
                    }
                }
            }

            return CallNextHookEx(_mouseHookId, nCode, wParam, lParam);
        }

        public void Dispose()
        {
            ResetInspectionMode();

            if (_keyboardHookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_keyboardHookId);
                _keyboardHookId = IntPtr.Zero;
            }

            if (_mouseHookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_mouseHookId);
                _mouseHookId = IntPtr.Zero;
            }
        }
    }
}
