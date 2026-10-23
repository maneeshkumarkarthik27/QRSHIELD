# QRShield Windows UI Automation & Accessibility Test Matrix

This matrix documents the expected behavior, URL extraction capability, click interception, and fallback mechanisms across common Windows applications and UI control types.

| Application / Target | Control Type / Architecture | Accessible Pattern Used | Can Intercept Pre-Click? | URL Destination Exposed? | Fallback & Safety Behavior |
|:---|:---|:---|:---|:---|:---|
| **Microsoft Edge** | Chromium RenderWidgetHost (HTML `<a href>`) | UIA `HyperlinkControlTypeId` / `ValuePattern` / `LegacyIAccessible` | **Yes** (when accessible) | **Yes** (Href via Value / HelpText) | If browser flags disable accessibility tree, displays: `"Link destination unavailable — not inspected"`. Never labels link safe. |
| **Google Chrome** | Chromium Content (HTML `<a href>`) | UIA `ValuePattern` / `LegacyIAccessible.Value` | **Yes** (with UIA tree active) | **Yes** (full destination URL) | Falls back to `"Link destination unavailable — not inspected"`. Normal click permitted only if user explicitly unholds 5. |
| **Microsoft Word (Office 365 / Desktop)** | RichEdit / Word Hyperlink Field | UIA `Hyperlink` / `LegacyIAccessiblePattern.Value` | **Yes** | **Yes** (Target URL in Value) | Click intercepted; QRShield pipeline invoked; safe links offer "Open in Browser". |
| **Microsoft Outlook Desktop** | WordMail / HTML Email Body | UIA `Hyperlink` / `ValuePattern` | **Yes** | **Yes** (Extracted destination URL) | Blocks navigation to malicious URLs immediately. |
| **Windows File Explorer** | AddressBar / Shell Links / Desktop Shortcuts | UIA `Edit` / `AddressBandRoot` / ShellLink Target | **Yes** | **Yes** (Resolved shortcut path or URI) | Intercepts .url internet shortcuts; local paths permitted. |
| **Windows Terminal / CMD / PowerShell** | Console Output (OSC 8 Hyperlinks or raw text) | UIA `TextPattern` / Screen Scraping | **Partial** | **Limited** (Raw URI string under cursor) | If valid URL matched under cursor, prompts scan. Otherwise normal selection/click preserved. |
| **Electron Applications (Slack, Teams, Discord)** | Chromium Webview / RichLink | UIA `Hyperlink` / DOM accessible node | **Yes** (when accessible) | **Yes** | Intercepts click before Chromium default handler. |
| **Legacy Win32 Controls (Notepad, standard dialogs)** | Static Text / Custom Owner-Drawn | No hyperlink pattern exposed | **No** | **No** | Identifies non-hyperlink target. Normal click is **not swallowed** or blocked. |
| **DirectX / Vulkan Games & Fullscreen Overlays** | Raw GPU Surface | None (No UIA / MSAA tree) | **No** | **No** | Does not intercept clicks. Overlay auto-bypasses or is inactive to avoid anti-cheat flag or game interruption. |
| **Protected / Elevated Apps (Running as Admin when QRShield is User)** | UAC Integrity Level Isolation | UIA blocked across integrity boundary | **No** | **No** | UI displays: `"Cannot inspect elevated window without administrator permissions"`. |

## Handling Unsupported & Ambiguous Links
1. **Never Label Unknown as Safe**: If UI Automation returns empty or invalid URL targets, QRShield explicitly displays:
   > `Link destination unavailable — not inspected`
2. **Click Transparency**: Ordinary desktop clicks (moving files, pressing buttons, focusing editors) are never blocked or swallowed.
3. **Double-Click & Drag Prevention**: Only single left-clicks while holding the activation key (`5`) are evaluated. Releasing `5` restores standard mouse interaction instantly.
