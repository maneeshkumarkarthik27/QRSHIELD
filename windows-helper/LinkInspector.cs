using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Windows.Automation;

namespace QRShieldHelper
{
    public class LinkInspectionResult
    {
        public bool IsHyperlink { get; set; }
        public string Url { get; set; }
        public string ElementName { get; set; }
        public string ApplicationName { get; set; }
        public string ControlType { get; set; }
        public string FailureReason { get; set; }

        public LinkInspectionResult()
        {
            IsHyperlink = false;
            Url = null;
            ElementName = "";
            ApplicationName = "";
            ControlType = "Unknown";
            FailureReason = null;
        }
    }

    public static class LinkInspector
    {
        private static readonly Regex UrlRegex = new Regex(
            @"(?<![\w@])(?:(?:https?:\/\/)|(?:www\.))[a-zA-Z0-9\-\._~:\/\?#\[\]@!$&'\(\)\*\+,;=%]+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static LinkInspectionResult InspectPoint(int x, int y)
        {
            LinkInspectionResult result = new LinkInspectionResult();

            try
            {
                System.Windows.Point point = new System.Windows.Point(x, y);
                AutomationElement element = AutomationElement.FromPoint(point);

                if (element == null)
                {
                    result.FailureReason = "No accessible element found at coordinates";
                    return result;
                }

                result.ElementName = element.Current.Name ?? "";
                if (element.Current.ControlType != null)
                {
                    result.ControlType = element.Current.ControlType.ProgrammaticName;
                }

                // Resolve root window to determine application
                try
                {
                    TreeWalker walker = TreeWalker.ControlViewWalker;
                    AutomationElement parent = element;
                    while (parent != null && parent != AutomationElement.RootElement)
                    {
                        if (parent.Current.ControlType == ControlType.Window)
                        {
                            result.ApplicationName = parent.Current.Name;
                            break;
                        }
                        parent = walker.GetParent(parent);
                    }
                }
                catch { }

                bool isHyperlinkType = false;
                List<AutomationElement> candidates = new List<AutomationElement>();
                AddCandidate(candidates, element);

                // Custom Chromium/Electron controls often expose the destination on a
                // parent or a nearby text child instead of the clicked element.
                TreeWalker parentWalker = TreeWalker.ControlViewWalker;
                AutomationElement parentElement = element;
                for (int i = 0; i < 3; i++)
                {
                    parentElement = parentWalker.GetParent(parentElement);
                    if (parentElement == null || parentElement == AutomationElement.RootElement) break;
                    AddCandidate(candidates, parentElement);
                }

                try
                {
                    AutomationElementCollection children = element.FindAll(
                        TreeScope.Descendants,
                        new PropertyCondition(AutomationElement.IsEnabledProperty, true));
                    int inspected = 0;
                    foreach (AutomationElement child in children)
                    {
                        AddCandidate(candidates, child);
                        inspected++;
                        if (inspected >= 24) break;
                    }
                }
                catch { }

                foreach (AutomationElement candidate in candidates)
                {
                    if (candidate.Current.ControlType == ControlType.Hyperlink)
                    {
                        isHyperlinkType = true;
                    }

                    string candidateUrl = ExtractUrl(candidate);
                    if (!string.IsNullOrWhiteSpace(candidateUrl))
                    {
                        result.IsHyperlink = true;
                        result.Url = candidateUrl;
                        return result;
                    }
                }

                if (isHyperlinkType)
                {
                    // It is a hyperlink element, but destination is obscured or dynamic
                    result.IsHyperlink = true;
                    result.FailureReason = "Link destination unavailable — not inspected";
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.FailureReason = "UI Automation lookup error: " + ex.Message;
            }

            return result;
        }

        private static void AddCandidate(List<AutomationElement> candidates, AutomationElement element)
        {
            if (element != null && !candidates.Contains(element))
            {
                candidates.Add(element);
            }
        }

        private static string ExtractUrl(AutomationElement element)
        {
            List<string> values = new List<string>();
            try { values.Add(element.Current.Name); } catch { }
            try { values.Add(element.Current.HelpText); } catch { }
            try { values.Add(element.Current.AutomationId); } catch { }

            object pattern;
            if (element.TryGetCurrentPattern(ValuePattern.Pattern, out pattern))
            {
                ValuePattern value = pattern as ValuePattern;
                if (value != null) values.Add(value.Current.Value);
            }

            if (element.TryGetCurrentPattern(TextPattern.Pattern, out pattern))
            {
                TextPattern text = pattern as TextPattern;
                if (text != null)
                {
                    try
                    {
                        values.Add(text.DocumentRange.GetText(2000));
                    }
                    catch { }
                }
            }

            foreach (string value in values)
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                Match match = UrlRegex.Match(value);
                if (!match.Success) continue;

                string url = match.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}');
                if (url.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                {
                    url = "https://" + url;
                }
                if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    return url;
                }
            }

            return null;
        }
    }
}
