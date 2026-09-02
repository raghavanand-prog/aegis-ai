/**
 * Shared chart styling for the Analytics page.
 *
 * Colours follow the severity language already used across the SOC UI, so a
 * red bar means the same thing on every screen.
 */

export const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#10b981",
};

export const ACCENT = "#06b6d4";
export const ACCENT_SOFT = "#0ea5e9";
export const MITRE = "#a855f7";
export const GRID = "#1e293b";
export const AXIS = "#64748b";

export const tooltipStyle = {
  contentStyle: {
    backgroundColor: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "0.75rem",
    color: "#e2e8f0",
    fontSize: "0.8rem",
  },
  labelStyle: { color: "#94a3b8" },
  cursor: { fill: "rgba(148, 163, 184, 0.08)" },
} as const;
