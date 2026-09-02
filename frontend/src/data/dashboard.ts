import {
  Shield,
  ShieldAlert,
  Bug,
  ScanSearch,
  UserRoundX,
  Globe,
  Bot,
  Brain,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

/* ===========================
   Dashboard KPI Cards
=========================== */

export const dashboardStats = [
  {
    title: "Active Threats",
    value: "124",
    trend: "▲ +12 Today",
    trendColor: "text-red-400",
  },
  {
    title: "Critical Alerts",
    value: "8",
    trend: "▲ +2 Today",
    trendColor: "text-orange-400",
  },
  {
    title: "Protected Systems",
    value: "98%",
    trend: "Operational",
    trendColor: "text-emerald-400",
  },
  {
    title: "AI Confidence",
    value: "94%",
    trend: "Learning",
    trendColor: "text-cyan-400",
  },
];

/* ===========================
   Threat Trend
=========================== */

export const threatTrend = [
  { day: "Mon", threats: 24 },
  { day: "Tue", threats: 38 },
  { day: "Wed", threats: 30 },
  { day: "Thu", threats: 45 },
  { day: "Fri", threats: 60 },
  { day: "Sat", threats: 48 },
  { day: "Sun", threats: 74 },
];

/* ===========================
   Threat Overview
=========================== */

export const threatOverview = [
  {
    name: "Malware",
    value: 42,
    count: 524,
    trend: "+8%",
    color: "#3B82F6",
  },
  {
    name: "Phishing",
    value: 28,
    count: 349,
    trend: "-2%",
    color: "#EF4444",
  },
  {
    name: "Ransomware",
    value: 18,
    count: 225,
    trend: "+5%",
    color: "#F59E0B",
    },
  {
    name: "Insider",
    value: 7,
    count: 87,
    trend: "0%",
    color: "#22C55E",
  },
  {
    name: "Zero-Day",
    value: 5,
    count: 63,
    trend: "+1%",
    color: "#8B5CF6",
  },
];

/* ===========================
   Recent Activity
=========================== */

export const recentActivities = [
  {
    id: 1,
    title: "SQL Injection Blocked",
    description: "Attack targeting /login endpoint was blocked.",
    severity: "Critical",
    time: "2 min ago",
    icon: ShieldAlert,
  },
  {
    id: 2,
    title: "Suspicious Login Attempt",
    description: "Multiple failed logins detected from Moscow.",
    severity: "High",
    time: "5 min ago",
    icon: UserRoundX,
  },
  {
    id: 3,
    title: "Malware Quarantined",
    description: "Trojan.Win32 isolated successfully.",
    severity: "Medium",
    time: "12 min ago",
    icon: Bug,
  },
  {
    id: 4,
    title: "Security Scan Completed",
    description: "OpenVAS vulnerability scan finished.",
    severity: "Low",
    time: "18 min ago",
    icon: ScanSearch,
  },
  {
    id: 5,
    title: "Firewall Policy Updated",
    description: "New outbound rule deployed.",
    severity: "Low",
    time: "24 min ago",
    icon: Shield,
  },
];

/* ===========================
   Attack Sources
=========================== */

export const attackSources = [
  {
    country: "China",
    code: "CN",
    attacks: 43,
    percentage: 100,
  },
  {
    country: "Russia",
    code: "RU",
    attacks: 35,
    percentage: 82,
  },
  {
    country: "United States",
    code: "US",
    attacks: 27,
    percentage: 63,
  },
  {
    country: "India",
    code: "IN",
    attacks: 19,
    percentage: 44,
  },
  {
    country: "Brazil",
    code: "BR",
    attacks: 12,
    percentage: 28,
  },
];

/* ===========================
   AI Insights
=========================== */

export const aiInsights = [
  {
    icon: Brain,
    title: "AI Threat Summary",
    description:
      "Phishing campaigns increased by 18% over the last 24 hours.",
    confidence: "94%",
  },
  {
    icon: Bot,
    title: "Recommended Action",
    description:
      "Enable stricter email filtering and MFA enforcement.",
    confidence: "91%",
  },
  {
    icon: TriangleAlert,
    title: "Emerging Threat",
    description:
      "Unusual outbound DNS traffic detected from two endpoints.",
    confidence: "87%",
  },
];

/* ===========================
   MITRE ATT&CK Coverage
=========================== */

type MitreCoverageStatus = "Protected" | "Partial" | "Missing";

export const mitreCoverage: Array<{
  tactic: string;
  status: MitreCoverageStatus;
}> = [
  {
    tactic: "Initial Access",
    status: "Protected",
  },
  {
    tactic: "Execution",
    status: "Protected",
  },
  {
    tactic: "Persistence",
    status: "Partial",
  },
  {
    tactic: "Privilege Escalation",
    status: "Partial",
  },
  {
    tactic: "Credential Access",
    status: "Protected",
  },
  {
    tactic: "Discovery",
    status: "Protected",
  },
  {
    tactic: "Lateral Movement",
    status: "Missing",
  },
  {
    tactic: "Exfiltration",
    status: "Partial",
  },
];

/* ===========================
   Quick Actions
=========================== */

export const quickActions = [
  {
    title: "Run Vulnerability Scan",
    icon: ScanSearch,
  },
  {
    title: "Investigate Alerts",
    icon: ShieldCheck,
  },
  {
    title: "View Threat Map",
    icon: Globe,
  },
];
type ThreatSeverity = "critical" | "high" | "medium" | "low";
type ThreatStatus =
  | "active"
  | "investigating"
  | "blocked"
  | "contained"
  | "resolved";

export const threatQueue: Array<{
  id: string;
  threat: string;
  severity: ThreatSeverity;
  source: string;
  status: ThreatStatus;
  time: string;
}> = [
  {
    id: "T-001",
    threat: "SQL Injection",
    severity: "critical",
    source: "CN",
    status: "active",
    time: "2 min ago",
  },
  {
    id: "T-002",
    threat: "Trojan.Win32",
    severity: "critical",
    source: "RU",
    status: "blocked",
    time: "5 min ago",
  },
  {
    id: "T-003",
    threat: "Malware",
    severity: "high",
    source: "US",
    status: "investigating",
    time: "8 min ago",
  },
  {
    id: "T-004",
    threat: "Brute Force Login",
    severity: "medium",
    source: "IN",
    status: "contained",
    time: "14 min ago",
  },
  {
    id: "T-005",
    threat: "Port Scan",
    severity: "low",
    source: "BR",
    status: "resolved",
    time: "22 min ago",
  },
];
