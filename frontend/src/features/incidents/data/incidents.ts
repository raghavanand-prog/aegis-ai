import type { Incident } from "../types";

export const incidents: Incident[] = [
  {
    id: "INC-1024",
    title: "Ransomware Activity Detected",
    severity: "Critical",
    description: "Potential ransomware activity detected on an endpoint.",
    status: "Open",
    analyst: "John Smith",
    source: "Microsoft Defender",
    created: "5 min ago",
  },
  {
    id: "INC-1025",
    title: "Credential Stuffing Attack",
    severity: "High",
    description: "Multiple failed sign-in attempts indicate credential stuffing.",
    status: "Investigating",
    analyst: "Emily Davis",
    source: "Azure AD",
    created: "14 min ago",
  },
  {
    id: "INC-1026",
    title: "Suspicious PowerShell",
    severity: "Medium",
    description: "Suspicious PowerShell execution was observed.",
    status: "Contained",
    analyst: "Unassigned",
    source: "CrowdStrike",
    created: "30 min ago",
  },
  {
    id: "INC-1027",
    title: "DNS Beaconing",
    severity: "High",
    description: "Recurring DNS queries suggest possible beaconing activity.",
    status: "Open",
    analyst: "Alex Johnson",
    source: "Firewall",
    created: "1 hour ago",
  },
];
