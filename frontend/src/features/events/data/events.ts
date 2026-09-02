import type { Event } from "../types";

export const events: Event[] = [
  {
    id: "EVT-001",
    time: "14:32:01",
    source: "Windows Defender",
    event: "PowerShell Encoded Command",
    severity: "High",
    status: "New",
  },
  {
    id: "EVT-002",
    time: "14:32:06",
    source: "Firewall",
    event: "Port Scan Detected",
    severity: "Medium",
    status: "Investigating",
  }
];

export const randomEvents = [
  {
    source: "Windows Defender",
    event: "Suspicious PowerShell Execution",
    severity: "High",
    status: "New",
  },
  {
    source: "Cisco Firewall",
    event: "Port Scan Detected",
    severity: "Medium",
    status: "New",
  },
  {
    source: "Azure AD",
    event: "Multiple Failed Logins",
    severity: "High",
    status: "Investigating",
  },
  {
    source: "Microsoft Defender",
    event: "Malware Quarantined",
    severity: "Critical",
    status: "New",
  },
  {
    source: "Sysmon",
    event: "Credential Dump Attempt",
    severity: "Critical",
    status: "New",
  },
];