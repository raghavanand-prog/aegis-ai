import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import IncidentsPage from "@/pages/dashboard/IncidentsPage";
import { IncidentProvider } from "@/store/IncidentContext";
import { renderWithProviders } from "@/test/render";
import type { Incident } from "../types";
import type { ApiIncident } from "@/services/api/types";

const fetchIncidents = vi.fn();
const apiGet = vi.fn();

vi.mock("@/services/api/incidents", async () => {
  const actual = await vi.importActual<typeof import("@/services/api/incidents")>(
    "@/services/api/incidents",
  );
  return {
    ...actual,
    fetchIncidents: (...args: unknown[]) => fetchIncidents(...args),
    // V9 Phase I: the workspace asks the server what this incident may become
    // rather than restating the lifecycle graph in TypeScript.
    fetchIncidentTransitions: vi.fn().mockResolvedValue({
      incidentId: "INC-1024",
      currentStatus: "Open",
      isTerminal: false,
      options: [
        {
          target: "Investigating",
          requiresReason: false,
          requiredPermission: "incidents:update",
          permitted: true,
          bindsEvidence: false,
        },
        {
          target: "Resolved",
          requiresReason: true,
          requiredPermission: "incidents:update",
          permitted: true,
          bindsEvidence: true,
        },
      ],
    }),
  };
});

vi.mock("@/services/api/responseActions", () => ({
  fetchResponseActions: vi.fn().mockResolvedValue({
    incidentId: "INC-1024",
    total: 0,
    pending: 0,
    items: [],
  }),
  requestResponseAction: vi.fn(),
  approveResponseAction: vi.fn(),
  rejectResponseAction: vi.fn(),
}));

// The V3 workspace fetches the incident itself rather than trusting the list
// row it was opened from, so the detail request is stubbed here.
vi.mock("@/services/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/services/api/client")>(
    "@/services/api/client",
  );
  return { ...actual, api: { get: (...args: unknown[]) => apiGet(...args) } };
});

vi.mock("@/services/api/ml", () => ({
  fetchIncidentMLFindings: vi.fn().mockResolvedValue({
    incidentId: "INC-1024",
    modelAvailable: false,
    reason: "No active model is registered.",
    eventsScored: 0,
    anomalyCount: 0,
    findings: [],
  }),
  fetchMLStatus: vi.fn().mockResolvedValue({
    enabled: true,
    available: false,
    modelName: "isolation_forest",
    modelVersion: null,
    featureSchemaVersion: "1.0",
    featureCount: 45,
    threshold: 0.65,
    loadedAt: null,
    eventsScored: 0,
    anomaliesFlagged: 0,
    failures: 0,
    reason: "No active model is registered.",
    context: {},
  }),
}));

vi.mock("@/services/api/ai", () => ({
  fetchAIStatus: vi.fn().mockResolvedValue({
    enabled: true,
    available: true,
    provider: "mock",
    model: "aegisx-template-analyst-1.0",
    reason: null,
    isTemplateProvider: true,
    sendsDataExternally: false,
    promptVersion: "1.0",
    analysisVersion: "1.0",
    budget: { day: null, used: 0, limit: 200, remaining: 200 },
  }),
  fetchAIAnalyses: vi
    .fn()
    .mockResolvedValue({ incidentId: "INC-1024", total: 0, analyses: [] }),
  requestAIAnalysis: vi.fn(),
}));

// V9: evidence provenance. Mocked with a realistic set so the provenance
// panel renders its real code path rather than the unavailable state.
vi.mock("@/services/api/evidence", () => ({
  fetchIncidentEvidence: vi.fn().mockResolvedValue({
    incidentId: "INC-1024",
    manifestDigest: "a".repeat(64),
    total: 2,
    countsByKind: { event: 1, threat_intel: 1 },
    countsByOrigin: { observed: 1, reported: 1 },
    injectionFlagged: [],
    degradedProviders: [],
    filters: { kind: null, provider: null },
    items: [
      {
        evidenceId: "EV-0123456789abcdef",
        kind: "event",
        title: "Process created: powershell.exe",
        content: { eventId: "EVT-000042" },
        contentDigest: "b".repeat(64),
        containsInjectionAttempt: false,
        provenance: {
          provider: "aegisx.telemetry",
          sourceRef: "event:EVT-000042",
          origin: "observed",
          integrity: "write_once",
          tamperEvidentAtRest: true,
          observedAt: "2026-01-01T12:00:00+00:00",
          collectedAt: "2026-01-01T12:00:05+00:00",
          confidence: null,
          confidenceBasis: null,
          incidentRef: "INC-1024",
          eventRef: "EVT-000042",
          isSynthetic: true,
          extra: {},
        },
      },
      {
        evidenceId: "EV-fedcba9876543210",
        kind: "threat_intel",
        title: "virustotal on 203.0.113.5: malicious",
        content: { reputation: "malicious" },
        contentDigest: "c".repeat(64),
        containsInjectionAttempt: false,
        provenance: {
          provider: "aegisx.threatintel",
          sourceRef: "threat_intel_result:9",
          origin: "reported",
          integrity: "mutable",
          tamperEvidentAtRest: false,
          observedAt: null,
          collectedAt: "2026-01-01T12:30:00+00:00",
          confidence: 0.9,
          confidenceBasis: "virustotal vendor confidence, 0-100",
          incidentRef: "INC-1024",
          eventRef: null,
          isSynthetic: false,
          extra: { assertedBy: "virustotal" },
        },
      },
    ],
  }),
  fetchEvidenceItem: vi.fn(),
}));

vi.mock("@/services/api/threatIntel", () => ({
  fetchThreatIntelStatus: vi.fn().mockResolvedValue({
    enabled: true,
    provider: "none",
    configured: false,
    supports: [],
    cacheTtlHours: 24,
    failureRetryMinutes: 15,
    budget: { day: null, used: 0, limit: 400, remaining: 400 },
  }),
  fetchIndicatorIntel: vi.fn().mockResolvedValue(null),
  enrichIndicator: vi.fn(),
}));

const INCIDENT: Incident = {
  id: "INC-1024",
  title: "Ransomware activity detected",
  severity: "Critical",
  description: "Mass file encryption on SYN-WIN-004",
  status: "Open",
  analyst: "Test Analyst",
  source: "EDR Agent",
  created: "5 min ago",
  riskScore: 90,
  eventIds: ["EVT-000090"],
  eventCount: 1,
};

const API_INCIDENT: ApiIncident = {
  id: "INC-1024",
  title: "Ransomware activity detected",
  description: "Mass file encryption on SYN-WIN-004",
  severity: "Critical",
  status: "Open",
  source: "EDR Agent",
  analyst: "Test Analyst",
  assigneeId: null,
  riskScore: 90,
  mitreTechniques: ["T1486"],
  riskSignals: [
    {
      type: "rule",
      source: "DET-RANSOM-001",
      contribution: 70,
      detail: "Endpoint agent reported mass encryption behaviour",
    },
    {
      type: "correlation",
      source: "COR-HOST-001",
      contribution: 20,
      detail: "Grouped with related activity on the same host",
    },
  ],
  sequences: [],
  aiAnalyses: [],
  mlAnomalyCount: 0,
  timeline: [],
  eventIds: ["EVT-000090"],
  events: [],
  iocs: [],
  eventCount: 1,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  resolvedAt: null,
};

function renderPage() {
  return renderWithProviders(
    <IncidentProvider>
      <IncidentsPage />
    </IncidentProvider>,
  );
}

describe("Incident rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fetchIncidents.mockResolvedValue({ incidents: [INCIDENT], total: 1 });
    apiGet.mockResolvedValue({ data: API_INCIDENT });
  });

  it("lists incidents from the backend", async () => {
    renderPage();

    expect(await screen.findByText("Ransomware activity detected")).toBeInTheDocument();
    expect(screen.getByText("INC-1024")).toBeInTheDocument();
  });

  it("opens the investigation workspace with the incident's own detail", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));

    const workspace = await screen.findByRole("complementary");
    expect(within(workspace).getByText("Investigation Workspace")).toBeInTheDocument();
    expect(within(workspace).getByText("Test Analyst")).toBeInTheDocument();
    expect(within(workspace).getByRole("tablist")).toBeInTheDocument();
  });

  it("shows the risk breakdown rather than a bare score", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));
    const workspace = await screen.findByRole("complementary");

    // The score, and the reasons behind it, together.
    expect(within(workspace).getByText("90")).toBeInTheDocument();
    expect(within(workspace).getByText(/Rule Detection/)).toBeInTheDocument();
    expect(within(workspace).getByText(/Behavioural Sequence/)).toBeInTheDocument();
    expect(
      within(workspace).getByText(/Endpoint agent reported mass encryption/),
    ).toBeInTheDocument();
  });

  it("offers the lifecycle transitions the server says are legal", async () => {
    // V9 Phase I wiring. The workspace had no status control at all before
    // this, which is why the evidence-freshness check behind it had never been
    // reachable by a click.
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));
    const workspace = await screen.findByRole("complementary");

    expect(
      await within(workspace).findByRole("button", { name: "Investigating" }),
    ).toBeInTheDocument();
    expect(within(workspace).getByRole("button", { name: "Resolved" })).toBeInTheDocument();
  });

  it("exposes the response-action panel", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));
    const workspace = await screen.findByRole("complementary");

    await user.click(within(workspace).getByRole("tab", { name: /Response/ }));
    expect(
      await within(workspace).findByText(/Nothing here is executed/i),
    ).toBeInTheDocument();
  });

  it("explains why the ML panel is empty instead of implying nothing was found", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));
    const workspace = await screen.findByRole("complementary");

    await user.click(within(workspace).getByRole("tab", { name: /Evidence/ }));

    expect(
      await within(workspace).findByText(/No anomaly model is running/),
    ).toBeInTheDocument();
    expect(
      within(workspace).getByText(/No active model is registered/),
    ).toBeInTheDocument();
  });

  it("labels the AI analyst as a template provider when no model backs it", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText("Ransomware activity detected"));
    const workspace = await screen.findByRole("complementary");

    await user.click(within(workspace).getByRole("tab", { name: /AI Analyst/ }));

    expect(
      await within(workspace).findByText(/offline template/),
    ).toBeInTheDocument();
    expect(
      within(workspace).getByText(/No AI analysis has been requested/),
    ).toBeInTheDocument();
  });

  it("shows an empty state when nothing has been promoted", async () => {
    fetchIncidents.mockResolvedValue({ incidents: [], total: 0 });
    renderPage();

    expect(await screen.findByText(/No incidents yet/i)).toBeInTheDocument();
  });

  it("shows a recoverable error when the backend is unreachable", async () => {
    fetchIncidents.mockRejectedValue(new Error("connection refused"));
    renderPage();

    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
