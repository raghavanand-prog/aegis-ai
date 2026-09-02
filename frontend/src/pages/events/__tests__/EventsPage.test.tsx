import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import EventsPage from "../EventsPage";
import { renderWithProviders, VIEWER } from "@/test/render";
import type { Event } from "@/features/events/types";
import type { Incident } from "@/features/incidents/types";

const fetchEvents = vi.fn();
const promoteEvent = vi.fn();

vi.mock("@/services/api/events", async () => {
  const actual = await vi.importActual<typeof import("@/services/api/events")>(
    "@/services/api/events",
  );
  return {
    ...actual,
    fetchEvents: (...args: unknown[]) => fetchEvents(...args),
    promoteEvent: (...args: unknown[]) => promoteEvent(...args),
  };
});

function makeEvent(overrides: Partial<Event> = {}): Event {
  return {
    id: "EVT-000042",
    time: "10:15:00",
    source: "Sysmon",
    event: "Process created: powershell.exe",
    severity: "High",
    status: "New",
    timestamp: new Date().toISOString(),
    hostname: "SYN-WIN-001",
    riskScore: 50,
    detectionRules: ["DET-PS-001"],
    detections: [
      {
        ruleId: "DET-PS-001",
        ruleVersion: "1.0",
        ruleName: "Suspicious PowerShell",
        reason: "PowerShell launched with a base64 encoded command",
        severity: "High",
        riskContribution: 50,
        mitreTechniques: ["T1059.001"],
        matchedAt: new Date().toISOString(),
      },
    ],
    ...overrides,
  };
}

const INCIDENT: Incident = {
  id: "INC-1001",
  title: "Suspicious PowerShell",
  severity: "High",
  description: "Promoted from EVT-000042",
  status: "Open",
  analyst: "Test Analyst",
  source: "Sysmon",
  created: "Just now",
  eventIds: ["EVT-000042"],
};

describe("Events workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fetchEvents.mockResolvedValue({ events: [makeEvent()], total: 1 });
    promoteEvent.mockResolvedValue(INCIDENT);
  });

  it("renders live events from the API", async () => {
    renderWithProviders(<EventsPage />);

    expect(await screen.findByText("Process created: powershell.exe")).toBeInTheDocument();
    expect(screen.getByText("Sysmon")).toBeInTheDocument();
    expect(screen.getAllByText("High").length).toBeGreaterThan(0);
  });

  it("shows an empty state rather than a blank table", async () => {
    fetchEvents.mockResolvedValue({ events: [], total: 0 });
    renderWithProviders(<EventsPage />);

    expect(await screen.findByText(/No events match this view/i)).toBeInTheDocument();
  });

  it("surfaces a backend failure with a retry", async () => {
    fetchEvents.mockRejectedValue(new Error("network down"));
    renderWithProviders(<EventsPage />);

    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
  });

  it("filters by severity through the API query", async () => {
    const user = userEvent.setup();
    renderWithProviders(<EventsPage />);
    await screen.findByText("Process created: powershell.exe");

    await user.selectOptions(screen.getByRole("combobox"), "Critical");

    await waitFor(() => {
      expect(fetchEvents).toHaveBeenLastCalledWith(
        expect.objectContaining({ severity: "Critical" }),
      );
    });
  });

  it("promotes an event to an incident", async () => {
    const user = userEvent.setup();
    renderWithProviders(<EventsPage />);
    await screen.findByText("Process created: powershell.exe");

    await user.click(screen.getByRole("button", { name: /promote/i }));

    await waitFor(() => {
      expect(promoteEvent).toHaveBeenCalledWith("EVT-000042", undefined);
    });
  });

  it("hides promotion from a read-only role", async () => {
    renderWithProviders(<EventsPage />, { user: VIEWER });
    await screen.findByText("Process created: powershell.exe");

    expect(screen.queryByRole("button", { name: /promote/i })).not.toBeInTheDocument();
  });

  it("does not offer promotion for an event already linked to an incident", async () => {
    fetchEvents.mockResolvedValue({
      events: [makeEvent({ incidentId: "INC-1001" })],
      total: 1,
    });
    renderWithProviders(<EventsPage />);
    await screen.findByText("Process created: powershell.exe");

    expect(screen.queryByRole("button", { name: /promote/i })).not.toBeInTheDocument();
  });
});
