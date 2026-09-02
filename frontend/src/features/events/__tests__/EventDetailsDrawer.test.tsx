import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import EventDetailsDrawer from "../components/EventDetailsDrawer";
import type { Event } from "../types";

/**
 * The event drawer is where an analyst first meets a hybrid score, so the
 * distinctions V3 introduced have to survive all the way to the markup:
 *
 * - the score is shown WITH the signals that produced it;
 * - an ML finding is labelled an anomaly score, never a confidence;
 * - "the model scored it and found nothing" and "the model never ran" produce
 *   different text.
 */

const BASE: Event = {
  id: "EVT-000042",
  time: "14:47:02",
  source: "Entra ID",
  event: "Repeated authentication failures",
  severity: "High",
  status: "New",
  timestamp: "2026-09-02T09:17:02Z",
  eventType: "auth_failure",
  riskScore: 75,
  riskLevel: "High",
  hostname: "SYN-WIN-042",
  username: "e.davis",
  sourceIp: "203.0.113.110",
  isSynthetic: true,
  detectionRules: ["DET-AUTH-001"],
  detections: [
    {
      ruleId: "DET-AUTH-001",
      ruleVersion: "1.0",
      ruleName: "Credential brute force",
      reason: "23 authentication failures for e.davis from 203.0.113.110 (threshold 5)",
      severity: "High",
      riskContribution: 45,
      mitreTechniques: ["T1110"],
      matchedAt: "2026-09-02T09:17:02Z",
    },
  ],
  riskSignals: [
    {
      type: "rule",
      source: "DET-AUTH-001",
      contribution: 45,
      detail: "23 authentication failures for e.davis from 203.0.113.110 (threshold 5)",
    },
    {
      type: "correlation",
      source: "SEQ-000001",
      contribution: 26,
      detail: "This event is part of a correlated sequence of related activity",
    },
    {
      type: "context",
      source: "event-context",
      contribution: 4,
      detail: "Source address is outside the internal estate",
    },
  ],
  mlFindings: [],
};

const ML_FINDING = {
  eventId: "EVT-000042",
  model: "isolation_forest",
  modelVersion: "1.0",
  featureSchemaVersion: "1.0",
  anomalyScore: 0.72,
  scoreKind: "anomaly_score",
  isAnomaly: true,
  threshold: 0.65,
  topContributors: [
    {
      name: "host_events_per_minute_scaled",
      value: 0.9,
      deviation: 3.2,
      direction: "above" as const,
    },
  ],
  latencyMs: 0.4,
  inferredAt: "2026-09-02T09:17:02Z",
};

function renderDrawer(event: Event) {
  return render(
    <EventDetailsDrawer event={event} open onClose={() => {}} />,
  );
}

describe("Event details drawer", () => {
  it("shows the risk score together with the signals that produced it", () => {
    renderDrawer(BASE);

    expect(screen.getByText("75")).toBeInTheDocument();
    // Each kind of evidence is named, not merged into one number.
    expect(screen.getByText(/Rule Detection/)).toBeInTheDocument();
    expect(screen.getByText(/Behavioural Sequence/)).toBeInTheDocument();
    expect(screen.getByText(/Event Context/)).toBeInTheDocument();
    // And the contributions add up to the score on screen.
    expect(screen.getByText("+45")).toBeInTheDocument();
    expect(screen.getByText("+26")).toBeInTheDocument();
    expect(screen.getByText("+4")).toBeInTheDocument();
  });

  it("labels an ML finding an anomaly score, never a confidence", () => {
    renderDrawer({ ...BASE, mlFindings: [ML_FINDING] });

    expect(screen.getByText("ML Anomaly")).toBeInTheDocument();
    expect(screen.getByText(/Anomaly score · threshold 65/)).toBeInTheDocument();
    expect(screen.getByText(/not a probability and not a confidence/i)).toBeInTheDocument();
    // The drivers are described as distance from normal, not as causes.
    expect(screen.getByText(/Features furthest from normal/)).toBeInTheDocument();
  });

  it("distinguishes 'scored and found nothing' from 'never scored'", () => {
    const { unmount } = renderDrawer({
      ...BASE,
      mlFindings: [{ ...ML_FINDING, isAnomaly: false, anomalyScore: 0.3 }],
    });
    expect(
      screen.getByText(/anomaly model scored it and did not find it unusual/i),
    ).toBeInTheDocument();
    unmount();

    renderDrawer({ ...BASE, mlFindings: [] });
    expect(
      screen.getByText(/did not score this event, so nothing is known either way/i),
    ).toBeInTheDocument();
  });

  it("says so when no signal explains the score", () => {
    renderDrawer({ ...BASE, riskScore: 0, riskSignals: [], detectionRules: [], detections: [] });
    expect(screen.getByText(/No signal contributed to this score/)).toBeInTheDocument();
  });

  it("marks synthetic telemetry", () => {
    renderDrawer(BASE);
    expect(screen.getByText(/Synthetic telemetry/)).toBeInTheDocument();
  });
});
