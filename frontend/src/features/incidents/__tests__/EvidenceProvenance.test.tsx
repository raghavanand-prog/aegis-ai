import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";

import EvidenceProvenance from "@/features/incidents/components/workspace/EvidenceProvenance";
import type {
  ApiEvidenceItem,
  ApiEvidenceSet,
  ApiProvenance,
} from "@/services/api/evidence";
import { renderWithProviders } from "@/test/render";

type ItemOverrides = Partial<Omit<ApiEvidenceItem, "provenance">> & {
  provenance?: Partial<ApiProvenance>;
};

function item(overrides: ItemOverrides = {}): ApiEvidenceItem {
  return {
    evidenceId: "EV-0123456789abcdef",
    kind: "event",
    title: "Process created: powershell.exe",
    content: { eventId: "EVT-000042" },
    contentDigest: "b".repeat(64),
    containsInjectionAttempt: false,
    ...overrides,
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
      isSynthetic: false,
      extra: {},
      ...(overrides.provenance ?? {}),
    },
  };
}

function evidenceSet(overrides: Partial<ApiEvidenceSet> = {}): ApiEvidenceSet {
  return {
    incidentId: "INC-1024",
    manifestDigest: "a".repeat(64),
    total: 1,
    countsByKind: { event: 1 },
    countsByOrigin: { observed: 1 },
    injectionFlagged: [],
    degradedProviders: [],
    filters: {},
    items: [item()],
    ...overrides,
  };
}

describe("EvidenceProvenance", () => {
  it("keeps the classes of claim visually distinct", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({
          total: 3,
          items: [
            item(),
            item({
              evidenceId: "EV-1111111111111111",
              kind: "threat_intel",
              title: "virustotal verdict",
              provenance: { origin: "reported", provider: "aegisx.threatintel" },
            }),
            item({
              evidenceId: "EV-2222222222222222",
              kind: "ai_analysis",
              title: "AI analyze",
              provenance: { origin: "analytic", provider: "aegisx.ai" },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );

    // An observation, a third party's assertion and a model's reading are
    // weighed differently, so they must never read as the same thing.
    // `span`, because "Observed" is also a column label further down the row.
    expect(screen.getByText("Observed", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("Reported", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("AI-generated", { selector: "span" })).toBeInTheDocument();
  });

  it("shows both timestamps rather than collapsing them", () => {
    renderWithProviders(
      <EvidenceProvenance evidence={evidenceSet()} isLoading={false} isError={false} />,
    );
    expect(screen.getByText("Observed", { selector: "dt" })).toBeInTheDocument();
    expect(screen.getByText("Collected")).toBeInTheDocument();
  });

  it("marks evidence whose stored record can still change", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({
          items: [
            item({
              provenance: { integrity: "mutable", tamperEvidentAtRest: false },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText("mutable")).toBeInTheDocument();
  });

  it("labels synthetic telemetry as simulated data", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({ items: [item({ provenance: { isSynthetic: true } })] })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText("Synthetic")).toBeInTheDocument();
  });

  it("flags injected text without hiding it", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({
          injectionFlagged: ["EV-0123456789abcdef"],
          items: [item({ containsInjectionAttempt: true })],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText("Injection text")).toBeInTheDocument();
  });

  it("separates a collection failure from an absence of evidence", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({
          degradedProviders: [
            { provider: "aegisx.ml", status: "unavailable", reason: "Provider raised RuntimeError." },
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText(/could not be collected/i)).toBeInTheDocument();
    expect(screen.getByText(/not an absence of evidence/i)).toBeInTheDocument();
  });

  it("says nothing is recorded rather than implying nothing happened", () => {
    renderWithProviders(
      <EvidenceProvenance
        evidence={evidenceSet({ total: 0, items: [] })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText(/No evidence is recorded/i)).toBeInTheDocument();
  });

  it("degrades instead of crashing when the payload does not match the contract", () => {
    // Regression: the first cut reached straight into `manifestDigest`, so a
    // malformed response took down the whole investigation workspace rather
    // than one panel.
    const malformed = { incidentId: "INC-1024" } as unknown as ApiEvidenceSet;
    renderWithProviders(
      <EvidenceProvenance evidence={malformed} isLoading={false} isError={false} />,
    );
    expect(screen.getByText(/could not be loaded/i)).toBeInTheDocument();
  });

  it("does not claim there is no evidence when the request failed", () => {
    renderWithProviders(
      <EvidenceProvenance evidence={undefined} isLoading={false} isError />,
    );
    expect(screen.getByText(/nothing is claimed either way/i)).toBeInTheDocument();
  });
});
