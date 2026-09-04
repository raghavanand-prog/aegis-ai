import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { QueryClient } from "@tanstack/react-query";
import { renderHook } from "@testing-library/react";

import DecisionIntegrity from "@/features/incidents/components/workspace/DecisionIntegrity";
import type {
  ApiDecisionBinding,
  ApiDecisionList,
  ApiDriftReport,
} from "@/services/api/decisions";
import { renderWithProviders } from "@/test/render";

type BindingOverrides = Partial<Omit<ApiDecisionBinding, "drift">> & {
  drift?: Partial<ApiDriftReport>;
};

function binding(overrides: BindingOverrides = {}): ApiDecisionBinding {
  return {
    decisionRef: "DEC-INC-1024-0001",
    decisionType: "incident.status_change",
    incidentRef: "INC-1024",
    fromState: "Investigating",
    toState: "Contained",
    reason: "isolated the host",
    decidedBy: "analyst@aegisx.dev",
    decidedByRole: "analyst",
    decidedAt: "2026-01-01T12:00:00+00:00",
    manifestDigest: "a".repeat(64),
    evidenceCount: 4,
    ...overrides,
    drift: {
      verdict: "unchanged",
      severity: 0,
      underminesDecision: false,
      manifestMatches: true,
      manifestAtDecision: "a".repeat(64),
      manifestNow: "a".repeat(64),
      added: [],
      removed: [],
      changed: [],
      attributionComplete: true,
      degradedAtDecision: [],
      ...(overrides.drift ?? {}),
    },
  };
}

function list(overrides: Partial<ApiDecisionList> = {}): ApiDecisionList {
  return {
    incidentId: "INC-1024",
    total: 1,
    worstVerdict: "unchanged",
    items: [binding()],
    ...overrides,
  };
}

describe("DecisionIntegrity", () => {
  it("says plainly when nothing has moved", () => {
    renderWithProviders(
      <DecisionIntegrity decisions={list()} isLoading={false} isError={false} />,
    );
    expect(screen.getByText("Evidence unchanged")).toBeInTheDocument();
  });

  it("keeps a routine refresh distinct from an unexpected change", () => {
    // The distinction the whole taxonomy exists for. A vendor verdict being
    // re-looked-up must not read as tampering, or the alarm gets ignored.
    renderWithProviders(
      <DecisionIntegrity
        decisions={list({
          worstVerdict: "refreshed",
          items: [
            binding({
              drift: {
                verdict: "refreshed",
                severity: 2,
                underminesDecision: true,
                manifestMatches: false,
                changed: [
                  {
                    evidenceId: "EV-1111111111111111",
                    integrity: "mutable",
                    kind: "threat_intel",
                    provider: "aegisx.threatintel",
                    digestAtDecision: "b".repeat(64),
                    digestNow: "c".repeat(64),
                  },
                ],
              },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );

    expect(screen.getByText("Basis changed")).toBeInTheDocument();
    expect(screen.queryByText("Unexpected change")).not.toBeInTheDocument();
    // And it is not presented as fine.
    expect(screen.getByText(/may no longer be supported/i)).toBeInTheDocument();
  });

  it("shows both digests for a changed item", () => {
    renderWithProviders(
      <DecisionIntegrity
        decisions={list({
          items: [
            binding({
              drift: {
                verdict: "tampered",
                severity: 3,
                underminesDecision: true,
                manifestMatches: false,
                changed: [
                  {
                    evidenceId: "EV-2222222222222222",
                    integrity: "write_once",
                    kind: "event",
                    provider: "aegisx.telemetry",
                    digestAtDecision: "b".repeat(64),
                    digestNow: "c".repeat(64),
                  },
                ],
              },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText("Unexpected change")).toBeInTheDocument();
    expect(screen.getByText(/bbbbbbbbbbbb… → cccccccccccc…/)).toBeInTheDocument();
  });

  it("treats new evidence as an addition, not an alarm", () => {
    renderWithProviders(
      <DecisionIntegrity
        decisions={list({
          worstVerdict: "extended",
          items: [
            binding({
              drift: {
                verdict: "extended",
                severity: 1,
                underminesDecision: false,
                manifestMatches: false,
                added: ["EV-3333333333333333"],
              },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText("New evidence since")).toBeInTheDocument();
    expect(screen.getByText(/1 item added since/)).toBeInTheDocument();
  });

  it("surfaces a decision taken while a provider was unreachable", () => {
    renderWithProviders(
      <DecisionIntegrity
        decisions={list({
          items: [
            binding({
              drift: { degradedAtDecision: [{ provider: "aegisx.ml" }] },
            }),
          ],
        })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText(/taken on partial evidence/i)).toBeInTheDocument();
  });

  it("says an unrecorded decision is not the same as an unchanged one", () => {
    renderWithProviders(
      <DecisionIntegrity
        decisions={list({ total: 0, items: [] })}
        isLoading={false}
        isError={false}
      />,
    );
    expect(screen.getByText(/not the same as their evidence being unchanged/i))
      .toBeInTheDocument();
  });

  it("does not claim the evidence is intact when the request failed", () => {
    renderWithProviders(
      <DecisionIntegrity decisions={undefined} isLoading={false} isError />,
    );
    expect(screen.getByText(/nothing is claimed either way/i)).toBeInTheDocument();
  });

  it("degrades instead of crashing on a malformed payload", () => {
    const malformed = { incidentId: "INC-1024" } as unknown as ApiDecisionList;
    renderWithProviders(
      <DecisionIntegrity decisions={malformed} isLoading={false} isError={false} />,
    );
    expect(screen.getByText(/could not be loaded/i)).toBeInTheDocument();
  });
});

// --- The sending half -----------------------------------------------------

const updateIncident = vi.hoisted(() => vi.fn());

vi.mock("@/services/api/incidents", async () => {
  const actual = await vi.importActual<typeof import("@/services/api/incidents")>(
    "@/services/api/incidents",
  );
  return { ...actual, updateIncident };
});

describe("useUpdateIncident evidence binding", () => {
  async function callWith(status: string, seedEvidence: boolean) {
    updateIncident.mockReset();
    updateIncident.mockResolvedValue({ id: "INC-1024" });

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    if (seedEvidence) {
      queryClient.setQueryData(["incident", "INC-1024", "evidence"], {
        manifestDigest: "d".repeat(64),
        items: [],
        degradedProviders: [],
      });
    }

    const { useUpdateIncident } = await import(
      "@/features/incidents/hooks/useIncidents"
    );
    const { QueryClientProvider } = await import("@tanstack/react-query");

    const { result } = renderHook(() => useUpdateIncident(), {
      wrapper: ({ children }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });

    result.current.mutate({
      incidentId: "INC-1024",
      input: { status: status as never },
    });
    await waitFor(() => expect(updateIncident).toHaveBeenCalled());
    return updateIncident.mock.calls[0][1];
  }

  it("states the reviewed evidence on a consequential transition", async () => {
    const payload = await callWith("Contained", true);
    expect(payload.expectedEvidenceDigest).toBe("d".repeat(64));
  });

  it("does not send a digest on routine progress", async () => {
    // Nothing is bound there, so there is nothing to be stale against.
    const payload = await callWith("Triaged", true);
    expect(payload.expectedEvidenceDigest).toBeUndefined();
  });

  it("sends nothing rather than inventing a digest when no evidence was loaded", async () => {
    // Claiming to have reviewed evidence the workspace never rendered would be
    // a false statement, and the backend would have no way to tell.
    const payload = await callWith("Contained", false);
    expect(payload.expectedEvidenceDigest).toBeUndefined();
  });
});
