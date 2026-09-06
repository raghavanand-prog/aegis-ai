import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";

import ProviderHealthPanel from "@/features/providers/components/ProviderHealthPanel";
import type { ApiProvider, ApiProviderList } from "@/services/api/providers";
import { renderWithProviders } from "@/test/render";

const fetchProviders = vi.fn();

vi.mock("@/services/api/providers", () => ({
  fetchProviders: (...args: unknown[]) => fetchProviders(...args),
}));

function provider(overrides: Partial<ApiProvider> = {}): ApiProvider {
  return {
    name: "aegisx.ml",
    produces: ["ml_inference"],
    isExternal: false,
    health: { status: "healthy", reason: null },
    ...overrides,
  };
}

function list(overrides: Partial<ApiProviderList> = {}): ApiProviderList {
  return {
    status: "healthy",
    total: 1,
    degraded: 0,
    providers: [provider()],
    ...overrides,
  };
}

beforeEach(() => {
  fetchProviders.mockReset();
});

describe("ProviderHealthPanel", () => {
  it("names every source and what it produces", async () => {
    fetchProviders.mockResolvedValue(
      list({
        total: 2,
        providers: [
          provider(),
          provider({ name: "aegisx.threatintel", produces: ["threat_intel"] }),
        ],
      }),
    );
    renderWithProviders(<ProviderHealthPanel />);

    expect(await screen.findByText("aegisx.ml")).toBeInTheDocument();
    expect(screen.getByText("aegisx.threatintel")).toBeInTheDocument();
    expect(screen.getByText(/ml_inference/)).toBeInTheDocument();
  });

  it("shows why a degraded source is degraded", async () => {
    // The reason is the whole value: "degraded" alone tells an operator
    // nothing they can act on.
    fetchProviders.mockResolvedValue(
      list({
        status: "degraded",
        degraded: 1,
        providers: [
          provider({
            health: {
              status: "degraded",
              reason: "No anomaly model has been loaded yet.",
            },
          }),
        ],
      }),
    );
    renderWithProviders(<ProviderHealthPanel />);

    expect(await screen.findByText(/No anomaly model has been loaded/)).toBeInTheDocument();
    expect(screen.getByText("degraded")).toBeInTheDocument();
  });

  it("counts the sources that are not answering", async () => {
    fetchProviders.mockResolvedValue(
      list({
        total: 7,
        degraded: 2,
        providers: [provider(), provider({ name: "aegisx.threatintel" })],
      }),
    );
    renderWithProviders(<ProviderHealthPanel />);
    expect(await screen.findByText(/2 of 7 sources are not fully available/))
      .toBeInTheDocument();
  });

  it("says so plainly when everything is answering", async () => {
    fetchProviders.mockResolvedValue(list({ total: 7, degraded: 0 }));
    renderWithProviders(<ProviderHealthPanel />);
    expect(await screen.findByText(/All 7 sources are answering/)).toBeInTheDocument();
  });

  it("marks a source that reaches outside the platform", async () => {
    fetchProviders.mockResolvedValue(
      list({ providers: [provider({ isExternal: true })] }),
    );
    renderWithProviders(<ProviderHealthPanel />);
    expect(await screen.findByText(/reaches outside the platform/)).toBeInTheDocument();
  });

  it("does not claim the sources are healthy when the request failed", async () => {
    // The dangerous rendering: an empty or green panel when nothing was asked.
    fetchProviders.mockRejectedValue(new Error("boom"));
    renderWithProviders(<ProviderHealthPanel />);
    expect(
      await screen.findByText(/not the same as them being healthy/i),
    ).toBeInTheDocument();
  });

  it("degrades instead of crashing on a malformed payload", async () => {
    fetchProviders.mockResolvedValue({ total: 7 } as unknown as ApiProviderList);
    renderWithProviders(<ProviderHealthPanel />);
    expect(await screen.findByText(/could not be loaded/i)).toBeInTheDocument();
  });

  it("offers no control over a provider", async () => {
    // V9 reports on providers; it does not operate them. A button here would
    // be the first thing that implied otherwise.
    fetchProviders.mockResolvedValue(list());
    renderWithProviders(<ProviderHealthPanel />);

    await screen.findByText("aegisx.ml");
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(screen.getByText(/does not enable, disable or reconfigure/i))
      .toBeInTheDocument();
  });
});
