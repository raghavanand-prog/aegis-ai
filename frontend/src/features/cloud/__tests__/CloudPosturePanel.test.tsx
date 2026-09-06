import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";

import CloudPosturePanel from "@/features/cloud/components/CloudPosturePanel";
import type { ApiCloudFinding, ApiCloudFindingPage } from "@/services/api/cloud";
import { renderWithProviders } from "@/test/render";

const fetchCloudFindings = vi.fn();

vi.mock("@/services/api/cloud", () => ({
  fetchCloudFindings: (...args: unknown[]) => fetchCloudFindings(...args),
}));

const NOTE =
  "Simulated. AEGISX has no cloud provider integration: findings are computed " +
  "from configuration snapshots on disk by local checks, and no cloud account " +
  "has been contacted.";

function finding(overrides: Partial<ApiCloudFinding> = {}): ApiCloudFinding {
  return {
    findingId: "CF-0123456789abcdef",
    checkId: "AEGISX-CLD-S3-001",
    title: "Bucket is not protected by a public access block",
    description: "Public access block is disabled.",
    severity: "Critical",
    control: "Object storage should not be reachable anonymously",
    resource: {
      provider: "aws",
      account: "111111111111",
      region: null,
      service: "s3",
      resourceType: "",
      resourceId: "aegisx-payroll-exports",
    },
    detail: { publicAccessBlock: false },
    sourceFile: "aws_account_111111111111.json",
    isSimulated: true,
    firstSeenAt: "2026-01-05T09:00:00+00:00",
    lastSeenAt: "2026-01-05T09:00:00+00:00",
    ...overrides,
  };
}

function page(overrides: Partial<ApiCloudFindingPage> = {}): ApiCloudFindingPage {
  return {
    total: 1,
    limit: 50,
    offset: 0,
    items: [finding()],
    note: NOTE,
    ...overrides,
  };
}

beforeEach(() => {
  fetchCloudFindings.mockReset();
});

describe("CloudPosturePanel", () => {
  it("says plainly that no cloud account was contacted", async () => {
    // The single most important thing this panel must not imply.
    fetchCloudFindings.mockResolvedValue(page());
    renderWithProviders(<CloudPosturePanel />);
    expect(await screen.findByText(/no cloud account has been contacted/i))
      .toBeInTheDocument();
  });

  it("takes the simulation statement from the server rather than restating it", async () => {
    // Two copies of "this is simulated" could drift, and the copy that drifts
    // is the one users read.
    fetchCloudFindings.mockResolvedValue(
      page({ note: "Simulated in a way this test made up." }),
    );
    renderWithProviders(<CloudPosturePanel />);
    expect(await screen.findByText(/a way this test made up/)).toBeInTheDocument();
  });

  it("shows the finding, the resource and the check", async () => {
    fetchCloudFindings.mockResolvedValue(page());
    renderWithProviders(<CloudPosturePanel />);

    expect(await screen.findByText(/not protected by a public access block/))
      .toBeInTheDocument();
    expect(screen.getByText(/aegisx-payroll-exports/)).toBeInTheDocument();
    expect(screen.getByText(/AEGISX-CLD-S3-001/)).toBeInTheDocument();
  });

  it("names the hardening theme without pretending to a benchmark", async () => {
    fetchCloudFindings.mockResolvedValue(page());
    renderWithProviders(<CloudPosturePanel />);

    expect(await screen.findByText(/reachable anonymously/)).toBeInTheDocument();
    // No CIS/NIST/ISO identifier anywhere: nothing here was assessed against one.
    expect(screen.queryByText(/CIS |NIST |ISO 27/)).not.toBeInTheDocument();
  });

  it("keeps severities separate rather than combining them", async () => {
    // Each finding keeps its own severity and the only number on screen is a
    // count of findings. Nothing here is summed into a posture grade, which
    // would need to know what the resources hold.
    fetchCloudFindings.mockResolvedValue(
      page({
        total: 2,
        items: [finding(), finding({ findingId: "CF-2", severity: "High" })],
      }),
    );
    renderWithProviders(<CloudPosturePanel />);

    expect(await screen.findByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText(/2 findings, worst first/)).toBeInTheDocument();
  });

  it("says nothing was scanned rather than implying nothing is wrong", async () => {
    fetchCloudFindings.mockResolvedValue(page({ total: 0, items: [] }));
    renderWithProviders(<CloudPosturePanel />);
    expect(
      await screen.findByText(/nothing has been looked at, not that nothing is wrong/i),
    ).toBeInTheDocument();
  });

  it("does not claim there are no findings when the request failed", async () => {
    fetchCloudFindings.mockRejectedValue(new Error("boom"));
    renderWithProviders(<CloudPosturePanel />);
    expect(
      await screen.findByText(/not the same as there being no findings/i),
    ).toBeInTheDocument();
  });

  it("degrades instead of crashing on a malformed payload", async () => {
    fetchCloudFindings.mockResolvedValue({ total: 3 } as unknown as ApiCloudFindingPage);
    renderWithProviders(<CloudPosturePanel />);
    expect(await screen.findByText(/could not be loaded/i)).toBeInTheDocument();
  });
});
