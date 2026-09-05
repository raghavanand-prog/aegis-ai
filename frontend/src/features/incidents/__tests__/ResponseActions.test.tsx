import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";

import ResponseActions from "@/features/incidents/components/workspace/ResponseActions";
import type {
  ApiResponseAction,
  ApiResponseActionList,
} from "@/services/api/responseActions";
import { renderWithProviders } from "@/test/render";

function action(overrides: Partial<ApiResponseAction> = {}): ApiResponseAction {
  return {
    requestRef: "RAR-INC-1024-0001",
    incidentRef: "INC-1024",
    actionType: "isolate_endpoint",
    parameters: { target: "SYN-WIN-001" },
    parametersDigest: "a".repeat(64),
    justification: "confirmed encoded PowerShell",
    status: "requested",
    requestedBy: "analyst@aegisx.dev",
    requestedByRole: "analyst",
    requestedAt: "2026-01-01T12:00:00+00:00",
    decidedBy: null,
    decidedByRole: null,
    decidedAt: null,
    decisionReason: null,
    decisionRef: null,
    executed: false,
    executionNote:
      "AEGISX records the decision only. No response action is executed against any system in this version.",
    ...overrides,
  };
}

function list(overrides: Partial<ApiResponseActionList> = {}): ApiResponseActionList {
  return {
    incidentId: "INC-1024",
    total: 1,
    pending: 1,
    items: [action()],
    ...overrides,
  };
}

function render(props: Partial<Parameters<typeof ResponseActions>[0]> = {}) {
  const onRequest = vi.fn();
  const onApprove = vi.fn();
  const onReject = vi.fn();
  renderWithProviders(
    <ResponseActions
      actions={list()}
      isLoading={false}
      isError={false}
      canRequest
      canDecide={false}
      currentUserEmail="admin@aegisx.dev"
      isSubmitting={false}
      error={null}
      onRequest={onRequest}
      onApprove={onApprove}
      onReject={onReject}
      {...props}
    />,
  );
  return { onRequest, onApprove, onReject };
}

describe("ResponseActions", () => {
  it("states plainly that nothing is executed", () => {
    // The single most important thing this panel must not imply.
    render();
    expect(screen.getByText(/Nothing here is executed/i)).toBeInTheDocument();
    expect(
      screen.getByText(/carries out no action against any system/i),
    ).toBeInTheDocument();
  });

  it("marks an approved action as approved and not executed", () => {
    render({
      actions: list({
        items: [
          action({
            status: "approved",
            decidedBy: "admin@aegisx.dev",
            decidedByRole: "admin",
            decisionRef: "DEC-INC-1024-0001",
          }),
        ],
      }),
    });
    expect(screen.getByText(/not executed/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing was carried out/i)).toBeInTheDocument();
  });

  it("does not offer a decision to someone without the authority", () => {
    render({ canDecide: false });
    expect(screen.queryByRole("button", { name: "Decide" })).not.toBeInTheDocument();
  });

  it("does not let the requester decide their own request", () => {
    // Four-eyes is the backend's rule; this only avoids offering a button that
    // would always be refused.
    render({ canDecide: true, currentUserEmail: "analyst@aegisx.dev" });

    expect(screen.queryByRole("button", { name: "Decide" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot also decide it/i)).toBeInTheDocument();
  });

  it("is not fooled by a different spelling of the same account", () => {
    render({ canDecide: true, currentUserEmail: "  Analyst@AEGISX.dev " });
    expect(screen.queryByRole("button", { name: "Decide" })).not.toBeInTheDocument();
  });

  it("lets a second authorised person approve", () => {
    const { onApprove } = render({
      canDecide: true,
      currentUserEmail: "admin@aegisx.dev",
    });

    fireEvent.click(screen.getByRole("button", { name: "Decide" }));
    fireEvent.click(screen.getByRole("button", { name: /Approve/ }));
    expect(onApprove).toHaveBeenCalledWith("RAR-INC-1024-0001", "");
  });

  it("requires a reason to refuse but not to approve", () => {
    render({ canDecide: true, currentUserEmail: "admin@aegisx.dev" });
    fireEvent.click(screen.getByRole("button", { name: "Decide" }));

    expect(screen.getByRole("button", { name: /Refuse/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Approve/ })).toBeEnabled();

    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "host is a domain controller" },
    });
    expect(screen.getByRole("button", { name: /Refuse/ })).toBeEnabled();
  });

  it("will not raise a request without a justification", () => {
    render();
    fireEvent.click(screen.getByRole("button", { name: /Request containment/ }));

    const submit = screen.getByRole("button", { name: /Raise request/ });
    expect(submit).toBeDisabled();

    const boxes = screen.getAllByRole("textbox");
    fireEvent.change(boxes[boxes.length - 1], {
      target: { value: "confirmed lateral movement" },
    });
    expect(screen.getByRole("button", { name: /Raise request/ })).toBeEnabled();
  });

  it("hides the request control from a role that may not request", () => {
    render({ canRequest: false });
    expect(
      screen.queryByRole("button", { name: /Request containment/ }),
    ).not.toBeInTheDocument();
  });

  it("shows a server refusal verbatim", () => {
    render({
      canDecide: true,
      currentUserEmail: "admin@aegisx.dev",
      error: "The evidence for this incident has changed since it was last loaded.",
    });
    fireEvent.click(screen.getByRole("button", { name: "Decide" }));
    expect(screen.getByText(/changed since it was last loaded/)).toBeInTheDocument();
  });

  it("says none is recorded rather than implying none is possible", () => {
    render({ actions: list({ total: 0, pending: 0, items: [] }) });
    expect(screen.getByText(/No containment action has been requested/i))
      .toBeInTheDocument();
  });

  it("does not claim there are none when the request failed", () => {
    render({ actions: undefined, isError: true });
    expect(screen.getByText(/nothing is claimed either way/i)).toBeInTheDocument();
  });

  it("degrades instead of crashing on a malformed payload", () => {
    const malformed = { incidentId: "INC-1024" } as unknown as ApiResponseActionList;
    render({ actions: malformed });
    expect(screen.getByText(/could not be loaded/i)).toBeInTheDocument();
  });
});
