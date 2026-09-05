import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";

import LifecycleControl from "@/features/incidents/components/workspace/LifecycleControl";
import type {
  ApiIncidentTransitions,
  ApiTransitionOption,
} from "@/services/api/incidents";
import { renderWithProviders } from "@/test/render";

function option(overrides: Partial<ApiTransitionOption> = {}): ApiTransitionOption {
  return {
    target: "Triaged",
    requiresReason: false,
    requiredPermission: "incidents:update",
    permitted: true,
    bindsEvidence: false,
    ...overrides,
  };
}

function transitions(
  overrides: Partial<ApiIncidentTransitions> = {},
): ApiIncidentTransitions {
  return {
    incidentId: "INC-1024",
    currentStatus: "Open",
    isTerminal: false,
    options: [option()],
    ...overrides,
  };
}

function render(props: Partial<Parameters<typeof LifecycleControl>[0]> = {}) {
  const onTransition = vi.fn();
  renderWithProviders(
    <LifecycleControl
      transitions={transitions()}
      isLoading={false}
      isError={false}
      isSubmitting={false}
      error={null}
      onTransition={onTransition}
      {...props}
    />,
  );
  return { onTransition };
}

describe("LifecycleControl", () => {
  it("offers only the transitions the server said are legal", () => {
    render({
      transitions: transitions({
        currentStatus: "Investigating",
        options: [
          option({ target: "Contained", requiredPermission: "incidents:respond" }),
          option({ target: "Resolved", requiresReason: true }),
        ],
      }),
    });

    expect(screen.getByText("Contained")).toBeInTheDocument();
    expect(screen.getByText("Resolved")).toBeInTheDocument();
    // Not offered by the server, so not on screen. The graph is not restated here.
    expect(screen.queryByText("Closed")).not.toBeInTheDocument();
  });

  it("shows a transition the user may not take rather than hiding it", () => {
    // Hiding it would teach an analyst that closing is not something the
    // system does, rather than something somebody else does.
    render({
      transitions: transitions({
        currentStatus: "Resolved",
        options: [
          option({
            target: "Closed",
            permitted: false,
            requiredPermission: "incidents:close",
            requiresReason: true,
          }),
        ],
      }),
    });

    const disabled = screen.getByTitle(/Requires incidents:close/);
    expect(disabled).toBeInTheDocument();
    expect(disabled.tagName).not.toBe("BUTTON");
  });

  it("requires a reason before allowing an edge that ends work", () => {
    render({
      transitions: transitions({
        options: [option({ target: "Resolved", requiresReason: true })],
      }),
    });

    fireEvent.click(screen.getByRole("button", { name: "Resolved" }));
    expect(screen.getByText(/required: this ends or undoes recorded work/i))
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Move to Resolved/ })).toBeDisabled();

    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "confirmed benign" },
    });
    expect(screen.getByRole("button", { name: /Move to Resolved/ })).toBeEnabled();
  });

  it("does not demand a reason for ordinary forward progress", () => {
    render();
    fireEvent.click(screen.getByRole("button", { name: "Triaged" }));
    expect(screen.getByRole("button", { name: /Move to Triaged/ })).toBeEnabled();
  });

  it("submits the chosen target and reason", () => {
    const { onTransition } = render({
      transitions: transitions({
        options: [option({ target: "Resolved", requiresReason: true })],
      }),
    });

    fireEvent.click(screen.getByRole("button", { name: "Resolved" }));
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "done" } });
    fireEvent.click(screen.getByRole("button", { name: /Move to Resolved/ }));

    expect(onTransition).toHaveBeenCalledWith("Resolved", "done");
  });

  it("says when a transition will be recorded against the evidence", () => {
    render({
      transitions: transitions({
        options: [option({ target: "Contained", bindsEvidence: true })],
      }),
    });
    fireEvent.click(screen.getByRole("button", { name: "Contained" }));
    expect(screen.getByText(/refused rather than taken on a stale view/i))
      .toBeInTheDocument();
  });

  it("shows a server refusal verbatim", () => {
    // The message is what tells the analyst what to do next.
    render({
      error: "The evidence for this incident has changed since it was last loaded.",
    });
    fireEvent.click(screen.getByRole("button", { name: "Triaged" }));
    expect(screen.getByText(/changed since it was last loaded/)).toBeInTheDocument();
  });

  it("explains a sealed incident instead of offering nothing", () => {
    render({
      transitions: transitions({
        currentStatus: "Closed",
        isTerminal: true,
        options: [],
      }),
    });
    expect(screen.getByText(/sealed/i)).toBeInTheDocument();
    expect(screen.getByText(/raise a new incident instead/i)).toBeInTheDocument();
  });

  it("does not claim no transition is possible when the request failed", () => {
    render({ transitions: undefined, isError: true });
    expect(screen.getByText(/does not mean none is possible/i)).toBeInTheDocument();
  });

  it("degrades instead of crashing on a malformed payload", () => {
    const malformed = { incidentId: "INC-1024" } as unknown as ApiIncidentTransitions;
    render({ transitions: malformed });
    expect(screen.getByText(/could not be loaded/i)).toBeInTheDocument();
  });
});
