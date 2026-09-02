import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ErrorBoundary from "../ErrorBoundary";

function Explodes(): never {
  throw new Error("panel exploded");
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    // React logs the caught error; keep the test output readable.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => vi.restoreAllMocks());

  it("contains the failure instead of unmounting the whole page", () => {
    render(
      <div>
        <ErrorBoundary label="Threat feed">
          <Explodes />
        </ErrorBoundary>
        <p>Rest of the console</p>
      </div>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(/Threat feed failed to render/i);
    expect(screen.getByText("Rest of the console")).toBeInTheDocument();
  });

  it("renders children normally when nothing throws", () => {
    render(
      <ErrorBoundary>
        <p>All good</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("All good")).toBeInTheDocument();
  });

  it("recovers when the analyst retries", async () => {
    const user = userEvent.setup();
    let shouldThrow = true;

    function Sometimes() {
      if (shouldThrow) throw new Error("transient");
      return <p>Recovered</p>;
    }

    render(
      <ErrorBoundary>
        <Sometimes />
      </ErrorBoundary>,
    );

    shouldThrow = false;
    await user.click(screen.getByRole("button", { name: /try again/i }));

    expect(screen.getByText("Recovered")).toBeInTheDocument();
  });

  it("clears the error when the reset key changes", () => {
    const { rerender } = render(
      <ErrorBoundary resetKeys={["/dashboard"]}>
        <Explodes />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeInTheDocument();

    rerender(
      <ErrorBoundary resetKeys={["/dashboard/events"]}>
        <p>New route</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("New route")).toBeInTheDocument();
  });
});
