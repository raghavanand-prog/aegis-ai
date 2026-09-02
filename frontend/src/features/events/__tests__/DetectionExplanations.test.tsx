import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import DetectionExplanations from "../components/DetectionExplanations";

const DETECTION = {
  ruleId: "DET-CRED-001",
  ruleVersion: "1.0",
  ruleName: "Credential dumping",
  reason: "procdump64.exe opened LSASS memory with access mask 0x1010",
  severity: "Critical",
  riskContribution: 80,
  mitreTechniques: ["T1003.001"],
  matchedAt: new Date().toISOString(),
};

describe("Detection explanation", () => {
  it("tells the analyst which rule fired and why", () => {
    render(<DetectionExplanations detections={[DETECTION]} />);

    expect(screen.getByText("Credential dumping")).toBeInTheDocument();
    expect(screen.getByText(/opened LSASS memory/)).toBeInTheDocument();
    expect(screen.getByText("DET-CRED-001 v1.0")).toBeInTheDocument();
    expect(screen.getByText("risk +80")).toBeInTheDocument();
    expect(screen.getByText("T1003.001")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("says so when an older event has ids but no stored reasons", () => {
    render(<DetectionExplanations ruleIds={["AEGIS-R002"]} />);

    expect(screen.getByText("AEGIS-R002")).toBeInTheDocument();
    expect(
      screen.getByText(/Recorded before rule explanations were stored/i),
    ).toBeInTheDocument();
  });

  it("renders nothing when no rule fired", () => {
    const { container } = render(<DetectionExplanations detections={[]} ruleIds={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
