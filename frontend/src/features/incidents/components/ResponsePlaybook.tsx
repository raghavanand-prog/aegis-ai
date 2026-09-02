import { CheckCircle2 } from "lucide-react";

const steps = [
  {
    title: "Isolate Endpoint",
    completed: true,
  },
  {
    title: "Disable Compromised Account",
    completed: true,
  },
  {
    title: "Collect Memory Dump",
    completed: false,
  },
  {
    title: "Run Full EDR Scan",
    completed: false,
  },
  {
    title: "Notify SOC Manager",
    completed: false,
  },
  {
    title: "Generate Incident Report",
    completed: false,
  },
];

export default function ResponsePlaybook() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h3 className="mb-5 text-lg font-semibold text-white">
        Response Playbook
      </h3>

      <div className="space-y-4">
        {steps.map((step, index) => (
          <div
            key={index}
            className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-3"
          >
            <div className="flex items-center gap-3">
              <CheckCircle2
                className={
                  step.completed
                    ? "text-green-400"
                    : "text-slate-600"
                }
                size={20}
              />

              <span className="text-white">
                {step.title}
              </span>
            </div>

            <span
              className={`rounded px-2 py-1 text-xs ${
                step.completed
                  ? "bg-green-500/20 text-green-400"
                  : "bg-yellow-500/20 text-yellow-400"
              }`}
            >
              {step.completed ? "Done" : "Pending"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}