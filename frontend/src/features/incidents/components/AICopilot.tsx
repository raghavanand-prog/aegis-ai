import { Bot, Send } from "lucide-react";
import { useState } from "react";

export default function AICopilot() {
  const [question, setQuestion] = useState("");
  const [answer] = useState(
    "This incident has been marked High Severity because multiple attack stages were detected, including credential compromise, privilege escalation, and lateral movement. Immediate endpoint isolation is recommended."
  );

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="mb-4 flex items-center gap-2">
        <Bot className="text-cyan-400" size={20} />

        <h3 className="text-lg font-semibold text-white">
          AI Copilot
        </h3>
      </div>

      <textarea
        rows={3}
        value={question}
        onChange={(e) => setQuestion(e.target.value)}
        placeholder="Ask AI about this incident..."
        className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-white outline-none focus:border-cyan-500"
      />

      <button className="mt-3 flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-white transition hover:bg-cyan-500">
        <Send size={16} />
        Ask AI
      </button>

      <div className="mt-5 rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-4">
        <p className="text-sm leading-6 text-slate-300">
          {answer}
        </p>
      </div>
    </div>
  );
}