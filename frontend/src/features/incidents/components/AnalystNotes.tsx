import { useState } from "react";
import { NotebookPen } from "lucide-react";

export default function AnalystNotes() {
  const [notes, setNotes] = useState(
    "Initial investigation started. AI recommends endpoint isolation."
  );

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="mb-4 flex items-center gap-2">
        <NotebookPen className="text-cyan-400" size={20} />

        <h3 className="text-lg font-semibold text-white">
          Analyst Notes
        </h3>
      </div>

      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={8}
        className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-slate-200 outline-none transition focus:border-cyan-500"
        placeholder="Write investigation notes..."
      />

      <button
        className="mt-4 rounded-lg bg-cyan-600 px-5 py-2 font-medium text-white transition hover:bg-cyan-500"
      >
        Save Notes
      </button>
    </div>
  );
}