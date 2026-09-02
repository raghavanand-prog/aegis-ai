import { ArrowUpCircle } from "lucide-react";
import SeverityBadge from "./SeverityBadge";
import type { Event } from "../types";

interface EventRowProps {
  event: Event;
  onClick: () => void;
  onPromote: () => void;
  /** False for read-only roles; the backend refuses the call either way. */
  canPromote?: boolean;
}

export default function EventRow({
  event,
  onClick,
  onPromote,
  canPromote = true,
}: EventRowProps) {
  return (
    <tr
      onClick={onClick}
      className="cursor-pointer border-b border-slate-800 transition hover:bg-slate-800/60"
    >
      <td className="px-4 py-4 text-slate-300">
        {event.time}
      </td>

      <td className="px-4 py-4 font-medium text-white">
        {event.source}
      </td>

      <td className="px-4 py-4 text-slate-300">
        {event.event}
      </td>

      <td className="px-4 py-4">
        <SeverityBadge severity={event.severity} />
      </td>

      <td className="px-4 py-4">
        <span
          className={`rounded-full px-3 py-1 text-xs font-medium ${
            event.status === "Resolved"
              ? "bg-green-500/20 text-green-400"
              : event.status === "Investigating"
              ? "bg-yellow-500/20 text-yellow-400"
              : "bg-cyan-500/20 text-cyan-400"
          }`}
        >
          {event.status}
        </span>
      </td>

      <td className="px-4 py-4">
{canPromote && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onPromote();
          }}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-cyan-500"
        >
          <ArrowUpCircle size={16} />
          Promote
        </button>
)}
      </td>
    </tr>
  );
}
