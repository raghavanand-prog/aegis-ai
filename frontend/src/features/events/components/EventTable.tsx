import EventRow from "./EventRow";
import type { Event } from "../types";

interface EventTableProps {
  events: Event[];
  onEventClick: (event: Event) => void;
  onPromote: (event: Event) => void;
  canPromote?: boolean;
}

export default function EventTable({
  events,
  onEventClick,
  onPromote,
  canPromote = true,
}: EventTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="border-b border-slate-800 bg-slate-950">
            <tr className="text-left text-sm text-slate-400">
              <th className="px-4 py-4">Time</th>
              <th className="px-4 py-4">Source</th>
              <th className="px-4 py-4">Event</th>
              <th className="px-4 py-4">Severity</th>
              <th className="px-4 py-4">Status</th>
              <th className="px-4 py-4">Actions</th>
            </tr>
          </thead>

          <tbody>
            {events.length > 0 ? (
              events.map((event) => (
                <EventRow
                  key={event.id}
                  event={event}
                  onClick={() => onEventClick(event)}
                  onPromote={() => onPromote(event)}
                  canPromote={canPromote && !event.incidentId}
                />
              ))
            ) : (
              <tr>
                <td
                  colSpan={6}
                  className="py-10 text-center text-slate-500"
                >
                  No events found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
