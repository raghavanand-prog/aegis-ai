import {
  CheckCircle2,
  ShieldAlert,
  Terminal,
  Server,
  Lock,
} from "lucide-react";

const events = [
  {
    time: "09:42 AM",
    title: "Initial Login",
    description: "User john.doe authenticated successfully.",
    icon: CheckCircle2,
    color: "text-green-400",
  },
  {
    time: "09:44 AM",
    title: "PowerShell Execution",
    description: "Encoded PowerShell command executed.",
    icon: Terminal,
    color: "text-yellow-400",
  },
  {
    time: "09:46 AM",
    title: "Privilege Escalation",
    description: "Administrator privileges obtained.",
    icon: Lock,
    color: "text-orange-400",
  },
  {
    time: "09:48 AM",
    title: "Lateral Movement",
    description: "Remote execution detected on SERVER-02.",
    icon: Server,
    color: "text-red-400",
  },
  {
    time: "09:50 AM",
    title: "EDR Response",
    description: "Endpoint isolated automatically.",
    icon: ShieldAlert,
    color: "text-cyan-400",
  },
];

export default function IncidentTimeline() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h3 className="mb-6 text-lg font-semibold text-white">
        Incident Timeline
      </h3>

      <div className="space-y-6">
        {events.map((event, index) => {
          const Icon = event.icon;

          return (
            <div key={index} className="flex gap-4">
              <div className="flex flex-col items-center">
                <Icon className={`${event.color}`} size={20} />

                {index !== events.length - 1 && (
                  <div className="mt-2 h-12 w-px bg-slate-700" />
                )}
              </div>

              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-white">
                    {event.title}
                  </h4>

                  <span className="text-xs text-slate-500">
                    {event.time}
                  </span>
                </div>

                <p className="mt-1 text-sm text-slate-300">
                  {event.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}