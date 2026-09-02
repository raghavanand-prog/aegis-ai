import {
  Globe,
  Laptop,
  User,
  FileCode,
} from "lucide-react";

const evidence = [
  {
    icon: Globe,
    label: "Source IP",
    value: "185.199.110.23",
  },
  {
    icon: Laptop,
    label: "Hostname",
    value: "WIN-CLIENT-07",
  },
  {
    icon: User,
    label: "Affected User",
    value: "john.doe",
  },
  {
    icon: FileCode,
    label: "PowerShell",
    value: "powershell.exe -enc SQBtA...",
  },
];

export default function EvidencePanel() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h3 className="mb-5 text-lg font-semibold text-white">
        Evidence
      </h3>

      <div className="space-y-4">
        {evidence.map((item) => {
          const Icon = item.icon;

          return (
            <div
              key={item.label}
              className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950 p-3"
            >
              <Icon
                className="mt-1 text-cyan-400"
                size={18}
              />

              <div>
                <p className="text-sm text-slate-400">
                  {item.label}
                </p>

                <p className="mt-1 break-all text-sm text-white">
                  {item.value}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}