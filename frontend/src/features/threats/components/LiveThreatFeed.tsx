import { useEffect, useState } from "react";
import { liveThreats } from "../data/liveThreats";
import ThreatFeedItem from "./ThreatFeedItem";

export default function LiveThreatFeed() {
  const [feed, setFeed] = useState(liveThreats);

  useEffect(() => {
    const interval = setInterval(() => {
      setFeed((prev) => {
        const next = [...prev];

        const item = next.pop();

        if (item) {
          next.unshift(item);
        }

        return next;
      });
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">
          Live Threat Feed
        </h2>

        <div className="flex items-center gap-2">
          <span className="h-2 w-2 animate-pulse rounded-full bg-green-400" />
          <span className="text-sm text-slate-400">
            Live
          </span>
        </div>
      </div>

      <div className="space-y-4">
        {feed.map((threat) => (
          <ThreatFeedItem
            key={threat.id}
            {...threat}
          />
        ))}
      </div>
    </div>
  );
}