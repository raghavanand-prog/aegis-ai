import { Bell } from "lucide-react";
import { useEffect, useState } from "react";

export default function NotificationBell() {
  const [count, setCount] = useState(3);

  useEffect(() => {
    const interval = setInterval(() => {
      setCount((c) => (c >= 99 ? 99 : c + 1));
    }, 8000);

    return () => clearInterval(interval);
  }, []);

  return (
    <button className="relative rounded-xl border border-slate-800 bg-slate-900 p-2 transition hover:border-cyan-500">
      <Bell className="h-5 w-5 text-slate-300" />

      {count > 0 && (
        <span className="absolute -right-2 -top-2 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
          {count}
        </span>
      )}
    </button>
  );
}