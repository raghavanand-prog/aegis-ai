import { useEffect, useState } from "react";

export default function LiveClock() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  return (
    <p className="text-sm text-slate-400">
      {time.toLocaleTimeString()}
    </p>
  );
}