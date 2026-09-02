import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";

interface AnimatedStatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  color: string;
  trend?: string;
  trendPositive?: boolean;
  delay?: number;
}

export default function AnimatedStatCard({
  title,
  value,
  icon: Icon,
  color,
  trend,
  trendPositive = true,
  delay = 0,
}: AnimatedStatCardProps) {
  const isNumber = typeof value === "number";
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (!isNumber) return;

    const end = value as number;
    const duration = 2000; // 2 seconds
    const fps = 60;
    const totalFrames = (duration / 1000) * fps;
    let frame = 0;

    const interval = setInterval(() => {
      frame++;
      const progress = frame / totalFrames;
      const current = Math.round(end * progress);

      setCount(current);

      if (frame >= totalFrames) {
        setCount(end);
        clearInterval(interval);
      }
    }, 1000 / fps);

    return () => clearInterval(interval);
  }, [value, isNumber]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay }}
      whileHover={{
        y: -6,
        scale: 1.02,
        transition: { duration: 0.2 },
      }}
      className="group relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg transition-all hover:border-cyan-500/40 hover:shadow-cyan-500/10"
    >
      {/* Background Glow */}
      <div className="absolute -right-10 -top-10 h-40 w-40 rounded-full bg-cyan-500/10 blur-3xl opacity-0 transition-opacity duration-300 group-hover:opacity-100" />

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-slate-400">
            {title}
          </p>

          <h2 className="mt-3 text-4xl font-bold text-white">
            {isNumber ? count.toLocaleString() : value}
          </h2>

          {trend && (
            <div
              className={`mt-4 inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
                trendPositive
                  ? "bg-green-500/10 text-green-400"
                  : "bg-red-500/10 text-red-400"
              }`}
            >
              {trendPositive ? "▲" : "▼"} {trend}
            </div>
          )}
        </div>

        <div className="rounded-2xl bg-slate-800 p-4 shadow-inner">
          <Icon className={`h-7 w-7 ${color}`} />
        </div>
      </div>
    </motion.div>
  );
}