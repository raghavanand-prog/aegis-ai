import { ReactNode, useEffect } from "react";
import {
  animate,
  motion,
  useMotionValue,
  useTransform,
} from "framer-motion";

interface StatCardProps {
  title: string;
  value: number;
  icon: ReactNode;
  trend: string;
  trendColor?: string;
  delay?: number;
}

export default function StatCard({
  title,
  value,
  icon,
  trend,
  trendColor = "text-emerald-400",
  delay = 0,
}: StatCardProps) {
  const count = useMotionValue(0);

  const rounded = useTransform(count, (latest) =>
    Math.round(latest).toLocaleString()
  );

  useEffect(() => {
    const timer = setTimeout(() => {
      const controls = animate(count, value, {
        duration: 1.6,
        ease: "easeOut",
      });

      return () => controls.stop();
    }, delay * 1000);

    return () => clearTimeout(timer);
  }, [count, value, delay]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{
        duration: 0.5,
        delay,
      }}
      whileHover={{
        y: -6,
        scale: 1.02,
      }}
      className="
        group
        relative
        overflow-hidden
        rounded-2xl
        border
        border-slate-700/70
        bg-gradient-to-br
        from-slate-900
        via-slate-900
        to-slate-950
        p-6
        shadow-lg
        transition-all
        duration-300
        hover:border-cyan-500/40
        hover:shadow-[0_0_35px_rgba(34,211,238,0.15)]
      "
    >
      {/* Background Glow */}
      <div className="absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100">
        <div className="absolute -top-28 -right-24 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-widest text-slate-400">
            {title}
          </p>

          <motion.h2
            className="mt-3 text-4xl font-bold tracking-tight text-white"
          >
            {rounded}
          </motion.h2>

          <p className={`mt-3 text-sm font-semibold ${trendColor}`}>
            {trend}
          </p>
        </div>

        <motion.div
          whileHover={{
            rotate: 8,
            scale: 1.12,
          }}
          className="
            flex
            h-14
            w-14
            items-center
            justify-center
            rounded-xl
            bg-cyan-500/10
            text-cyan-400
          "
        >
          {icon}
        </motion.div>
      </div>
    </motion.div>
  );
}