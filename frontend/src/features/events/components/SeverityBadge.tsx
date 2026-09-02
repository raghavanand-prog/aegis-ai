interface SeverityBadgeProps {
  severity: "Low" | "Medium" | "High" | "Critical";
}

export default function SeverityBadge({
  severity,
}: SeverityBadgeProps) {
  const styles = {
    Low: "bg-emerald-500/20 text-emerald-400",
    Medium: "bg-yellow-500/20 text-yellow-400",
    High: "bg-orange-500/20 text-orange-400",
    Critical: "bg-red-500/20 text-red-400",
  };

  return (
    <span
      className={`rounded-full px-3 py-1 text-xs font-semibold ${styles[severity]}`}
    >
      {severity}
    </span>
  );
}