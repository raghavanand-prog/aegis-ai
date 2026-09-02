interface Props {
  severity: string;
}

export default function StatusBadge({ severity }: Props) {
  const styles = {
    Critical:
      "bg-red-500/10 text-red-400 border border-red-500/20",

    High:
      "bg-orange-500/10 text-orange-400 border border-orange-500/20",

    Medium:
      "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20",

    Low:
      "bg-blue-500/10 text-blue-400 border border-blue-500/20",
  };

  return (
    <span
      className={`rounded-full px-3 py-1 text-xs font-medium ${
        styles[severity as keyof typeof styles]
      }`}
    >
      {severity}
    </span>
  );
}