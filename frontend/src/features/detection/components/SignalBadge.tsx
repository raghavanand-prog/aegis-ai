import type { SignalKind } from "../signalVocabulary";
import { SIGNAL_STYLES } from "../signalVocabulary";

/**
 * A labelled badge for one kind of evidence.
 *
 * The vocabulary itself lives in `../signalVocabulary`; this file renders it.
 */

interface SignalBadgeProps {
  kind: SignalKind;
  /** Optional trailing text, e.g. a rule id or a model version. */
  detail?: string;
  size?: "sm" | "md";
  showIcon?: boolean;
}

export default function SignalBadge({
  kind,
  detail,
  size = "md",
  showIcon = true,
}: SignalBadgeProps) {
  const style = SIGNAL_STYLES[kind] ?? SIGNAL_STYLES.context;
  const Icon = style.icon;

  return (
    <span
      title={style.meaning}
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${style.className} ${
        size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs"
      }`}
    >
      {showIcon && <Icon size={size === "sm" ? 11 : 13} />}
      {style.label}
      {detail && <span className="opacity-70">· {detail}</span>}
    </span>
  );
}

/** Small legend, used at the top of evidence views. */
export function SignalLegend({ kinds }: { kinds: SignalKind[] }) {
  if (kinds.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {kinds.map((kind) => (
        <SignalBadge key={kind} kind={kind} size="sm" />
      ))}
    </div>
  );
}
