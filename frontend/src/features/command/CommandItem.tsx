type Props = {
  icon: string;
  title: string;
};

export default function CommandItem({
  icon,
  title,
}: Props) {
  return (
    <button
      className="
        flex
        w-full
        items-center
        gap-3
        rounded-lg
        px-4
        py-3
        transition
        hover:bg-slate-800
      "
    >
      <span className="text-xl">{icon}</span>

      <span className="text-slate-200">
        {title}
      </span>
    </button>
  );
}