import { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type Variant =
  | "primary"
  | "secondary"
  | "danger"
  | "ghost";

interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
}

const variants = {
  primary:
    "bg-blue-600 hover:bg-blue-500 text-white",

  secondary:
    "bg-slate-800 hover:bg-slate-700 text-white border border-border",

  danger:
    "bg-red-600 hover:bg-red-500 text-white",

  ghost:
    "hover:bg-slate-800 text-slate-300",
};

export default function Button({
  children,
  variant = "primary",
  className,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        `
        inline-flex
        items-center
        justify-center

        rounded-xl

        px-5
        py-2.5

        text-sm
        font-medium

        transition-all
        duration-200

        active:scale-95

        disabled:opacity-50
        disabled:pointer-events-none
        `,
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}