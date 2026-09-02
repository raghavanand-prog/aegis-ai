import { InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type CheckboxProps = InputHTMLAttributes<HTMLInputElement>;

export default function Checkbox({
  className,
  ...props
}: CheckboxProps) {
  return (
    <input
      type="checkbox"
      className={cn(
        "h-4 w-4 rounded border-slate-600 accent-blue-600",
        className
      )}
      {...props}
    />
  );
}