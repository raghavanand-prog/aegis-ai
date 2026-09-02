import { useState, InputHTMLAttributes } from "react";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";

type PasswordInputProps = InputHTMLAttributes<HTMLInputElement>;

export default function PasswordInput({
  className,
  ...props
}: PasswordInputProps) {
  const [show, setShow] = useState(false);

  return (
    <div className="relative">
      <input
        type={show ? "text" : "password"}
        className={cn(
          "w-full rounded-xl border border-border bg-slate-900/70 px-4 py-3 pr-12 text-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20",
          className
        )}
        {...props}
      />

      <button
        type="button"
        onClick={() => setShow(!show)}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
      >
        {show ? <EyeOff size={18} /> : <Eye size={18} />}
      </button>
    </div>
  );
}