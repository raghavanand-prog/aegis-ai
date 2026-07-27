import { useState } from "react";
import {
  Mail,
  LockKeyhole,
  Eye,
  EyeOff,
} from "lucide-react";

import { Card } from "@/components/ui";

export default function LoginForm() {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <Card>
      {/* Heading */}
      <h2 className="text-3xl font-semibold text-foreground">
        Welcome Back
      </h2>

      <p className="mt-2 text-muted-foreground">
        Sign in to continue to Aegis.
      </p>

      {/* Form */}
      <form className="mt-8 space-y-5">
        {/* Email */}
        <div>
          <label
            htmlFor="email"
            className="mb-2 block text-sm font-medium text-foreground"
          >
            Email Address
          </label>

          <div className="relative">
            <Mail
              size={18}
              className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              className="
                w-full
                rounded-xl
                border
                border-border
                bg-slate-900/70
                py-3
                pl-11
                pr-4
                text-white
                placeholder:text-slate-500
                outline-none
                transition
                focus:border-blue-500
                focus:ring-2
                focus:ring-blue-500/20
              "
            />
          </div>
        </div>

        {/* Password */}
        <div>
          <label
            htmlFor="password"
            className="mb-2 block text-sm font-medium text-foreground"
          >
            Password
          </label>

          <div className="relative">
            <LockKeyhole
              size={18}
              className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              placeholder="Enter your password"
              className="
                w-full
                rounded-xl
                border
                border-border
                bg-slate-900/70
                py-3
                pl-11
                pr-12
                text-white
                placeholder:text-slate-500
                outline-none
                transition
                focus:border-blue-500
                focus:ring-2
                focus:ring-blue-500/20
              "
            />

            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="
                absolute
                right-4
                top-1/2
                -translate-y-1/2
                text-slate-500
                transition
                hover:text-white
              "
            >
              {showPassword ? (
                <EyeOff size={18} />
              ) : (
                <Eye size={18} />
              )}
            </button>
          </div>
        </div>

        {/* Remember Me */}
        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center gap-2 text-slate-300">
            <input type="checkbox" />
            <span>Remember Me</span>
          </label>

          <button
            type="button"
            className="text-blue-400 transition hover:text-blue-300"
          >
            Forgot Password?
          </button>
        </div>

        {/* Sign In */}
        <button
          type="submit"
          className="
            w-full
            rounded-xl
            bg-blue-600
            py-3
            font-medium
            text-white
            transition-all
            duration-300
            hover:bg-blue-500
            hover:shadow-lg
            hover:shadow-blue-500/30
            active:scale-[0.98]
          "
        >
          Sign In
        </button>
      </form>

      {/* Footer */}
      <div className="mt-8 border-t border-slate-800 pt-6 text-center">
        <p className="text-xs text-slate-500">
          Protected by{" "}
          <span className="font-semibold text-slate-300">
            Aegis AI
          </span>
        </p>

        <p className="mt-1 text-xs text-slate-600">
          Version 1.0.0
        </p>
      </div>
    </Card>
  );
}