import { RefreshCw, LogOut } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/features/auth/hooks/useAuth";

function DashboardHeader() {
  const { logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="mb-10 flex flex-col justify-between gap-6 md:flex-row md:items-center">
      {/* Left */}
      <div>
        <p className="text-sm font-semibold uppercase tracking-[0.25em] text-blue-500">
          Security Operations Center
        </p>

        <h1 className="mt-2 text-5xl font-bold tracking-tight text-white">
          Security Dashboard
        </h1>

        <p className="mt-4 max-w-3xl text-lg leading-7 text-slate-400">
          Monitor threats, incidents, assets and AI-powered security insights
          from one centralized dashboard.
        </p>
      </div>

      {/* Right */}
      <div className="flex gap-3">
        <button
          className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-5 py-3 text-sm font-semibold text-white hover:border-blue-500 hover:bg-slate-800"
        >
          <RefreshCw className="h-5 w-5" />
          Refresh
        </button>

        <button
          onClick={handleLogout}
          className="flex items-center gap-2 rounded-xl border border-red-700 bg-red-600 px-5 py-3 text-sm font-semibold text-white hover:bg-red-500"
        >
          <LogOut className="h-5 w-5" />
          Logout
        </button>
      </div>
    </div>
  );
}

export default DashboardHeader;