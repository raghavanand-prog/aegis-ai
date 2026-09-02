import {
  LayoutDashboard,
  ShieldAlert,
  ShieldCheck,
  FileText,
  BarChart3,
  Network,
  FlaskConical,
  Settings,
  LogOut,
} from "lucide-react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../../auth/hooks/useAuth";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export default function Sidebar({
  collapsed,
}: SidebarProps) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center ${
      collapsed ? "justify-center" : "gap-3"
    } rounded-lg px-4 py-3 transition-all duration-200 ${
      isActive
        ? "bg-cyan-600 text-white shadow-md"
        : "text-slate-300 hover:bg-slate-800 hover:text-white"
    }`;

  return (
    <aside
      className={`
        ${collapsed ? "w-20" : "w-72"}
        flex
        min-h-screen
        flex-col
        border-r
        border-slate-800
        bg-slate-950
        text-white
        transition-all
        duration-300
      `}
    >
      {/* Logo */}
      <div className="border-b border-slate-800 px-6 py-6">
        {collapsed ? (
          <div className="flex justify-center">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-600 text-lg font-bold">
              A
            </div>
          </div>
        ) : (
          <>
            <h1 className="text-2xl font-bold tracking-wide">
              AEGIS X
            </h1>

            <p className="mt-1 text-sm text-slate-400">
              Security Operations Center
            </p>
          </>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-2 px-4 py-6">
        <NavLink to="/dashboard" className={navLinkClass}>
          <LayoutDashboard className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Dashboard</span>}
        </NavLink>

        <NavLink
          to="/dashboard/threats"
          className={navLinkClass}
        >
          <ShieldAlert className="h-5 w-5 flex-shrink-0" />
          {!collapsed && (
            <span>Threat Intelligence</span>
          )}
        </NavLink>

        <NavLink
          to="/dashboard/incidents"
          className={navLinkClass}
        >
          <ShieldCheck className="h-5 w-5 flex-shrink-0" />
          {!collapsed && (
            <span>Incident Response</span>
          )}
        </NavLink>

        <NavLink
          to="/dashboard/events"
          className={navLinkClass}
        >
          <FileText className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Events</span>}
        </NavLink>

        <NavLink
          to="/dashboard/sequences"
          className={navLinkClass}
        >
          <Network className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Correlation</span>}
        </NavLink>

        <NavLink
          to="/dashboard/research"
          className={navLinkClass}
        >
          <FlaskConical className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Research</span>}
        </NavLink>

        <NavLink
          to="/dashboard/analytics"
          className={navLinkClass}
        >
          <BarChart3 className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Analytics</span>}
        </NavLink>

        <NavLink
          to="/dashboard/settings"
          className={navLinkClass}
        >
          <Settings className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Settings</span>}
        </NavLink>
      </nav>

      {/* Footer */}
      <div className="border-t border-slate-800 p-4">
        <button
          onClick={handleLogout}
          className={`flex w-full items-center ${
            collapsed ? "justify-center" : "gap-3"
          } rounded-lg px-4 py-3 text-slate-300 transition-all duration-200 hover:bg-red-600 hover:text-white`}
        >
          <LogOut className="h-5 w-5 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </aside>
  );
}