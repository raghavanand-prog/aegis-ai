import { useState } from "react";
import { Bell, Menu, Search, UserCircle } from "lucide-react";

import NotificationDrawer from "@/features/notifications/NotificationDrawer";
import { useNotificationCounts } from "@/features/notifications/hooks/useNotifications";
import { useAuth } from "@/features/auth/hooks/useAuth";

interface TopNavbarProps {
  collapsed: boolean;
  onToggle: () => void;
}

function TopNavbar({ onToggle }: TopNavbarProps) {
  const [openNotifications, setOpenNotifications] = useState(false);

  const { user } = useAuth();
  const { data: counts } = useNotificationCounts();

  const notificationCount = counts?.unread ?? 0;

  return (
    <>
      <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950 px-6">
        {/* Left */}
        <div className="flex items-center gap-4">
          <button
            onClick={onToggle}
            className="rounded-lg p-2 transition hover:bg-slate-800"
          >
            <Menu size={20} className="text-slate-300" />
          </button>

          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        </div>

        {/* Right */}
        <div className="flex items-center gap-5">
          {/* Search */}
          <button className="rounded-lg p-2 transition hover:bg-slate-800">
            <Search size={20} className="text-slate-300 hover:text-white" />
          </button>

          {/* Notifications */}
          <button
            onClick={() => setOpenNotifications(true)}
            className="relative rounded-lg p-2 transition hover:bg-slate-800"
          >
            <Bell size={20} className="text-slate-300 hover:text-white" />

            {notificationCount > 0 && (
              <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
                {notificationCount > 99 ? "99+" : notificationCount}
              </span>
            )}
          </button>

          {/* User */}
          <div className="flex items-center gap-3">
            <UserCircle size={34} className="text-slate-300" />

            <div className="text-right">
              <p className="text-sm font-semibold text-white">
                {user?.fullName || user?.email || "Analyst"}
              </p>

              <p className="text-xs capitalize text-slate-400">
                {user?.role ?? "security analyst"}
              </p>
            </div>
          </div>
        </div>
      </header>

      <NotificationDrawer
        open={openNotifications}
        onClose={() => setOpenNotifications(false)}
      />
    </>
  );
}

export default TopNavbar;
