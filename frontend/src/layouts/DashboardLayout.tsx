import { Outlet } from "react-router-dom";
import { useState } from "react";

import { useLocation } from "react-router-dom";

import Sidebar from "../features/dashboard/components/Sidebar";
import TopNavbar from "../features/dashboard/components/TopNavbar";
import SystemStatusBar from "../features/dashboard/components/SystemStatusBar";
import ErrorBoundary from "@/components/ErrorBoundary";
import { useLiveCacheSync } from "@/services/realtime/useLiveCacheSync";

export default function DashboardLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  // One live connection for the whole dashboard: keeps every page's cached
  // data in step with the backend stream.
  useLiveCacheSync();

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed(!collapsed)}
      />

      <div className="flex flex-1 flex-col">
        <TopNavbar
          collapsed={collapsed}
          onToggle={() => setCollapsed(!collapsed)}
        />

        <ErrorBoundary label="System status">
          <SystemStatusBar />
        </ErrorBoundary>

        <main className="flex-1 overflow-y-auto p-8">
          {/* A crash in one page must not take the shell down with it, and
              navigating away clears the error. */}
          <ErrorBoundary label="This page" resetKeys={[location.pathname]}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
