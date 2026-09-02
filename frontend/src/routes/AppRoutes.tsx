import { Routes, Route, Navigate } from "react-router-dom";

import LoginPage from "../features/auth/pages/LoginPage";

import DashboardLayout from "../layouts/DashboardLayout";
import ProtectedRoute from "./ProtectedRoute";

import DashboardPage from "../pages/dashboard/DashboardPage";
import ThreatsPage from "../pages/dashboard/ThreatsPage";
import IncidentsPage from "../pages/dashboard/IncidentsPage";
import AnalyticsPage from "../features/analytics/AnalyticsPage";
import SettingsPage from "../pages/dashboard/SettingsPage";
import EventsPage from "../pages/events/EventsPage";
import SequencesPage from "../pages/dashboard/SequencesPage";

export default function AppRoutes() {
  return (
    <Routes>
      {/* Redirect root */}
      <Route
        path="/"
        element={<Navigate to="/login" replace />}
      />

      {/* Public Route */}
      <Route
        path="/login"
        element={<LoginPage />}
      />

      {/* Protected Dashboard Routes */}
      <Route
        element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }
      >
        <Route
          path="/dashboard"
          element={<DashboardPage />}
        />

        <Route
          path="/dashboard/threats"
          element={<ThreatsPage />}
        />

        <Route
          path="/dashboard/incidents"
          element={<IncidentsPage />}
        />

        <Route
          path="/dashboard/events"
          element={<EventsPage />}
        />

        <Route
          path="/dashboard/sequences"
          element={<SequencesPage />}
        />

        <Route
          path="/dashboard/analytics"
          element={<AnalyticsPage />}
        />

        <Route
          path="/dashboard/settings"
          element={<SettingsPage />}
        />
      </Route>

      {/* Catch All */}
      <Route
        path="*"
        element={<Navigate to="/dashboard" replace />}
      />
    </Routes>
  );
}