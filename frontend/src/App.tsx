import { useEffect, useState } from "react";

import AppRoutes from "./routes/AppRoutes";

import CommandPalette from "./features/command/CommandPalette";
import { useAuth } from "./features/auth/hooks/useAuth";

export default function App() {
  const { isAuthenticated } = useAuth();

  const [commandOpen, setCommandOpen] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandOpen((v) => !v);
      }

      if (e.key === "Escape") {
        setCommandOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () =>
      window.removeEventListener("keydown", handleKeyDown);
  }, [isAuthenticated]);

  return (
    <>
      <AppRoutes />

      {isAuthenticated && commandOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 backdrop-blur-sm pt-24"
          onClick={() => setCommandOpen(false)}
        >
          <div
            className="w-full max-w-2xl px-4"
            onClick={(e) => e.stopPropagation()}
          >
            <CommandPalette />
          </div>
        </div>
      )}
    </>
  );
}