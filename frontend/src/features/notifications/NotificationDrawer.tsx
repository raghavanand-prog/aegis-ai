import { CheckCheck, X } from "lucide-react";

import NotificationItem from "./NotificationItem";
import {
  useMarkAllNotificationsRead,
  useNotificationsQuery,
} from "./hooks/useNotifications";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui";

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function NotificationDrawer({ open, onClose }: Props) {
  // Only fetch while the drawer is actually open.
  const { data, isLoading, isError, error, refetch } = useNotificationsQuery(open);
  const markAllRead = useMarkAllNotificationsRead();

  const notifications = data ?? [];

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-40 bg-black/60" onClick={onClose} />
      )}

      <aside
        className={`fixed right-0 top-0 z-50 h-screen w-[380px] overflow-y-auto border-l border-slate-800 bg-slate-950 transition-transform duration-300 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between border-b border-slate-800 p-6">
          <h2 className="text-xl font-bold text-white">Notifications</h2>

          <div className="flex items-center gap-3">
            {notifications.length > 0 && (
              <button
                onClick={() => markAllRead.mutate()}
                disabled={markAllRead.isPending}
                title="Mark all as read"
                className="text-slate-400 transition hover:text-white disabled:opacity-50"
              >
                <CheckCheck size={18} />
              </button>
            )}

            <button onClick={onClose}>
              <X className="text-slate-400 hover:text-white" />
            </button>
          </div>
        </div>

        <div className="space-y-4 p-6">
          {isLoading ? (
            <LoadingState label="Loading notifications..." />
          ) : isError ? (
            <ErrorState error={error} onRetry={() => void refetch()} />
          ) : notifications.length === 0 ? (
            <EmptyState
              title="Nothing to review"
              description="High and critical events raise a notification here as they arrive."
            />
          ) : (
            notifications.map((notification) => (
              <NotificationItem key={notification.id} notification={notification} />
            ))
          )}
        </div>
      </aside>
    </>
  );
}
