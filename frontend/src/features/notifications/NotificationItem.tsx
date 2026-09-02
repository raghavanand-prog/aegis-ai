import type { Notification } from "./notifications";
import { useMarkNotificationRead } from "./hooks/useNotifications";

const colors = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

export default function NotificationItem({
  notification,
}: {
  notification: Notification;
}) {
  const markRead = useMarkNotificationRead();
  const isUnread = notification.isRead === false;

  return (
    <div
      onClick={() => {
        if (isUnread) markRead.mutate(notification.id);
      }}
      className={`cursor-pointer rounded-xl border bg-slate-900 p-4 transition hover:border-blue-500 ${
        isUnread ? "border-slate-700" : "border-slate-800 opacity-70"
      }`}
    >
      <div className="flex gap-3">
        <div
          className={`mt-1 h-3 w-3 rounded-full ${colors[notification.severity]}`}
        />

        <div className="flex-1">
          <div className="flex justify-between">
            <h3 className="font-semibold text-white">{notification.title}</h3>

            <span className="text-xs text-slate-500">{notification.time}</span>
          </div>

          <p className="mt-2 text-sm text-slate-400">{notification.description}</p>

          {(notification.incidentId || notification.eventId) && (
            <p className="mt-2 text-xs text-slate-600">
              {notification.incidentId ?? notification.eventId}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
