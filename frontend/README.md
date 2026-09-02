# AEGISX Console

React + TypeScript + Tailwind front end for the AEGISX SOC platform. It talks to the
FastAPI backend in `../backend` over REST and a WebSocket stream.

## Run

```bash
npm install
cp .env.example .env.local     # VITE_API_URL=http://localhost:8000/api/v1
npm run dev
```

The backend must be running (see `../backend/README.md`). Sign in with the bootstrap
analyst account configured in the backend `.env`.

```bash
npm run build          # tsc -b && vite build
npm run lint
npm run typecheck
npm run test           # component tests (vitest + Testing Library)
npm run test:coverage
npm run verify         # everything above, in the order CI runs it
```

## Structure

```
src/
  services/
    api/          axios client, typed endpoint modules, API -> UI mappers
    realtime/     shared WebSocket client, connection-status and cache-sync hooks
  features/
    auth/         AuthContext (real JWT session), login form
    events/       live event table, filters, detail drawer, promotion
    incidents/    incident list, drawer, timeline
    analytics/    charts and KPIs, all fed by /analytics/summary
    notifications/ drawer and unread badge
    dashboard/    layout chrome, stat cards, sidebar, navbar
    threats/      threat intelligence screens (still static demo content)
  components/     shared primitives, Loading / Empty / Error states, error boundaries
  lib/            query client, time formatting, class helpers
  pages/          route-level compositions
  test/           vitest setup and the provider-aware render helper
```

Components never call `axios` directly - everything goes through `services/api`, so
request shapes, auth headers and error normalization live in one place.

## Data sources

Wired to the backend: authentication, events, incidents, notifications, analytics,
IOCs, telemetry status.

Still static demo content: the Threat Intelligence page (CVE feed, malware families,
live threat feed) and some dashboard panels that have no V1 backend equivalent.
These are labelled here rather than quietly presented as live data.

## Reliability

* **Error boundaries** at three levels - the app root, the routed page (cleared
  on navigation) and each Analytics panel - so one broken component cannot blank
  the console.
* **System status bar** merges browser connectivity, API reachability, component
  health and stream state into one line, shown only when something is wrong.
* **Permission-aware UI**: controls a role cannot use are hidden, while the
  backend enforces the same matrix independently. Hiding is usability, not
  security.
* **Detection explanations**: the event drawer shows which rule fired, its
  version, the reason, its risk contribution and the MITRE technique.

## Realtime behaviour

The Events page shows the stream state in its banner: connected, reconnecting, or
disconnected. On drop, the client retries with exponential backoff and jitter, and a
watchdog forces a reconnect if the server heartbeat stops. Data still loads over
HTTP while the socket is down, so the page degrades rather than breaking.
