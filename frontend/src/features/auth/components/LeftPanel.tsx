import {
  ShieldCheck,
  Radar,
  BrainCircuit,
  Activity,
} from "lucide-react";

export default function LeftPanel() {
  return (
    <section
      className="
        relative
        hidden
        lg:flex
        flex-col
        justify-between
        overflow-hidden
        bg-gradient-to-br
        from-slate-950
        via-slate-900
        to-blue-950
        px-16
        py-14
        text-white
      "
    >
      {/* Background Grid */}
      <div
        className="
          absolute
          inset-0
          opacity-[0.04]
          bg-[linear-gradient(to_right,#ffffff_1px,transparent_1px),linear-gradient(to_bottom,#ffffff_1px,transparent_1px)]
          bg-[size:42px_42px]
        "
      />

      {/* Glow */}
      <div className="absolute -left-40 top-40 h-96 w-96 rounded-full bg-blue-500/20 blur-[140px]" />

      {/* Foreground Content */}
      <div className="relative z-10 flex h-full flex-col justify-between">
        {/* Logo */}
        <div>
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-600 text-xl font-bold shadow-lg shadow-blue-600/30">
              A
            </div>

            <div>
              <h1 className="text-3xl font-bold tracking-wide">
                AEGIS
              </h1>

              <p className="text-slate-400">
                AI Cyber Defense Platform
              </p>
            </div>
          </div>
        </div>

        {/* Hero */}
        <div>
          <h2 className="text-5xl font-bold leading-tight">
            Monitor.
            <br />
            Detect.
            <br />
            Respond.
          </h2>

          <p className="mt-6 max-w-md text-lg text-slate-400">
            Intelligent cybersecurity powered by AI for modern
            Security Operations Centers.
          </p>

          <div className="mt-12 space-y-6">
            <div className="flex items-center gap-4">
              <ShieldCheck className="h-6 w-6 text-blue-400" />
              <span>Threat Detection</span>
            </div>

            <div className="flex items-center gap-4">
              <Radar className="h-6 w-6 text-blue-400" />
              <span>Live Monitoring</span>
            </div>

            <div className="flex items-center gap-4">
              <BrainCircuit className="h-6 w-6 text-blue-400" />
              <span>AI Investigation</span>
            </div>

            <div className="flex items-center gap-4">
              <Activity className="h-6 w-6 text-blue-400" />
              <span>Incident Response</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-sm text-slate-500">
          <p>Aegis v1.0.0</p>
          <p className="mt-1">
            © 2026 Aegis Security Labs
          </p>
        </div>
      </div>
    </section>
  );
}