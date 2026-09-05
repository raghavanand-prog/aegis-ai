import ProviderHealthPanel from "@/features/providers/components/ProviderHealthPanel";

/**
 * Operational settings.
 *
 * Still mostly unbuilt. What it does carry, from V9 Phase F, is the evidence
 * source listing - the one place where "no source reported this" can be told
 * apart from "no source was able to".
 */
export default function SettingsPage() {
  return (
    <div className="space-y-8 text-white">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="mt-2 text-slate-400">
          Configuration is not yet exposed here. The platform state below is
          read-only.
        </p>
      </div>

      <ProviderHealthPanel />
    </div>
  );
}
