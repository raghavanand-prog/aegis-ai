import LeftPanel from "../../features/auth/components/LeftPanel";
import RightPanel from "../../features/auth/components/RightPanel";

export default function LoginPage() {
  return (
    <main className="min-h-screen bg-background">
      <div className="grid min-h-screen lg:grid-cols-2">
        <LeftPanel />
        <RightPanel />
      </div>
    </main>
  );
}