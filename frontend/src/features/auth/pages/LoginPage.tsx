import LeftPanel from "../components/LeftPanel";
import RightPanel from "../components/RightPanel";

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