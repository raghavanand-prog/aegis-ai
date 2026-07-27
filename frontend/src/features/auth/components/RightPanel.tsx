import LoginForm from "./LoginForm";

export default function RightPanel() {
  return (
    <section
      className="
        relative
        flex
        items-center
        justify-center
        overflow-hidden
        bg-gradient-to-b
        from-slate-900
        to-slate-950
        p-8
      "
    >
      {/* Background Glow */}
      <div className="absolute right-0 top-1/2 h-80 w-80 -translate-y-1/2 rounded-full bg-blue-500/10 blur-[120px]" />

      {/* Form */}
      <div className="relative z-10 w-full max-w-md">
        <LoginForm />
      </div>
    </section>
  );
}