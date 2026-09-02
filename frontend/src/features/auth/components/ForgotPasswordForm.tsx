import { Link } from "react-router-dom";
import { Button, Card, Input, Logo } from "../../../components/ui";

export default function ForgotPasswordForm() {
  return (
    <Card className="w-full max-w-md p-8">
      <div className="flex flex-col items-center gap-4">

        <Logo />

        <div className="text-center">
          <h1 className="text-2xl font-bold">Forgot Password</h1>

          <p className="mt-2 text-sm text-gray-500">
            Enter your registered email address and we'll send you a password
            reset link.
          </p>
        </div>

        <div className="w-full mt-4">
          <Input
            type="email"
            placeholder="Enter your email"
          />
        </div>

        <Button className="w-full mt-2">
          Send Reset Link
        </Button>
<Link
  to="/login"
  className="mt-4 text-sm text-blue-500 hover:underline"
>
  ← Back to Login
</Link>

      </div>
    </Card>

  );
}