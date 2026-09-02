import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface CardContentProps {
  children: ReactNode;
  className?: string;
}

export default function CardContent({
  children,
  className,
}: CardContentProps) {
  return (
    <div className={cn("p-6", className)}>
      {children}
    </div>
  );
}