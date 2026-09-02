import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface CardFooterProps {
  children: ReactNode;
  className?: string;
}

export default function CardFooter({
  children,
  className,
}: CardFooterProps) {
  return (
    <div
      className={cn(
        "border-t border-border/60 p-6",
        className
      )}
    >
      {children}
    </div>
  );
}