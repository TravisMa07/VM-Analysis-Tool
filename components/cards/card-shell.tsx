import type { ReactNode } from "react";

type CardShellProps = {
  title: string;
  subtitle?: string;
  fullWidth?: boolean;
  children: ReactNode;
};

export function CardShell({
  title,
  subtitle,
  fullWidth = false,
  children
}: CardShellProps) {
  return (
    <section className={`card${fullWidth ? " full-width" : ""}`}>
      <h2>{title}</h2>
      {subtitle ? <p>{subtitle}</p> : null}
      {children}
    </section>
  );
}
