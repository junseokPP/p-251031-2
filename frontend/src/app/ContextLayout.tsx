"use client";

import ClientLayout from "@/app/ClientLayout";
import { AuthProvider } from "@/global/auth/hooks/useAuth";

export default function ContextLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthProvider>
      <ClientLayout>{children}</ClientLayout>
    </AuthProvider>
  );
}
