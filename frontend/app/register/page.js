import { Suspense } from "react";

import AuthPortal from "@/app/components/auth-portal";

export default function RegisterPage() {
  return (
    <Suspense fallback={<main className="grid min-h-screen place-items-center text-vt-muted">Loading secure portal...</main>}>
      <AuthPortal mode="register" />
    </Suspense>
  );
}
