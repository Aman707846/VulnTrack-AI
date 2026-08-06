"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { motion } from "framer-motion";
import { ChevronRight, LogOut, Shield } from "lucide-react";

import { logoutUser } from "@/lib/api";
import { secondaryButtonClassName } from "@/app/components/ui";
import { clearUser } from "@/lib/session";

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

export default function WorkspaceShell({ user, config, children }) {
  const router = useRouter();
  const [loggingOut, setLoggingOut] = useState(false);

  async function handleLogout() {
    if (loggingOut) {
      return;
    }

    setLoggingOut(true);
    try {
      await logoutUser();
    } catch {
      // Local cleanup still happens if the backend session was already revoked.
    } finally {
      clearUser();
      router.replace("/login");
      setLoggingOut(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[420px] bg-[radial-gradient(circle_at_top,rgba(96,165,250,0.18),transparent_48%),radial-gradient(circle_at_80%_20%,rgba(168,85,247,0.15),transparent_42%)]" />
      <div className={cx("pointer-events-none absolute inset-x-0 top-0 -z-20 h-[420px] bg-gradient-to-b", config.accentClass)} />

      <div className="mx-auto grid min-h-screen w-[min(1600px,100%)] gap-4 p-4 lg:grid-cols-[300px_minmax(0,1fr)] lg:p-6">
        <motion.aside
          initial={{ opacity: 0, x: -18 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
          className="flex flex-col gap-5 rounded-[28px] border border-white/10 bg-[linear-gradient(180deg,rgba(14,20,40,0.92),rgba(7,10,22,0.94))] p-5 shadow-[0_28px_90px_rgba(0,0,0,0.35)] backdrop-blur-[26px] lg:sticky lg:top-6 lg:h-[calc(100vh-3rem)] lg:overflow-y-auto"
        >
          <Link
            href={config.path}
            className="flex items-center gap-3 rounded-[22px] border border-white/8 bg-white/5 px-4 py-3"
          >
            <span
              className={cx(
                "grid h-12 w-12 place-items-center rounded-2xl border text-white shadow-[0_14px_35px_rgba(0,0,0,0.25)]",
                config.badgeClass,
              )}
            >
              <Shield size={20} strokeWidth={2.1} />
            </span>
            <span>
              <strong className="block text-base font-semibold text-white">VulnTrack AI</strong>
              <small className="mt-1 block text-[0.82rem] text-[#98a9ce]">{config.title}</small>
            </span>
          </Link>

          <div className="grid gap-3 rounded-[22px] border border-white/8 bg-white/5 p-4">
            <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-[#9fb4ff]">
              Session
            </div>
            <div className="grid gap-2 text-sm leading-6 text-[#d9e3ff]">
              <div>
                <span className="text-[#95a6c9]">User:</span> {user?.email || "Loading"}
              </div>
              <div>
                <span className="text-[#95a6c9]">Role:</span> {user?.role?.name || user?.role?.code || "Unknown"}
              </div>
              <div>
                <span className="text-[#95a6c9]">Organization:</span> {user?.organization?.name || "Unknown"}
              </div>
              {user?.department ? (
                <div>
                  <span className="text-[#95a6c9]">Department:</span> {user.department}
                </div>
              ) : null}
            </div>
          </div>

          <nav className="grid gap-2">
            {config.sidebar.map((item) => (
              <Link
                key={`${config.path}-${item.href}`}
                href={`${config.path}${item.href}`}
                className="flex items-center justify-between rounded-[18px] border border-white/8 bg-white/4 px-4 py-3 text-[#dbe6ff] transition duration-200 hover:-translate-y-0.5 hover:border-[rgba(128,156,255,0.24)] hover:bg-white/6"
              >
                <span>{item.label}</span>
                <ChevronRight size={15} className="text-[#8ea3d6]" />
              </Link>
            ))}
          </nav>

          <div className="mt-auto grid gap-3">
            <div className="rounded-[22px] border border-white/8 bg-white/5 p-4 text-sm leading-7 text-[#c8d3ef]">
              Role-specific dashboards stay compact so the live tools remain easy to reach from the sidebar.
            </div>
            <button
              type="button"
              className={secondaryButtonClassName}
              onClick={handleLogout}
              disabled={loggingOut}
            >
              <LogOut size={16} />
              <span>{loggingOut ? "Signing out..." : "Logout"}</span>
            </button>
          </div>
        </motion.aside>

        <main className="min-w-0 pb-4 lg:py-0">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
            className="rounded-[30px] border border-white/10 bg-[linear-gradient(180deg,rgba(14,20,40,0.84),rgba(8,12,24,0.9))] p-5 shadow-[0_28px_90px_rgba(0,0,0,0.38)] backdrop-blur-[26px] lg:p-8"
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  );
}
