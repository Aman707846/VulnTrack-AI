"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState } from "react";
import {
  Building2,
  History,
  LayoutDashboard,
  LogOut,
  Radar,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UploadCloud,
} from "lucide-react";
import { motion } from "framer-motion";

import { logoutUser } from "@/lib/api";
import { primaryButtonClassName, secondaryButtonClassName } from "@/app/components/ui";
import { clearUser } from "@/lib/session";

const NAV_ITEMS = [
  {
    id: "nav-file-scan",
    href: "/scan-upload",
    label: "File Scan",
    icon: UploadCloud,
    match: (pathname) => pathname === "/scan-upload",
  },
  {
    id: "nav-dashboard",
    href: "/dashboard",
    label: "Dashboard",
    icon: LayoutDashboard,
    match: (pathname) => pathname === "/dashboard",
  },
  {
    id: "nav-history",
    href: "/history",
    label: "History",
    icon: History,
    match: (pathname) => pathname === "/history",
  },
  {
    id: "nav-organization",
    href: "/organization",
    label: "Organization",
    icon: Building2,
    match: (pathname) => pathname === "/organization",
  },
  {
    id: "nav-roles",
    href: "/roles",
    label: "Roles",
    icon: ShieldCheck,
    match: (pathname) => pathname === "/roles",
  },
  {
    id: "nav-malware-intelligence",
    href: "/malware-intelligence",
    label: "Malware Intel",
    icon: ShieldAlert,
    match: (pathname) => pathname === "/malware-intelligence",
  },
  {
    id: "nav-threat-intelligence",
    href: "/threat-intelligence",
    label: "Threat Intel",
    icon: Radar,
    match: (pathname) => pathname === "/threat-intelligence",
  },
  {
    id: "nav-ai-dashboard",
    href: "/ai-dashboard",
    label: "AI Intel",
    icon: Sparkles,
    match: (pathname) => pathname === "/ai-dashboard",
  },
];

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

export default function AppShell({ user, eyebrow, title, subtitle, status, actions, children }) {
  const pathname = usePathname();
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
      // Clear the local cache even if the backend session is already invalid.
    } finally {
      clearUser();
      router.push("/login");
      setLoggingOut(false);
    }
  }

  return (
    <div className="relative grid min-h-screen overflow-hidden lg:grid-cols-[290px_minmax(0,1fr)]">
      <motion.div
        className="pointer-events-none fixed -left-20 -top-28 -z-10 h-[420px] w-[420px] rounded-full bg-[radial-gradient(circle,rgba(115,240,207,0.22),transparent_70%)] blur-[48px]"
        animate={{ x: [0, 18, 0], y: [0, 12, 0] }}
        transition={{ duration: 16, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="pointer-events-none fixed -bottom-36 -right-28 -z-10 h-[520px] w-[520px] rounded-full bg-[radial-gradient(circle,rgba(121,168,255,0.18),transparent_68%)] blur-[56px]"
        animate={{ x: [0, -22, 0], y: [0, -10, 0] }}
        transition={{ duration: 18, repeat: Infinity, ease: "easeInOut" }}
      />

      <aside className="border-b border-vt-line bg-[linear-gradient(180deg,rgba(7,16,31,0.92),rgba(8,17,34,0.86))] p-6 backdrop-blur-[26px] lg:border-b-0 lg:border-r">
        <div className="flex flex-col gap-[18px]">
          <Link
            className="flex items-center gap-3 rounded-[20px] border border-white/6 bg-white/3 px-3 py-2"
            href="/dashboard"
          >
            <span className="grid h-12 w-12 place-items-center rounded-2xl bg-[linear-gradient(135deg,rgba(121,242,192,0.2),rgba(64,106,255,0.24))] text-vt-accent shadow-[inset_0_0_0_1px_rgba(121,242,192,0.18)]">
              <Shield size={20} strokeWidth={2.1} />
            </span>
            <span>
              <strong className="block text-base font-bold">VulnTrack AI</strong>
              <small className="mt-1 block text-[0.82rem] text-vt-muted">AI threat intelligence platform</small>
            </span>
          </Link>

          <nav className="grid gap-2.5">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = item.match(pathname);

              return (
                <Link
                  key={item.id}
                  href={item.href}
                  className={cx(
                    "flex items-center gap-3 rounded-[18px] border px-4 py-3 text-[#dce7ff] transition duration-200 hover:-translate-y-0.5",
                    active
                      ? "border-[rgba(121,242,192,0.14)] bg-[linear-gradient(135deg,rgba(121,242,192,0.14),rgba(64,106,255,0.12))]"
                      : "border-transparent hover:border-[rgba(121,242,192,0.14)] hover:bg-[linear-gradient(135deg,rgba(121,242,192,0.14),rgba(64,106,255,0.12))]",
                  )}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>
      </aside>

      <main className="px-4 py-6 sm:px-6 lg:px-[30px] lg:py-[30px]">
        <header className="mb-6 flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">{eyebrow}</div>
            <h1 className="mt-2 text-[clamp(2rem,3vw,3.4rem)] font-semibold leading-[0.98] tracking-[-0.04em]">
              {title}
            </h1>
            <p className="mt-4 max-w-[64ch] text-base leading-7 text-vt-muted">{subtitle}</p>
          </div>

          <div className="flex flex-wrap items-center gap-3 lg:justify-end">
            <Link className={primaryButtonClassName} href="/scan-upload">
              <UploadCloud size={16} />
              <span>File Scan</span>
            </Link>
            <div className="rounded-[18px] border border-vt-line bg-white/5 px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
              <div className="text-[0.68rem] font-bold uppercase tracking-[0.16em] text-vt-accent">User</div>
              <div className="mt-1 text-sm font-medium text-vt-text">{user?.email || "Loading user..."}</div>
            </div>
            <div className="rounded-[18px] border border-vt-line bg-white/5 px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
              <div className="text-[0.68rem] font-bold uppercase tracking-[0.16em] text-vt-accent">Role</div>
              <div className="mt-1 text-sm font-medium text-vt-text">
                {user?.role?.name || user?.role?.code || "Loading role..."}
              </div>
              {user?.role?.code ? <div className="mt-1 text-[0.75rem] text-vt-muted">{user.role.code}</div> : null}
            </div>
            <div className="rounded-[18px] border border-vt-line bg-white/5 px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
              <div className="text-[0.68rem] font-bold uppercase tracking-[0.16em] text-vt-accent">
                Organization
              </div>
              <div className="mt-1 text-sm font-medium text-vt-text">
                {user?.organization?.name || "Loading organization..."}
              </div>
              {user?.organization?.slug ? (
                <div className="mt-1 text-[0.75rem] text-vt-muted">{user.organization.slug}</div>
              ) : null}
            </div>
            {status ? (
              <div className="rounded-full bg-[rgba(121,242,192,0.08)] px-4 py-2.5 text-[0.88rem] text-[#dff8ed] shadow-[inset_0_0_0_1px_rgba(121,242,192,0.18)]">
                {status}
              </div>
            ) : null}
            {actions}
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
        </header>

        <div className="grid gap-[18px]">{children}</div>
      </main>
    </div>
  );
}
