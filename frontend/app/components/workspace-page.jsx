"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { AlertTriangle, ArrowRight, Building2, FileUp, ShieldCheck, Sparkles, Users } from "lucide-react";

import WorkspaceShell from "@/app/components/workspace-shell";
import { MetricCard, Panel, RiskBadge, SectionHeading } from "@/app/components/ui";
import { EXISTING_ROUTE_LINKS, getWorkspaceConfig, getWorkspacePathForRole, normalizeRoleCode } from "@/lib/workspaces";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

function toneForRole(code) {
  switch (normalizeRoleCode(code)) {
    case "SUPER_ADMIN":
      return "danger";
    case "ORGANIZATION_OWNER":
      return "warning";
    case "MANAGER":
      return "accent";
    case "ANALYST":
      return "safe";
    default:
      return "neutral";
  }
}

function stateTone(state) {
  return state === "construction" ? "warning" : "safe";
}

export default function WorkspacePage({ roleCode }) {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);

  const config = useMemo(() => getWorkspaceConfig(roleCode), [roleCode]);

  useEffect(() => {
    let active = true;

    async function hydrateSession() {
      const sessionUser = await restoreSession();
      if (!active) {
        return;
      }

      if (!sessionUser) {
        router.replace("/login");
        return;
      }

      const userWorkspacePath = getWorkspacePathForRole(sessionUser?.role?.code);
      if (userWorkspacePath !== config.path) {
        router.replace(userWorkspacePath);
        return;
      }

      setUser(sessionUser);
    }

    hydrateSession();

    return () => {
      active = false;
    };
  }, [config.path, router]);

  if (!mounted || !user) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading workspace...</main>;
  }

  return (
    <WorkspaceShell user={user} config={config}>
      <div className="grid gap-6">
        <section id="overview" className="grid gap-5">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="text-[0.72rem] font-bold uppercase tracking-[0.2em] text-[#9fb4ff]">
                {config.eyebrow}
              </div>
              <h1 className="mt-2 text-[clamp(2rem,4vw,3.6rem)] font-semibold leading-[0.95] tracking-[-0.05em] text-white">
                {config.title}
              </h1>
              <p className="mt-4 max-w-3xl text-base leading-8 text-[#a8b6d8]">{config.description}</p>
            </div>

            <div className="flex flex-wrap gap-2">
              <RiskBadge label={normalizeRoleCode(user?.role?.code) || "UNKNOWN"} tone={toneForRole(user?.role?.code)} />
              <span className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-[#dbe6ff]">
                {user?.organization?.name || "Unknown organization"}
              </span>
              {user?.department ? (
                <span className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-[#dbe6ff]">
                  {user.department}
                </span>
              ) : null}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {config.stats.map((item, index) => (
              <motion.div
                key={`${item.label}-${index}`}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.04 * index }}
              >
                <MetricCard label={item.label} value={item.value} helper={item.helper} tone={index === 0 ? "accent" : index === 1 ? "safe" : "default"} />
              </motion.div>
            ))}
          </div>
        </section>

        <section id="actions">
          <Panel>
            <SectionHeading
              eyebrow="Primary actions"
              title="Scan and module entry points"
              description="The legacy scan and intelligence routes still exist. They are surfaced here so the new workspaces do not hide active product areas."
            />

            <div className="grid gap-3 lg:grid-cols-[1.15fr_0.85fr]">
              <Link
                href="/scan-upload"
                className="group relative overflow-hidden rounded-[28px] border border-[rgba(115,240,207,0.22)] bg-[linear-gradient(180deg,rgba(115,240,207,0.14),rgba(255,255,255,0.04))] p-5 transition duration-200 hover:-translate-y-0.5 hover:border-[rgba(115,240,207,0.34)]"
              >
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(115,240,207,0.18),transparent_34%),radial-gradient(circle_at_bottom_left,rgba(121,168,255,0.12),transparent_40%)]" />
                <div className="relative flex items-start justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <span className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl bg-[rgba(115,240,207,0.14)] text-[#dcfff4]">
                      <FileUp size={22} />
                    </span>
                    <div>
                      <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
                        File Scan
                      </div>
                      <strong className="mt-2 block text-xl font-semibold text-white">Open scanner</strong>
                      <p className="mt-2 max-w-[46ch] text-sm leading-7 text-[#bdd0f1]">
                        Upload files or scan URLs from the original security workflow.
                      </p>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white">
                    Scan now <ArrowRight size={15} />
                  </span>
                </div>
              </Link>

              <div className="grid gap-2 rounded-[28px] border border-white/8 bg-white/4 p-4">
                <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-[#9fb4ff]">
                  Existing routes
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {EXISTING_ROUTE_LINKS.map((item) => (
                    <Link
                      key={item.id}
                      href={item.href}
                      className="rounded-[18px] border border-white/8 bg-[rgba(6,10,22,0.62)] px-4 py-3 transition duration-200 hover:-translate-y-0.5 hover:border-[rgba(120,158,255,0.24)] hover:bg-[rgba(12,18,34,0.8)]"
                    >
                      <div className="text-[0.7rem] font-bold uppercase tracking-[0.16em] text-[#9fb4ff]">
                        {item.group}
                      </div>
                      <strong className="mt-1 block text-sm font-semibold text-white">{item.label}</strong>
                      <p className="mt-1 text-xs leading-5 text-[#96a8cb]">{item.description}</p>
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </Panel>
        </section>

        <section id="modules">
          <Panel>
            <SectionHeading
              eyebrow="Workspace modules"
              title="Role dashboard"
              description="Each workspace gets its own layout, with live tools surfaced where the role needs them."
              aside={user?.email}
            />

            <div className="grid gap-3 xl:grid-cols-3">
              {config.modules.map((module, index) => (
                <motion.article
                  key={`${module.title}-${index}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, delay: 0.04 * index }}
                  className="rounded-[24px] border border-white/8 bg-white/4 p-5"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                    <span className="grid h-11 w-11 place-items-center rounded-2xl bg-[linear-gradient(135deg,rgba(96,165,250,0.24),rgba(168,85,247,0.22))] text-white">
                      {module.state === "construction" ? <AlertTriangle size={18} /> : <ShieldCheck size={18} />}
                    </span>
                    <div>
                      <strong className="block text-base font-semibold text-white">{module.title}</strong>
                      <p className="mt-1 text-sm leading-6 text-[#a8b6d8]">{module.description}</p>
                    </div>
                  </div>
                  <RiskBadge
                    label={module.state === "construction" ? "Building" : "Ready"}
                    tone={stateTone(module.state)}
                  />
                </div>

                <div className="mt-4 rounded-[20px] border border-white/8 bg-[rgba(4,8,18,0.65)] p-4 text-sm leading-7 text-[#cdd8f4]">
                  {module.state === "construction" ? (
                    <div className="grid gap-2">
                      <strong className="text-white">In rollout</strong>
                      <p className="text-[#9fb0d0]">
                        The workflow is now available in the role dashboard and can be expanded with backend-driven
                        actions later.
                      </p>
                    </div>
                  ) : (
                    <div className="grid gap-2">
                      <strong className="text-white">Available now</strong>
                      <p className="text-[#9fb0d0]">
                        This tool is active for the current role and contributes to the live workspace experience.
                      </p>
                    </div>
                  )}
                </div>
              </motion.article>
              ))}
            </div>
          </Panel>
        </section>

        <section id="construction">
          <Panel>
            <SectionHeading
              eyebrow="Role toolkit"
              title="Built tools"
              description="These sections collect the role-specific actions that are now part of the workspace instead of future placeholders."
            />

            <div className="grid gap-3 md:grid-cols-2">
              {config.construction.map((item, index) => (
                <motion.article
                  key={`${item.title}-${index}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, delay: 0.04 * index }}
                  className="rounded-[24px] border border-[rgba(255,185,90,0.18)] bg-[linear-gradient(180deg,rgba(255,185,90,0.12),rgba(255,255,255,0.03))] p-5"
                >
                  <div className="flex items-center gap-3">
                    <span className="grid h-11 w-11 place-items-center rounded-2xl border border-[rgba(255,185,90,0.22)] bg-[rgba(255,185,90,0.12)] text-[#ffe4bd]">
                      <Sparkles size={18} />
                    </span>
                    <div>
                      <strong className="block text-base font-semibold text-white">{item.title}</strong>
                      <p className="mt-1 text-sm leading-6 text-[#d8e0f4]">{item.description}</p>
                    </div>
                  </div>
                  {Array.isArray(item.highlights) && item.highlights.length ? (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {item.highlights.map((highlight) => (
                        <span
                          key={highlight}
                          className="rounded-full border border-[rgba(255,185,90,0.18)] bg-[rgba(3,7,16,0.5)] px-3 py-1.5 text-[0.74rem] font-semibold uppercase tracking-[0.12em] text-[#ffe4bd]"
                        >
                          {highlight}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </motion.article>
              ))}
            </div>
          </Panel>
        </section>

        <section id="session">
          <Panel>
            <SectionHeading
              eyebrow="Session details"
              title="Authenticated workspace"
              description="The workspace is driven by the JWT-backed session. Role and organization are read from the stored account."
            />

            <div className="grid gap-3 xl:grid-cols-[1.1fr_0.9fr]">
              <div className="rounded-[24px] border border-white/8 bg-white/4 p-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-[20px] border border-white/8 bg-[rgba(6,10,22,0.72)] p-4">
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-[#9fb4ff]">Email</div>
                    <div className="mt-2 text-sm text-white">{user.email}</div>
                  </div>
                  <div className="rounded-[20px] border border-white/8 bg-[rgba(6,10,22,0.72)] p-4">
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-[#9fb4ff]">Role</div>
                    <div className="mt-2 text-sm text-white">{user.role?.name || user.role?.code}</div>
                  </div>
                  <div className="rounded-[20px] border border-white/8 bg-[rgba(6,10,22,0.72)] p-4">
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-[#9fb4ff]">
                      Organization
                    </div>
                    <div className="mt-2 flex items-center gap-2 text-sm text-white">
                      <Building2 size={16} className="text-[#9fb4ff]" />
                      <span>{user.organization?.name || "Unknown organization"}</span>
                    </div>
                  </div>
                  <div className="rounded-[20px] border border-white/8 bg-[rgba(6,10,22,0.72)] p-4">
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-[#9fb4ff]">
                      Workspace path
                    </div>
                    <div className="mt-2 text-sm text-white">{config.path}</div>
                  </div>
                </div>
              </div>

              <div className="rounded-[24px] border border-white/8 bg-[linear-gradient(180deg,rgba(96,165,250,0.1),rgba(168,85,247,0.08))] p-5">
                <div className="flex items-center gap-3">
                  <span className="grid h-11 w-11 place-items-center rounded-2xl bg-[rgba(96,165,250,0.14)] text-[#dbe6ff]">
                    <Users size={18} />
                  </span>
                  <div>
                    <strong className="block text-base font-semibold text-white">Placeholder modules</strong>
                    <p className="mt-1 text-sm leading-6 text-[#b6c4e3]">
                      Any unfinished area is intentionally marked as under construction until the feature lands.
                    </p>
                  </div>
                </div>

                <div className="mt-4 rounded-[20px] border border-white/8 bg-[rgba(6,10,22,0.7)] p-4 text-sm leading-7 text-[#cdd8f4]">
                  {config.code === "SUPER_ADMIN"
                    ? "Super admins can expand the platform across organizations and inspect the live cross-tenant tools from here."
                    : "This workspace keeps the tenant and role context visible while the live tools stay one click away."}
                </div>
              </div>
            </div>
          </Panel>
        </section>
      </div>
    </WorkspaceShell>
  );
}
