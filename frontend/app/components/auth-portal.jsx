"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import { ArrowRight, Lock, ShieldCheck, Sparkles, UserPlus } from "lucide-react";

import { primaryButtonClassName, secondaryButtonClassName } from "@/app/components/ui";
import { loginUser, registerUser } from "@/lib/api";
import {
  getRegistrationRoleConfig,
  getWorkspacePathForRole,
  REGISTRATION_ROLE_OPTIONS,
} from "@/lib/workspaces";
import { restoreSession, saveUser } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

const initialForm = {
  email: "",
  password: "",
  role_code: "USER",
  organization_name: "",
  department: "",
  industry: "",
  company_size: "",
};

const loginHighlights = [
  {
    title: "Long-lived session",
    description: "Refresh cookies keep you signed in between visits without re-entering credentials every time.",
  },
  {
    title: "Role-aware routing",
    description: "Users land in the correct workspace immediately after login.",
  },
  {
    title: "Glassmorphism UI",
    description: "Blue and purple neon surfaces give the portal a cleaner security-console feel.",
  },
];

const registerHighlights = [
  {
    title: "Dynamic registration",
    description: "Fields change based on the selected role so the form stays focused.",
  },
  {
    title: "Workspace metadata",
    description: "Organization owner onboarding captures tenant context up front.",
  },
  {
    title: "Fast handoff",
    description: "Successful registration routes the user straight to the sign-in screen.",
  },
];

export default function AuthPortal({ mode = "login" }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const mounted = useMounted();
  const [form, setForm] = useState(initialForm);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const selectedRole = useMemo(
    () => getRegistrationRoleConfig(form.role_code),
    [form.role_code],
  );

  useEffect(() => {
    if (!mounted) {
      return;
    }

    let active = true;

    async function hydrateSession() {
      const sessionUser = await restoreSession();
      if (!active) {
        return;
      }

      if (sessionUser) {
        router.replace(getWorkspacePathForRole(sessionUser?.role?.code));
      }
    }

    hydrateSession();

    return () => {
      active = false;
    };
  }, [mounted, router]);

  useEffect(() => {
    if (mode !== "login") {
      return;
    }

    const registered = searchParams.get("registered");
    if (registered === "1") {
      setNotice("Registration complete. Sign in with your new credentials.");
    }
  }, [mode, searchParams]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading secure portal...</main>;
  }

  const copy = mode === "login" ? loginHighlights : registerHighlights;
  const title =
    mode === "login" ? "Secure login" : "Create a role-aware SaaS account";
  const subtitle =
    mode === "login"
      ? "Sign in with email and password only. Sessions persist through a long-lived refresh token, and the backend routes you to the correct workspace."
      : "Choose a role, complete the dynamic fields, and provision the organization metadata needed for your workspace.";

  function updateField(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setNotice("");

    try {
      if (mode === "login") {
        const response = await loginUser({
          email: form.email,
          password: form.password,
        });
        saveUser(response.user);
        router.replace(getWorkspacePathForRole(response.user?.role?.code));
        return;
      }

      const payload = {
        email: form.email,
        password: form.password,
        role_code: form.role_code,
      };

      for (const field of selectedRole.fields) {
        const rawValue = String(form[field.name] ?? "").trim();
        if (rawValue) {
          payload[field.name] = rawValue;
        }
      }

      const user = await registerUser(payload);
      setNotice(`Account created for ${user.email}. Redirecting to login...`);
      router.replace("/login?registered=1");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute -left-24 -top-28 -z-10 h-[420px] w-[420px] rounded-full bg-[radial-gradient(circle,rgba(99,102,241,0.28),transparent_70%)] blur-[70px]" />
      <div className="pointer-events-none absolute right-[-120px] top-16 -z-10 h-[380px] w-[380px] rounded-full bg-[radial-gradient(circle,rgba(168,85,247,0.24),transparent_70%)] blur-[70px]" />
      <div className="pointer-events-none absolute bottom-[-120px] left-[14%] -z-10 h-[360px] w-[360px] rounded-full bg-[radial-gradient(circle,rgba(59,130,246,0.18),transparent_70%)] blur-[72px]" />

      <div className="mx-auto grid min-h-screen w-[min(1280px,calc(100%-24px))] items-center gap-5 py-6 lg:grid-cols-[1.08fr_0.92fr] lg:py-10">
        <motion.section
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: "easeOut" }}
          className="relative overflow-hidden rounded-[30px] border border-white/10 bg-[linear-gradient(150deg,rgba(19,27,55,0.88),rgba(5,10,22,0.92))] p-7 shadow-[0_30px_100px_rgba(0,0,0,0.45)] backdrop-blur-[28px] lg:p-10"
        >
          <div className="pointer-events-none absolute inset-x-12 top-0 h-px bg-gradient-to-r from-transparent via-white/70 to-transparent" />
          <div className="pointer-events-none absolute right-[-40px] top-[-24px] h-52 w-52 rounded-full bg-[radial-gradient(circle,rgba(99,102,241,0.22),transparent_70%)] blur-[26px]" />

          <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
            <div className="flex flex-col justify-between gap-6">
              <div className="grid gap-4">
                <div className="inline-flex w-fit items-center gap-2 rounded-full border border-white/10 bg-white/6 px-4 py-2 text-[0.76rem] font-semibold uppercase tracking-[0.18em] text-[#d9e3ff]">
                  <ShieldCheck size={14} />
                  VulnTrack AI
                </div>
                <div>
                  <div className="text-[0.74rem] font-bold uppercase tracking-[0.22em] text-[#9fb4ff]">
                    {mode === "login" ? "Authentication Portal" : "Workspace Provisioning"}
                  </div>
                  <h1 className="mt-3 max-w-[12ch] text-[clamp(2.6rem,5vw,5.2rem)] font-semibold leading-[0.9] tracking-[-0.06em] text-white">
                    {title}
                  </h1>
                  <p className="mt-5 max-w-2xl text-base leading-8 text-[#aebde0]">{subtitle}</p>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                {copy.map((item, index) => (
                  <motion.article
                    key={`${item.title}-${index}`}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35, delay: 0.05 * index }}
                    className="rounded-[22px] border border-white/8 bg-white/5 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
                  >
                    <div className="flex items-center gap-2 text-[0.78rem] font-semibold uppercase tracking-[0.14em] text-[#c9d5ff]">
                      <Sparkles size={14} />
                      {index + 1}
                    </div>
                    <strong className="mt-3 block text-base font-semibold text-white">{item.title}</strong>
                    <p className="mt-2 text-sm leading-6 text-[#a8b6d8]">{item.description}</p>
                  </motion.article>
                ))}
              </div>
            </div>

            <div className="grid gap-4">
              <div className="rounded-[26px] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.03))] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                <div className="flex items-center gap-3">
                  <span className="grid h-12 w-12 place-items-center rounded-2xl bg-[linear-gradient(135deg,rgba(96,165,250,0.3),rgba(168,85,247,0.34))] text-white">
                    {mode === "login" ? <Lock size={20} /> : <UserPlus size={20} />}
                  </span>
                  <div>
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-[#9fb4ff]">
                      {mode === "login" ? "Session Access" : "Role Selection"}
                    </div>
                    <strong className="mt-1 block text-lg font-semibold text-white">
                      {mode === "login"
                        ? "Email and password only"
                        : selectedRole.label}
                    </strong>
                  </div>
                </div>

                <div className="mt-5 grid gap-3">
                  {mode === "login" ? (
                    <div className="rounded-[20px] border border-white/8 bg-white/5 p-4 text-sm leading-7 text-[#c8d3ef]">
                      Login does not ask for a role. The JWT session is decoded after authentication and the app
                      sends the user directly to the correct workspace. The refresh token keeps the session alive
                      for future visits.
                    </div>
                  ) : (
                    <div className="rounded-[20px] border border-white/8 bg-white/5 p-4 text-sm leading-7 text-[#c8d3ef]">
                      Select a role first. The registration fields below will change to match the workspace you are
                      provisioning. Super admin is available for the initial platform bootstrap.
                    </div>
                  )}

                  <div className="grid gap-2">
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-[#9fb4ff]">
                      Supported roles
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {REGISTRATION_ROLE_OPTIONS.map((role) => (
                        <span
                          key={role.code}
                          className={cx(
                            "rounded-full border px-3 py-1.5 text-[0.78rem] font-semibold uppercase tracking-[0.12em]",
                            form.role_code === role.code
                              ? "border-[rgba(144,191,255,0.35)] bg-[rgba(99,102,241,0.18)] text-white"
                              : "border-white/10 bg-white/5 text-[#c5d4f4]",
                          )}
                        >
                          {role.label}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="rounded-[26px] border border-white/10 bg-white/5 p-5">
                <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-[#9fb4ff]">
                  {mode === "login" ? "Status" : "Registration Notes"}
                </div>
                {notice ? (
                  <div className="mt-3 rounded-2xl border border-[rgba(96,165,250,0.24)] bg-[rgba(59,130,246,0.12)] px-4 py-3 text-sm leading-6 text-[#e5eeff]">
                    {notice}
                  </div>
                ) : (
                  <div className="mt-3 text-sm leading-7 text-[#a8b6d8]">
                    {mode === "login"
                      ? "When a valid session exists, the portal will skip this screen and open the correct workspace."
                      : "Managers provide a department, owners provide organization metadata, and analysts/users only need their organization link."}
                  </div>
                )}
              </div>
            </div>
          </div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.08, ease: "easeOut" }}
          className="relative overflow-hidden rounded-[30px] border border-white/10 bg-[linear-gradient(180deg,rgba(16,22,45,0.96),rgba(8,13,28,0.98))] p-6 shadow-[0_30px_100px_rgba(0,0,0,0.44)] backdrop-blur-[28px] lg:p-8"
        >
          <div className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-white/60 to-transparent" />
          <div className="mb-6">
            <div className="text-[0.72rem] font-bold uppercase tracking-[0.22em] text-[#9fb4ff]">
              {mode === "login" ? "Access Session" : "Provision Account"}
            </div>
            <h2 className="mt-2 text-[clamp(1.9rem,3vw,2.7rem)] font-semibold tracking-[-0.04em] text-white">
              {mode === "login" ? "Sign in" : "Register"}
            </h2>
            <p className="mt-3 max-w-[58ch] text-sm leading-7 text-[#a9b8da]">
              {mode === "login"
                ? "Use the email and password registered to your account. Workspace access is derived from the JWT session."
                : "Complete the role-specific fields below. The app will capture tenant metadata and route the new account back to login."}
            </p>
          </div>

          <form className="grid gap-4" onSubmit={handleSubmit}>
            {mode === "register" ? (
              <div className="grid gap-2">
                <label htmlFor="role_code" className="text-[0.78rem] font-bold uppercase tracking-[0.18em] text-[#cfd9ff]">
                  Role
                </label>
                <div className="grid gap-2 sm:grid-cols-2">
                  {REGISTRATION_ROLE_OPTIONS.map((role) => (
                    <button
                      key={role.code}
                      type="button"
                      className={cx(
                        "rounded-[22px] border p-4 text-left transition duration-200",
                        form.role_code === role.code
                          ? "border-[rgba(120,158,255,0.35)] bg-[linear-gradient(180deg,rgba(80,105,212,0.3),rgba(255,255,255,0.04))] shadow-[0_18px_40px_rgba(79,70,229,0.18)]"
                          : "border-white/8 bg-white/4 hover:border-[rgba(120,158,255,0.22)] hover:bg-white/6",
                      )}
                      onClick={() => updateField("role_code", role.code)}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <strong className="text-sm font-semibold text-white">{role.label}</strong>
                        <ArrowRight size={15} className="text-[#9fb4ff]" />
                      </div>
                      <p className="mt-2 text-sm leading-6 text-[#a9b8da]">{role.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="grid gap-2">
              <label htmlFor="email" className="text-[0.78rem] font-bold uppercase tracking-[0.18em] text-[#cfd9ff]">
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                autoComplete="email"
                placeholder="analyst@company.com"
                className="w-full rounded-2xl border border-white/10 bg-[rgba(7,11,22,0.72)] px-4 py-3.5 text-white outline-none transition duration-200 placeholder:text-slate-500 focus:border-[rgba(120,158,255,0.45)] focus:shadow-[0_0_0_4px_rgba(120,158,255,0.14)]"
                value={form.email}
                onChange={(event) => updateField("email", event.target.value)}
              />
            </div>

            <div className="grid gap-2">
              <label htmlFor="password" className="text-[0.78rem] font-bold uppercase tracking-[0.18em] text-[#cfd9ff]">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                placeholder={mode === "login" ? "Enter your password" : "Create a strong password"}
                className="w-full rounded-2xl border border-white/10 bg-[rgba(7,11,22,0.72)] px-4 py-3.5 text-white outline-none transition duration-200 placeholder:text-slate-500 focus:border-[rgba(120,158,255,0.45)] focus:shadow-[0_0_0_4px_rgba(120,158,255,0.14)]"
                value={form.password}
                onChange={(event) => updateField("password", event.target.value)}
              />
            </div>

            {mode === "register"
              ? selectedRole.fields.map((field) => (
                  <div key={field.name} className="grid gap-2">
                    <label
                      htmlFor={field.name}
                      className="text-[0.78rem] font-bold uppercase tracking-[0.18em] text-[#cfd9ff]"
                    >
                      {field.label}
                    </label>
                    <input
                      id={field.name}
                      name={field.name}
                      type="text"
                      required={Boolean(field.required)}
                      placeholder={field.placeholder}
                      className="w-full rounded-2xl border border-white/10 bg-[rgba(7,11,22,0.72)] px-4 py-3.5 text-white outline-none transition duration-200 placeholder:text-slate-500 focus:border-[rgba(120,158,255,0.45)] focus:shadow-[0_0_0_4px_rgba(120,158,255,0.14)]"
                      value={form[field.name]}
                      onChange={(event) => updateField(field.name, event.target.value)}
                    />
                    <p className="text-xs leading-6 text-[#91a5cb]">{field.helper}</p>
                  </div>
                ))
              : null}

            {error ? (
              <div className="rounded-2xl border border-[rgba(248,113,113,0.28)] bg-[rgba(248,113,113,0.12)] px-4 py-3 text-sm leading-7 text-[#ffe4e6]">
                {error}
              </div>
            ) : null}

            {notice && mode === "register" ? (
              <div className="rounded-2xl border border-[rgba(96,165,250,0.24)] bg-[rgba(59,130,246,0.12)] px-4 py-3 text-sm leading-7 text-[#e5eeff]">
                {notice}
              </div>
            ) : null}

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button className={primaryButtonClassName} type="submit" disabled={loading}>
                {loading ? "Working..." : mode === "login" ? "Enter workspace" : "Create account"}
              </button>
              <button
                className={secondaryButtonClassName}
                type="button"
                onClick={() => router.push(mode === "login" ? "/register" : "/login")}
              >
                {mode === "login" ? "Go to register" : "Back to login"}
              </button>
            </div>
          </form>
        </motion.section>
      </div>
    </main>
  );
}
