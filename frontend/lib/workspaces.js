const ROLE_WORKSPACE_PATHS = {
  USER: "/user",
  ANALYST: "/analyst",
  MANAGER: "/manager",
  ORGANIZATION_OWNER: "/owner",
  SUPER_ADMIN: "/super-admin",
};

export const AUTH_ACCESS_COOKIE_NAME = "vulntrack_access_token";
export const AUTH_REFRESH_COOKIE_NAME = "vulntrack_refresh_token";

export const EXISTING_ROUTE_LINKS = [
  {
    id: "scan-upload",
    group: "File Scan",
    href: "/scan-upload",
    description: "Upload a file or scan a URL.",
    label: "Scan",
  },
  {
    id: "malware-intelligence",
    group: "Malware Analysis",
    href: "/malware-intelligence",
    description: "Review malware dashboard and reputation trends.",
    label: "Malware",
  },
  {
    id: "threat-intelligence",
    group: "Threat Intelligence",
    href: "/threat-intelligence",
    description: "Explore CVE correlation and threat feeds.",
    label: "Threat",
  },
  {
    id: "ai-dashboard",
    group: "AI Investigation",
    href: "/ai-dashboard",
    description: "Open the AI dashboard and copilot tools.",
    label: "AI",
  },
  {
    id: "dashboard",
    group: "Existing dashboards",
    href: "/dashboard",
    description: "Return to the scan overview dashboard.",
    label: "Dashboard",
  },
  {
    id: "history",
    group: "Existing routes",
    href: "/history",
    description: "Open scan history and legacy routes.",
    label: "Routes",
  },
  {
    id: "organization",
    group: "Organization / Roles",
    href: "/organization",
    description: "Keep the tenant and role surfaces reachable.",
    label: "Admin",
  },
  {
    id: "roles",
    group: "Roles management",
    href: "/roles",
    description: "Review and assign role-based access.",
    label: "Roles",
  },
];

export const REGISTRATION_ROLE_OPTIONS = [
  {
    code: "USER",
    label: "User",
    description: "Standard workspace access for day-to-day security tasks.",
    fields: [
      {
        name: "organization_name",
        label: "Organization",
        placeholder: "Northwind Security",
        helper: "Join an existing workspace or create a starter one.",
        required: true,
      },
    ],
  },
  {
    code: "ANALYST",
    label: "Security Analyst",
    description: "Investigation-oriented access for triage and review.",
    fields: [
      {
        name: "organization_name",
        label: "Organization",
        placeholder: "Northwind Security",
        helper: "Pick the tenant this analyst belongs to.",
        required: true,
      },
    ],
  },
  {
    code: "MANAGER",
    label: "Manager",
    description: "Oversight access for team coordination and reporting.",
    fields: [
      {
        name: "department",
        label: "Department",
        placeholder: "Security Operations",
        helper: "Surface the team or function this manager owns.",
        required: true,
      },
      {
        name: "organization_name",
        label: "Organization",
        placeholder: "Northwind Security",
        helper: "Select or create the organization this manager oversees.",
        required: true,
      },
    ],
  },
  {
    code: "SUPER_ADMIN",
    label: "Super Admin",
    description: "Platform-wide governance access for bootstrapping and cross-tenant oversight.",
    fields: [
      {
        name: "organization_name",
        label: "Platform Organization",
        placeholder: "Platform Administration",
        helper: "Create the platform control tenant used by the first super admin account.",
        required: true,
      },
    ],
  },
  {
    code: "ORGANIZATION_OWNER",
    label: "Organization Owner",
    description: "Full tenant administration with organization setup.",
    fields: [
      {
        name: "organization_name",
        label: "Organization Name",
        placeholder: "Northwind Security",
        helper: "This becomes the tenant name in the workspace.",
        required: true,
      },
      {
        name: "industry",
        label: "Industry",
        placeholder: "Healthcare",
        helper: "Helps tailor the workspace metadata to your business.",
        required: true,
      },
      {
        name: "company_size",
        label: "Company Size",
        placeholder: "51-200 employees",
        helper: "Used to shape the owner onboarding context.",
        required: true,
      },
    ],
  },
];

export const WORKSPACE_CONFIGS = {
  USER: {
    code: "USER",
    path: "/user",
    title: "Personal Security Workspace",
    eyebrow: "User Workspace",
    description:
      "A private workspace for reviewing scans, tracking personal assignments, and keeping account activity in one place.",
    accentClass: "from-sky-500/25 via-cyan-400/10 to-transparent",
    badgeClass: "border-sky-400/20 bg-sky-500/10 text-sky-100",
    sidebar: [
      { label: "Overview", href: "#overview" },
      { label: "Personal Modules", href: "#modules" },
      { label: "Tools", href: "#construction" },
      { label: "Session", href: "#session" },
    ],
    stats: [
      { label: "Open items", value: "08", helper: "Tasks waiting on your review" },
      { label: "Recent scans", value: "24", helper: "Files and URLs in scope" },
      { label: "Access mode", value: "Protected", helper: "JWT-backed workspace access" },
    ],
    modules: [
      {
        title: "Personal risk feed",
        description: "See the latest scan outcomes, alerts, and follow-up items tied to your account.",
        state: "live",
      },
      {
        title: "Automated follow-up",
        description: "Scheduled re-scans, reminders, and due dates are now managed from this workspace.",
        state: "live",
      },
      {
        title: "Shared inbox",
        description: "Review comments, escalations, and handoffs from a single inbox surface.",
        state: "live",
      },
    ],
    construction: [
      {
        title: "Evidence export",
        description: "Export scan summaries, case notes, and evidence bundles directly from the user view.",
        highlights: ["CSV export", "PDF case packet", "Shareable evidence bundle"],
      },
      {
        title: "Personal workflows",
        description: "Track recurring actions and task templates for individual users and shared handoffs.",
        highlights: ["Task templates", "Recurring actions", "Follow-up reminders"],
      },
    ],
  },
  ANALYST: {
    code: "ANALYST",
    path: "/analyst",
    title: "Analyst Investigation Workspace",
    eyebrow: "Security Analyst",
    description:
      "Built for triage, investigation, and escalation with a clear line of sight to telemetry and threat context.",
    accentClass: "from-violet-500/25 via-fuchsia-400/10 to-transparent",
    badgeClass: "border-violet-400/20 bg-violet-500/10 text-violet-100",
    sidebar: [
      { label: "Overview", href: "#overview" },
      { label: "Investigations", href: "#modules" },
      { label: "Tools", href: "#construction" },
      { label: "Case Notes", href: "#session" },
    ],
    stats: [
      { label: "Queue depth", value: "12", helper: "Alerts ready for triage" },
      { label: "Correlations", value: "41", helper: "Linked indicators and incidents" },
      { label: "Access mode", value: "Investigative", helper: "JWT-backed workspace access" },
    ],
    modules: [
      {
        title: "Alert triage console",
        description: "High signal findings and suspicious activity will land here for review.",
        state: "live",
      },
      {
        title: "Threat correlation graph",
        description: "Trace indicators across alerts, endpoints, and malware context in the active graph view.",
        state: "live",
      },
      {
        title: "Case handoff board",
        description: "Move escalations, evidence, and analyst notes through the review workflow.",
        state: "live",
      },
    ],
    construction: [
      {
        title: "Timeline replay",
        description: "Replay key events in order and jump directly to correlated indicators.",
        highlights: ["Event timeline", "Indicator pivots", "Case annotations"],
      },
      {
        title: "Detection tuning",
        description: "Review tuning rules, suppression controls, and analyst feedback in one place.",
        highlights: ["Suppression rules", "Rule refinement", "Feedback loop"],
      },
    ],
  },
  MANAGER: {
    code: "MANAGER",
    path: "/manager",
    title: "Manager Operations Workspace",
    eyebrow: "Manager",
    description:
      "Designed for operational oversight, team coordination, and status reporting without exposing admin-only controls.",
    accentClass: "from-emerald-500/25 via-teal-400/10 to-transparent",
    badgeClass: "border-emerald-400/20 bg-emerald-500/10 text-emerald-100",
    sidebar: [
      { label: "Overview", href: "#overview" },
      { label: "Team Health", href: "#modules" },
      { label: "Tools", href: "#construction" },
      { label: "Reporting", href: "#session" },
    ],
    stats: [
      { label: "Active team", value: "18", helper: "Members in the current tenant" },
      { label: "Approvals", value: "05", helper: "Items awaiting manager review" },
      { label: "Access mode", value: "Operational", helper: "JWT-backed workspace access" },
    ],
    modules: [
      {
        title: "Team posture board",
        description: "A quick view of workload, escalations, and actions in progress.",
        state: "live",
      },
      {
        title: "Approval queue",
        description: "Review approvals, pending decisions, and priority actions from the team queue.",
        state: "live",
      },
      {
        title: "Execution calendar",
        description: "Plan recurring reviews, follow-ups, and operational checkpoints.",
        state: "live",
      },
    ],
    construction: [
      {
        title: "Department dashboards",
        description: "Track departmental status, workload, and ownership from a single view.",
        highlights: ["Department queue", "Ownership map", "SLA snapshot"],
      },
      {
        title: "SLA tracking",
        description: "Monitor response timers, escalation reminders, and service-level trends.",
        highlights: ["Response timers", "Escalation reminders", "Review cadence"],
      },
    ],
  },
  ORGANIZATION_OWNER: {
    code: "ORGANIZATION_OWNER",
    path: "/owner",
    title: "Owner Governance Workspace",
    eyebrow: "Organization Owner",
    description:
      "Tenant-wide administration with user oversight, organization controls, and access management in one place.",
    accentClass: "from-amber-500/25 via-orange-400/10 to-transparent",
    badgeClass: "border-amber-400/20 bg-amber-500/10 text-amber-100",
    sidebar: [
      { label: "Overview", href: "#overview" },
      { label: "Governance", href: "#modules" },
      { label: "Tools", href: "#construction" },
      { label: "Tenant Settings", href: "#session" },
    ],
    stats: [
      { label: "Tenants", value: "01", helper: "Organization scope for this owner" },
      { label: "Users", value: "26", helper: "Accounts managed inside the tenant" },
      { label: "Access mode", value: "Tenant admin", helper: "JWT-backed workspace access" },
    ],
    modules: [
      {
        title: "User governance",
        description: "Account oversight and role review are available at the tenant layer.",
        state: "live",
      },
      {
        title: "Policy center",
        description: "Edit tenant policy rules and review the guardrails that are currently enforced.",
        state: "live",
      },
      {
        title: "Billing and plans",
        description: "Review organization entitlement, lifecycle, and plan context.",
        state: "live",
      },
    ],
    construction: [
      {
        title: "Security baselines",
        description: "Review tenant hardening profiles and baseline configuration templates.",
        highlights: ["Baseline profiles", "Hardening checklist", "Drift review"],
      },
      {
        title: "Executive reports",
        description: "Generate board-ready summaries and exportable posture reports.",
        highlights: ["Risk posture", "Executive summary", "Export packet"],
      },
    ],
  },
  SUPER_ADMIN: {
    code: "SUPER_ADMIN",
    path: "/super-admin",
    title: "Super Admin Control Room",
    eyebrow: "Super Admin",
    description:
      "Platform-wide governance across tenants, roles, and system health with the broadest access boundary.",
    accentClass: "from-rose-500/25 via-pink-400/10 to-transparent",
    badgeClass: "border-rose-400/20 bg-rose-500/10 text-rose-100",
    sidebar: [
      { label: "Overview", href: "#overview" },
      { label: "Platform", href: "#modules" },
      { label: "Tools", href: "#construction" },
      { label: "Audit", href: "#session" },
    ],
    stats: [
      { label: "Tenants", value: "12", helper: "Organizations onboarded on the platform" },
      { label: "Role sets", value: "05", helper: "Defined SaaS access levels" },
      { label: "Access mode", value: "Global", helper: "JWT-backed workspace access" },
    ],
    modules: [
      {
        title: "Tenant control plane",
        description: "Platform operators can inspect tenant health and high-level activity.",
        state: "live",
      },
      {
        title: "Role orchestration",
        description: "Shape platform access boundaries, role composition, and permission tiers.",
        state: "live",
      },
      {
        title: "Audit stream",
        description: "Inspect platform activity, role changes, and tenant-level actions in one stream.",
        state: "live",
      },
    ],
    construction: [
      {
        title: "Feature flag console",
        description: "Toggle platform features, beta modules, and rollout targets from one console.",
        highlights: ["Feature toggles", "Rollout targets", "Audit trail"],
      },
      {
        title: "Cross-tenant analytics",
        description: "Compare organizations, role usage, and platform health across tenants.",
        highlights: ["Tenant comparisons", "Role distribution", "Platform health"],
      },
    ],
  },
};

export function normalizeRoleCode(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, "_");
}

export function getWorkspacePathForRole(roleCode) {
  return ROLE_WORKSPACE_PATHS[normalizeRoleCode(roleCode)] || "/login";
}

export function getRoleFromWorkspacePath(pathname) {
  const normalizedPath = String(pathname || "").split("?")[0];
  const match = Object.entries(ROLE_WORKSPACE_PATHS).find(([, path]) => path === normalizedPath);
  return match ? match[0] : null;
}

export function getWorkspaceConfig(roleCode) {
  return WORKSPACE_CONFIGS[normalizeRoleCode(roleCode)] || WORKSPACE_CONFIGS.USER;
}

export function getRegistrationRoleConfig(roleCode) {
  const normalizedRoleCode = normalizeRoleCode(roleCode) || "USER";
  return (
    REGISTRATION_ROLE_OPTIONS.find((option) => option.code === normalizedRoleCode) ||
    REGISTRATION_ROLE_OPTIONS[0]
  );
}

function decodeBase64Url(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  if (typeof atob === "function") {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(padded, "base64");
  }

  throw new Error("Base64 decoder is unavailable.");
}

export function readJwtPayload(token) {
  if (!token || typeof token !== "string") {
    return null;
  }

  try {
    const parts = token.split(".");
    if (parts.length < 2) {
      return null;
    }

    const payloadBytes = decodeBase64Url(parts[1]);
    const payloadText = new TextDecoder().decode(payloadBytes);
    return JSON.parse(payloadText);
  } catch {
    return null;
  }
}
