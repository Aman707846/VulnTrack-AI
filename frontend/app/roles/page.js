"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { RefreshCw, Users } from "lucide-react";

import AppShell from "@/app/components/app-shell";
import {
  EmptyState,
  MetricCard,
  Panel,
  RiskBadge,
  SectionHeading,
  primaryButtonClassName,
  secondaryButtonClassName,
} from "@/app/components/ui";
import { assignUserRole, fetchOrganizations, fetchRoles, fetchUsers } from "@/lib/api";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

function roleTone(code) {
  switch (code) {
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

export default function RolesPage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [roles, setRoles] = useState([]);
  const [users, setUsers] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState("");
  const [loading, setLoading] = useState(true);
  const [savingUserId, setSavingUserId] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const isSuperAdmin = user?.role?.code === "SUPER_ADMIN";
  const canAssignRoles = user?.role?.code === "SUPER_ADMIN" || user?.role?.code === "ORGANIZATION_OWNER";

  useEffect(() => {
    async function loadInitialData() {
      try {
        setLoading(true);
        setError("");
        const sessionUser = await restoreSession();
        if (!sessionUser) {
          router.replace("/login");
          return;
        }

        setUser(sessionUser);

        const nextRoles = await fetchRoles();
        setRoles(Array.isArray(nextRoles) ? nextRoles : []);

        let nextOrganizations = [];
        if (sessionUser.role?.code === "SUPER_ADMIN") {
          const organizationsResponse = await fetchOrganizations();
          nextOrganizations = Array.isArray(organizationsResponse) ? organizationsResponse : [];
          setOrganizations(nextOrganizations);
        }

        const defaultOrganizationId = sessionUser.organization?.id
          ? String(sessionUser.organization.id)
          : String(nextOrganizations[0]?.id || "");
        if (defaultOrganizationId) {
          setSelectedOrganizationId(defaultOrganizationId);
        }

        try {
          const usersResponse = await fetchUsers(defaultOrganizationId ? Number(defaultOrganizationId) : null);
          setUsers(Array.isArray(usersResponse) ? usersResponse : []);
        } catch (requestError) {
          setUsers([]);
          setNotice(requestError.message);
        }
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    }

    loadInitialData();
  }, [router]);

  const roleCounts = useMemo(() => {
    const counts = new Map(roles.map((role) => [role.code, 0]));
    for (const entry of users) {
      const code = entry?.role?.code;
      if (code) {
        counts.set(code, (counts.get(code) || 0) + 1);
      }
    }
    return counts;
  }, [roles, users]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading role management...</main>;
  }

  const selectedOrganization = organizations.find((organization) => String(organization.id) === selectedOrganizationId);

  async function refreshUsers(targetOrganizationId = selectedOrganizationId) {
    try {
      setError("");
      setNotice("");
      const response = await fetchUsers(targetOrganizationId ? Number(targetOrganizationId) : null);
      setUsers(Array.isArray(response) ? response : []);
    } catch (requestError) {
      setUsers([]);
      setNotice(requestError.message);
    }
  }

  async function handleOrganizationChange(event) {
    const nextOrganizationId = event.target.value;
    setSelectedOrganizationId(nextOrganizationId);
    await refreshUsers(nextOrganizationId);
  }

  async function handleRoleChange(userId, roleId) {
    if (!canAssignRoles) {
      setNotice("This account has read-only access to role data.");
      return;
    }

    try {
      setSavingUserId(userId);
      setError("");
      setNotice("");
      const updatedUser = await assignUserRole(userId, Number(roleId));
      setUsers((current) => current.map((item) => (item.id === updatedUser.id ? updatedUser : item)));
      setNotice(`Updated ${updatedUser.email} to ${updatedUser.role.name}.`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSavingUserId(null);
    }
  }

  return (
    <AppShell
      user={user}
      eyebrow="Role-Based Access Control"
      title="Role Management"
      subtitle="Review tenants, inspect assigned roles, and update access boundaries without changing the existing auth flow."
      status={canAssignRoles ? "Role assignment enabled" : "Read-only role view"}
      actions={
        <button
          type="button"
          className={secondaryButtonClassName}
          onClick={() => refreshUsers()}
        >
          <RefreshCw size={16} />
          <span>Refresh</span>
        </button>
      }
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading role assignments...
        </div>
      ) : null}
      {error ? (
        <div className="rounded-2xl border border-[rgba(255,93,118,0.2)] bg-[rgba(255,93,118,0.1)] px-4 py-3 text-[#ffd9de]">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-2xl border border-[rgba(82,224,162,0.2)] bg-[rgba(82,224,162,0.1)] px-4 py-3 text-[#ddfff2]">
          {notice}
        </div>
      ) : null}

      {!loading && !error ? (
        <>
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: "easeOut" }}
          >
            <Panel>
              <SectionHeading
                eyebrow="Access map"
                title="Organization scope"
                description="The backend now supports multi-tenant role assignment. Super admins can switch scope, while organization owners manage users inside their own tenant."
                aside={selectedOrganization ? `Selected: ${selectedOrganization.name}` : null}
              />

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                  label="Roles"
                  value={roles.length}
                  helper="System-defined access levels"
                  tone="accent"
                />
                <MetricCard
                  label="Users"
                  value={users.length}
                  helper="Users in the selected scope"
                  tone="safe"
                />
                <MetricCard
                  label="Assignable"
                  value={users.filter((item) => item.id !== user?.id).length}
                  helper="Accounts that can be updated"
                  tone="warning"
                />
                <MetricCard
                  label="Current Role"
                  value={user?.role?.code || "Unknown"}
                  helper={user?.role?.name || "No role loaded"}
                  tone="default"
                />
              </div>
            </Panel>
          </motion.section>

          <div className="grid gap-[18px] xl:grid-cols-[0.9fr_1.1fr]">
            <motion.section
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.05 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Directory"
                  title="Defined roles"
                  description="The platform seeds the standard SaaS roles and keeps them in the database for future extension."
                />

                <div className="grid gap-3">
                  {roles.map((role) => (
                    <div key={role.id} className="rounded-[22px] border border-vt-line bg-white/4 px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <strong className="block text-sm font-semibold">{role.name}</strong>
                          <p className="mt-1 text-sm leading-7 text-vt-muted">{role.description}</p>
                        </div>
                        <RiskBadge label={role.code} tone={roleTone(role.code)} />
                      </div>
                      <div className="mt-3 flex items-center justify-between text-sm text-vt-muted">
                        <span>Assigned users</span>
                        <span>{roleCounts.get(role.code) || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            </motion.section>

            <motion.section
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.1 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Assignments"
                title="Role assignments"
                description="Change a user's role while keeping organization boundaries and the existing login flow intact."
                aside={
                    isSuperAdmin && organizations.length ? (
                      <select
                        className="rounded-2xl border border-vt-line bg-white/5 px-4 py-2.5 text-sm text-vt-text outline-none"
                        value={selectedOrganizationId}
                        onChange={handleOrganizationChange}
                      >
                        {organizations.map((organization) => (
                          <option key={organization.id} value={organization.id}>
                            {organization.name}
                          </option>
                        ))}
                      </select>
                    ) : null
                  }
                />

                {users.length ? (
                  <div className="overflow-hidden rounded-[24px] border border-vt-line bg-white/3">
                    <div className="overflow-x-auto">
                      <table className="w-full min-w-[760px] border-collapse">
                        <thead>
                          <tr className="bg-white/3">
                            {["User", "Organization", "Role", "Change"].map((header, index) => (
                              <th
                                key={`${header}-${index}`}
                                className="border-b border-white/6 px-[18px] py-4 text-left text-[0.78rem] font-bold uppercase tracking-[0.16em] text-vt-muted"
                              >
                                {header}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {users.map((entry) => {
                            const isCurrentUser = entry.id === user?.id;
                            return (
                              <tr key={entry.id} className="transition hover:bg-white/3">
                                <td className="border-b border-white/6 px-[18px] py-4 align-top">
                                  <div className="grid gap-1">
                                    <strong className="text-[0.98rem] font-semibold">{entry.email}</strong>
                                    <small className="text-vt-muted">{isCurrentUser ? "Current session" : "Managed user"}</small>
                                  </div>
                                </td>
                                <td className="border-b border-white/6 px-[18px] py-4 align-top">
                                  <div className="grid gap-1">
                                    <span className="text-sm">{entry.organization?.name || "Unknown"}</span>
                                    <small className="text-vt-muted">{entry.organization?.slug || ""}</small>
                                  </div>
                                </td>
                                <td className="border-b border-white/6 px-[18px] py-4 align-top">
                                  <RiskBadge label={entry.role?.code || "UNKNOWN"} tone={roleTone(entry.role?.code)} />
                                </td>
                                <td className="border-b border-white/6 px-[18px] py-4 align-top">
                                  <div className="flex flex-col gap-2">
                                    <select
                                      className="rounded-2xl border border-vt-line bg-[rgba(3,10,21,0.54)] px-4 py-3 text-sm text-vt-text outline-none disabled:cursor-not-allowed disabled:opacity-60"
                                      value={entry.role_id}
                                      disabled={!canAssignRoles || isCurrentUser || savingUserId === entry.id}
                                      onChange={(event) => handleRoleChange(entry.id, event.target.value)}
                                    >
                                      {roles.map((role) => (
                                        <option key={role.id} value={role.id}>
                                          {role.name}
                                        </option>
                                      ))}
                                    </select>
                                    <div className="text-xs text-vt-muted">
                                      {isCurrentUser
                                        ? "Current session role is locked until re-authentication."
                                        : canAssignRoles
                                          ? "Choose a role and the backend will enforce tenant guards."
                                          : "Read-only access."}
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : (
                  <EmptyState
                    title="No users in scope"
                    description="There are no users available for this tenant yet, or your account only has read-only access to this view."
                    action={
                      canAssignRoles ? (
                        <button className={primaryButtonClassName} type="button" onClick={() => refreshUsers()}>
                          <Users size={16} />
                          <span>Reload users</span>
                        </button>
                      ) : null
                    }
                  />
                )}
              </Panel>
            </motion.section>
          </div>

          <Panel>
            <SectionHeading
              eyebrow="Notes"
              title="Multi-tenant readiness"
              description="The role layer is isolated from malware and threat intelligence modules. Those existing surfaces continue to work, while auth and authorization now carry organization and role context through the API."
            />
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-[#dbe7ff]">
                JWT tokens now include both `organization_id` and `role` claims.
              </div>
              <div className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-[#dbe7ff]">
                Organization owners can manage tenant users without crossing organization boundaries.
              </div>
              <div className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-[#dbe7ff]">
                Super admins can extend the platform across multiple organizations later without reworking the auth model.
              </div>
            </div>
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
