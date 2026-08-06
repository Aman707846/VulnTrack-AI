"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Plus, Save, Trash2 } from "lucide-react";

import AppShell from "@/app/components/app-shell";
import { EmptyState, MetricCard, Panel, SectionHeading, primaryButtonClassName, secondaryButtonClassName, RiskBadge } from "@/app/components/ui";
import { createOrganization, deleteOrganization, fetchOrganizations, updateOrganization } from "@/lib/api";
import { restoreSession, saveUser } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

const initialForm = {
  name: "",
  description: "",
  status: "active",
};

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

function statusTone(status) {
  switch ((status || "").toLowerCase()) {
    case "active":
      return "safe";
    case "suspended":
      return "warning";
    case "archived":
      return "neutral";
    default:
      return "neutral";
  }
}

function formatDateTime(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export default function OrganizationPage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [organizations, setOrganizations] = useState([]);
  const [form, setForm] = useState(initialForm);
  const [editingId, setEditingId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const roleCode = user?.role?.code || "";
  const canCreateOrganization = roleCode === "SUPER_ADMIN";
  const canManageOrganization = roleCode === "SUPER_ADMIN" || roleCode === "ORGANIZATION_OWNER";

  useEffect(() => {
    async function loadOrganizations() {
      try {
        setLoading(true);
        setError("");
        const sessionUser = await restoreSession();
        if (!sessionUser) {
          router.replace("/login");
          return;
        }

        setUser(sessionUser);
        const response = await fetchOrganizations();
        setOrganizations(Array.isArray(response) ? response : []);
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    }

    loadOrganizations();
  }, [router]);

  const totals = useMemo(() => {
    const totalOrganizations = organizations.length;
    const activeOrganizations = organizations.filter((organization) => organization.status === "active").length;
    const totalMembers = organizations.reduce((sum, organization) => sum + Number(organization.member_count || 0), 0);
    return { totalOrganizations, activeOrganizations, totalMembers };
  }, [organizations]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading organizations...</main>;
  }

  async function refreshOrganizations(nextUser = user) {
    const response = await fetchOrganizations();
    const nextOrganizations = Array.isArray(response) ? response : [];
    setOrganizations(nextOrganizations);

    if (nextUser?.organization?.id) {
      const refreshedOrganization = nextOrganizations.find(
        (organization) => organization.id === nextUser.organization.id,
      );
      if (refreshedOrganization) {
        const nextStoredUser = {
          ...nextUser,
          organization: refreshedOrganization,
        };
        setUser(nextStoredUser);
        saveUser(nextStoredUser);
      }
    }
  }

  function resetEditor() {
    setEditingId(null);
    setForm(initialForm);
  }

  function clearNotices() {
    setMessage("");
    setError("");
  }

  function startEditMode(organization) {
    setEditingId(organization.id);
    setForm({
      name: organization.name || "",
      description: organization.description || "",
      status: organization.status || "active",
    });
    setMessage("");
    setError("");
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (!canManageOrganization) {
      setError("You do not have permission to modify organizations.");
      return;
    }

    setSubmitting(true);
    clearNotices();

    try {
      const payload = {
        name: form.name,
        description: form.description,
        status: form.status,
      };
      const response = editingId
        ? await updateOrganization(editingId, payload)
        : await createOrganization(payload);

      await refreshOrganizations({
        ...user,
        organization:
          user?.organization?.id === response.id
            ? {
                ...(user.organization || {}),
                ...response,
              }
            : user?.organization,
      });
      setMessage(editingId ? "Organization updated." : "Organization created.");
      resetEditor();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(organization) {
    if (!canManageOrganization) {
      setError("You do not have permission to delete organizations.");
      return;
    }

    const confirmation = window.confirm(`Delete ${organization.name}? This cannot be undone.`);
    if (!confirmation) {
      return;
    }

    setSubmitting(true);
    clearNotices();

    try {
      await deleteOrganization(organization.id);
      await refreshOrganizations();
      if (editingId === organization.id) {
        resetEditor();
      }
      setMessage("Organization deleted.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AppShell
      user={user}
      eyebrow="Organization Foundation"
      title="Organization Management"
      subtitle="Create, update, and retire organizations from one control surface. The backend is now ready for tenant-aware growth."
      status={totals.totalOrganizations ? `${totals.totalOrganizations} organizations configured` : "No organizations configured"}
      actions={
        canCreateOrganization ? (
          <button
            className={secondaryButtonClassName}
            type="button"
            onClick={() => {
              clearNotices();
              resetEditor();
            }}
          >
            <Plus size={16} />
            <span>New organization</span>
          </button>
        ) : null
      }
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading organizations...
        </div>
      ) : null}
      {error ? (
        <div className="rounded-2xl border border-[rgba(255,93,118,0.2)] bg-[rgba(255,93,118,0.1)] px-4 py-3 text-[#ffd9de]">
          {error}
        </div>
      ) : null}
      {message ? (
        <div className="rounded-2xl border border-[rgba(82,224,162,0.2)] bg-[rgba(82,224,162,0.1)] px-4 py-3 text-[#ddfff2]">
          {message}
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
                eyebrow="Tenant posture"
                title="Foundation overview"
                description="Track the current organization footprint before you add user-scoped tenancy across the rest of the platform."
                aside={user?.organization?.name ? `Current org: ${user.organization.name}` : null}
              />

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                  label="Organizations"
                  value={totals.totalOrganizations}
                  helper="All configured tenant containers"
                  tone="accent"
                />
                <MetricCard
                  label="Active"
                  value={totals.activeOrganizations}
                  helper="Organizations marked active"
                  tone="safe"
                />
                <MetricCard
                  label="Members"
                  value={totals.totalMembers}
                  helper="Users assigned to organizations"
                  tone="warning"
                />
                <MetricCard
                  label="Current Org"
                  value={user?.organization?.name || "None"}
                  helper={user?.organization?.slug || "No organization loaded"}
                  tone="default"
                />
              </div>
            </Panel>
          </motion.section>

          <div className="grid gap-[18px] xl:grid-cols-[minmax(0,1.15fr)_minmax(380px,0.85fr)]">
            <motion.section
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.08 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Directory"
                  title="Organization list"
                  description="Review status, slug, and membership count for each tenant."
                  aside={`${organizations.length} records`}
                />

                {organizations.length ? (
                  <div className="grid gap-3">
                    {organizations.map((organization) => {
                      const isCurrent = user?.organization?.id === organization.id;
                      const isEditing = editingId === organization.id;
                      return (
                        <article
                          key={organization.id}
                          className={cx(
                            "rounded-[22px] border p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] transition duration-200",
                            isCurrent
                              ? "border-[rgba(121,242,192,0.22)] bg-[linear-gradient(180deg,rgba(121,242,192,0.1),rgba(255,255,255,0.03))]"
                              : "border-vt-line bg-white/4 hover:-translate-y-0.5 hover:border-[rgba(121,242,192,0.18)]",
                          )}
                        >
                          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                            <div>
                              <div className="flex flex-wrap items-center gap-2">
                                <strong className="text-lg font-semibold">{organization.name}</strong>
                                {isCurrent ? <RiskBadge label="Current tenant" tone="safe" /> : null}
                                <RiskBadge label={organization.status} tone={statusTone(organization.status)} />
                              </div>
                              <div className="mt-2 text-sm text-vt-muted">
                                Slug: <span className="font-mono text-[#dbe7ff]">{organization.slug}</span>
                              </div>
                              <p className="mt-3 max-w-3xl text-sm leading-7 text-[#d7e2ff]">
                                {organization.description || "No organization description provided."}
                              </p>
                              <div className="mt-4 flex flex-wrap gap-2 text-[0.84rem] text-vt-muted">
                                <span className="rounded-full bg-white/4 px-3 py-1.5">
                                  {organization.member_count || 0} members
                                </span>
                                <span className="rounded-full bg-white/4 px-3 py-1.5">
                                  Created {formatDateTime(organization.created_at)}
                                </span>
                                <span className="rounded-full bg-white/4 px-3 py-1.5">
                                  Updated {formatDateTime(organization.updated_at)}
                                </span>
                              </div>
                            </div>

                            <div className="flex flex-wrap gap-2 lg:justify-end">
                              {canManageOrganization ? (
                                <>
                                  <button
                                    type="button"
                                    className={cx(
                                      secondaryButtonClassName,
                                      isEditing ? "border-[rgba(121,242,192,0.28)] bg-[rgba(121,242,192,0.12)] text-vt-text" : "",
                                    )}
                                    onClick={() => startEditMode(organization)}
                                  >
                                    <Save size={16} />
                                    <span>{isEditing ? "Editing" : "Edit"}</span>
                                  </button>
                                  <button
                                    type="button"
                                    className={secondaryButtonClassName}
                                    disabled={submitting}
                                    onClick={() => handleDelete(organization)}
                                  >
                                    <Trash2 size={16} />
                                    <span>Delete</span>
                                  </button>
                                </>
                              ) : (
                                <div className="rounded-full border border-white/8 bg-white/5 px-3 py-2 text-xs uppercase tracking-[0.12em] text-vt-muted">
                                  Read only
                                </div>
                              )}
                            </div>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyState
                    title="No organizations yet"
                    description="Create the first organization to establish a tenant boundary for the platform."
                    action={
                      canManageOrganization ? (
                      <button
                        className={primaryButtonClassName}
                        type="button"
                        onClick={() => {
                          clearNotices();
                          resetEditor();
                        }}
                        >
                          <Plus size={16} />
                          <span>Create organization</span>
                        </button>
                      ) : null
                    }
                  />
                )}
              </Panel>
            </motion.section>

            <motion.section
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.14 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Editor"
                  title={editingId ? "Edit organization" : "Create organization"}
                  description="This panel handles tenant provisioning while leaving the malware and threat intelligence modules untouched."
                />

                {canManageOrganization ? (
                  <form className="grid gap-4" onSubmit={handleSubmit}>
                    <div className="grid gap-2">
                      <label htmlFor="name" className="text-[0.82rem] font-bold uppercase tracking-[0.14em] text-[#d8e4ff]">
                        Name
                      </label>
                      <input
                        id="name"
                        name="name"
                        type="text"
                        required
                        placeholder="Northwind Security"
                        className="w-full rounded-2xl border border-vt-line bg-[rgba(3,10,21,0.54)] px-4 py-3.5 text-vt-text outline-none transition duration-200 placeholder:text-slate-500 focus:border-[rgba(121,242,192,0.45)] focus:shadow-[0_0_0_4px_rgba(121,242,192,0.12)]"
                        value={form.name}
                        onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                      />
                    </div>

                    <div className="grid gap-2">
                      <label
                        htmlFor="description"
                        className="text-[0.82rem] font-bold uppercase tracking-[0.14em] text-[#d8e4ff]"
                      >
                        Description
                      </label>
                      <textarea
                        id="description"
                        name="description"
                        rows="4"
                        placeholder="Tenant boundary, business unit, or customer environment."
                        className="w-full rounded-2xl border border-vt-line bg-[rgba(3,10,21,0.54)] px-4 py-3.5 text-vt-text outline-none transition duration-200 placeholder:text-slate-500 focus:border-[rgba(121,242,192,0.45)] focus:shadow-[0_0_0_4px_rgba(121,242,192,0.12)]"
                        value={form.description}
                        onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
                      />
                    </div>

                    <div className="grid gap-2">
                      <label htmlFor="status" className="text-[0.82rem] font-bold uppercase tracking-[0.14em] text-[#d8e4ff]">
                        Status
                      </label>
                      <select
                        id="status"
                        name="status"
                        className="w-full rounded-2xl border border-vt-line bg-[rgba(3,10,21,0.54)] px-4 py-3.5 text-vt-text outline-none transition duration-200 focus:border-[rgba(121,242,192,0.45)] focus:shadow-[0_0_0_4px_rgba(121,242,192,0.12)]"
                        value={form.status}
                        onChange={(event) => setForm((current) => ({ ...current, status: event.target.value }))}
                      >
                        <option value="active">Active</option>
                        <option value="suspended">Suspended</option>
                        <option value="archived">Archived</option>
                      </select>
                    </div>

                    <div className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-vt-muted">
                      Organization slugs are derived automatically. That keeps future subdomain or tenant-routing work
                      predictable.
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                      <button className={primaryButtonClassName} type="submit" disabled={submitting}>
                        {submitting ? "Working..." : editingId ? "Save organization" : "Create organization"}
                      </button>
                      <button
                        className={secondaryButtonClassName}
                        type="button"
                        onClick={() => {
                          clearNotices();
                          resetEditor();
                        }}
                      >
                        Reset
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="rounded-[24px] border border-dashed border-vt-line bg-white/4 p-5 text-sm leading-7 text-vt-muted">
                    You can view the organization directory, but this account cannot create or update tenants.
                  </div>
                )}

                <div className="mt-5 rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-vt-muted">
                  The existing malware scanning and threat intelligence modules continue to run unchanged. This
                  foundation only adds tenant identity and management.
                </div>
              </Panel>
            </motion.section>
          </div>
        </>
      ) : null}
    </AppShell>
  );
}
