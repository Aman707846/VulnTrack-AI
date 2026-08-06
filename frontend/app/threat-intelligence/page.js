"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import AppShell from "@/app/components/app-shell";
import { MetricCard, Panel, SectionHeading, secondaryButtonClassName } from "@/app/components/ui";
import { fetchThreatIntelDashboard, syncThreatIntel } from "@/lib/api";
import { formatDateTime } from "@/lib/scan-model";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

const CHART_COLORS = {
  total_cves: "#73f0cf",
  critical_cves: "#ff5d76",
  high_cves: "#ffb95a",
  indicators: "#79a8ff",
  correlations: "#c7a6ff",
  average_threat_score: "#52e0a2",
};

function chartTooltipStyle() {
  return {
    background: "rgba(6, 12, 24, 0.94)",
    border: "1px solid rgba(157, 176, 212, 0.16)",
    borderRadius: 16,
    color: "#eff4ff",
  };
}

export default function ThreatIntelligencePage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);
        setError("");
        const sessionUser = await restoreSession();
        if (!sessionUser) {
          router.replace("/login");
          return;
        }

        setUser(sessionUser);
        const response = await fetchThreatIntelDashboard();
        setDashboard(response);
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, [router]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading threat intelligence...</main>;
  }

  const latestCritical = Array.isArray(dashboard?.latest_critical_cves) ? dashboard.latest_critical_cves : [];
  const feedSummary = dashboard?.threat_feed_summary ?? {};
  const coverage = Array.isArray(dashboard?.mitre_attack_coverage) ? dashboard.mitre_attack_coverage : [];
  const topIndicators = Array.isArray(dashboard?.top_threat_indicators) ? dashboard.top_threat_indicators : [];
  const trends = Array.isArray(dashboard?.threat_trends) ? dashboard.threat_trends : [];

  async function handleSync() {
    try {
      setSyncing(true);
      await syncThreatIntel({
        sync_nvd: true,
        sync_attack: true,
        sync_indicators: false,
        lookback_days: 7,
        force: false,
      });
      const refreshed = await fetchThreatIntelDashboard();
      setDashboard(refreshed);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSyncing(false);
    }
  }

  return (
    <AppShell
      user={user}
      eyebrow="Threat Intelligence"
      title="CVE Correlation Engine"
      subtitle="Unify vulnerability feeds, threat indicators, ATT&CK coverage, malware context, and assets into one correlated threat view."
      status={dashboard ? `${dashboard.critical_cves} critical CVEs tracked` : "Threat feed idle"}
      actions={
        <button
          type="button"
          className={secondaryButtonClassName}
          onClick={handleSync}
          disabled={syncing}
        >
          {syncing ? "Syncing..." : "Sync Feeds"}
        </button>
      }
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading threat intelligence...
        </div>
      ) : null}
      {error ? (
        <div className="rounded-2xl border border-[rgba(255,93,118,0.2)] bg-[rgba(255,93,118,0.1)] px-4 py-3 text-[#ffd9de]">
          {error}
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
                eyebrow="Overview"
                title="Threat feed summary"
                description="Latest critical CVEs, threat indicator coverage, and correlated asset exposure."
              />
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard label="Total CVEs" value={dashboard?.total_cves ?? 0} helper="Synced vulnerability intelligence" tone="accent" />
                <MetricCard label="Critical CVEs" value={dashboard?.critical_cves ?? 0} helper="CVSS critical records" tone="danger" />
                <MetricCard label="Indicators Ingested" value={dashboard?.indicators_ingested ?? 0} helper="IP, domain, URL, and hash IOCs" tone="warning" />
                <MetricCard label="Correlations Generated" value={dashboard?.correlations_generated ?? 0} helper="Unified threat assessments" tone="safe" />
              </div>
            </Panel>
          </motion.section>

          <div className="grid gap-[18px] xl:grid-cols-[1.1fr_0.9fr]">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.05 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Trends"
                  title="Threat trends"
                  description="Daily trend line showing CVE velocity, indicator ingestion, and correlation volume."
                />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="h-[320px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trends} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                        <CartesianGrid stroke="rgba(157,176,212,0.10)" vertical={false} />
                        <XAxis dataKey="date" stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} />
                        <YAxis stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={chartTooltipStyle()} labelFormatter={(value) => formatDateTime(value)} />
                        <Line type="monotone" dataKey="total_cves" stroke={CHART_COLORS.total_cves} strokeWidth={3} dot={{ r: 3 }} />
                        <Line type="monotone" dataKey="critical_cves" stroke={CHART_COLORS.critical_cves} strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="indicators" stroke={CHART_COLORS.indicators} strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="correlations" stroke={CHART_COLORS.correlations} strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 inline-flex items-center gap-2 rounded-full bg-white/4 px-3 py-2 text-[0.84rem] text-[#dfe8ff]">
                    <i className="h-2.5 w-2.5 rounded-full bg-vt-accent" />
                    Average threat score trend: {(trends.at(-1)?.average_threat_score ?? 0).toFixed(1)}
                  </div>
                </div>
              </Panel>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.08 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Coverage"
                  title="MITRE ATT&CK coverage"
                  description="Technique and tactic coverage inferred from CVE text, indicators, malware labels, and correlations."
                />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="grid gap-4">
                    {coverage.slice(0, 6).map((item, index) => (
                      <div key={`${item.tactic_name}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3">
                        <div className="flex items-center justify-between gap-3">
                          <strong className="text-sm font-semibold">{item.tactic_name}</strong>
                          <span className="text-sm text-vt-muted">{item.technique_count} techniques</span>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-[0.78rem] text-[#d9e5ff]">
                          <span className="rounded-full bg-[rgba(115,240,207,0.12)] px-3 py-1">
                            CVEs: {item.mapped_cves}
                          </span>
                          <span className="rounded-full bg-[rgba(121,168,255,0.12)] px-3 py-1">
                            IOCs: {item.mapped_indicators}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </Panel>
            </motion.div>
          </div>

          <div className="grid gap-[18px] xl:grid-cols-[0.95fr_1.05fr]">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.12 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Critical"
                  title="Latest critical CVEs"
                  description="High-priority vulnerabilities most relevant to exploitation and incident response."
                />
                <div className="space-y-3">
                  {latestCritical.length ? (
                    latestCritical.map((item, index) => (
                      <div key={`${item.cve_id}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <strong className="block text-sm font-semibold">{item.cve_id}</strong>
                            <p className="mt-1 text-sm leading-7 text-vt-muted line-clamp-3">
                              {item.description || "No description available."}
                            </p>
                          </div>
                          <div className="shrink-0 rounded-full border border-[rgba(255,93,118,0.24)] bg-[rgba(255,93,118,0.12)] px-3 py-1 text-xs uppercase tracking-[0.12em] text-[#ffd9e0]">
                            {item.cvss_severity || "UNKNOWN"} {Number(item.cvss_score || 0).toFixed(1)}
                          </div>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2">
                          {(item.attack_techniques || []).slice(0, 3).map((technique, techniqueIndex) => (
                            <span key={`${technique}-${techniqueIndex}`} className="rounded-full bg-white/6 px-3 py-1 text-[0.76rem] text-[#dfe8ff]">
                              {technique}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="rounded-2xl border border-dashed border-vt-line bg-white/4 px-4 py-5 text-sm text-vt-muted">
                      No synced critical CVEs are available yet.
                    </div>
                  )}
                </div>
              </Panel>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.16 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Indicators"
                  title="Top threat indicators"
                  description="Most actionable IOCs by reputation and correlation volume."
                />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="h-[240px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Tooltip contentStyle={chartTooltipStyle()} />
                        <Pie data={topIndicators.slice(0, 6)} dataKey="count" nameKey="value" innerRadius={68} outerRadius={108} paddingAngle={3}>
                          {topIndicators.slice(0, 6).map((entry, index) => (
                            <Cell
                              key={`${entry.value}-${index}`}
                              fill={["#73f0cf", "#79a8ff", "#ffb95a", "#ff8f5a", "#ff5d76", "#52e0a2"][index % 6]}
                            />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 grid gap-2">
                    {topIndicators.slice(0, 6).map((item, index) => (
                      <div key={`${item.value}-${index}`} className="flex items-center justify-between rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm">
                        <span className="truncate">{item.value}</span>
                        <span className="text-vt-muted">
                          {item.indicator_type} | {item.reputation_level} | {item.reputation_score}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </Panel>
            </motion.div>
          </div>

          <Panel>
            <SectionHeading
              eyebrow="Telemetry"
              title="Threat feed summary"
              description="Recent sync runs and feed counters for operational visibility."
            />
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <MetricCard label="Coverage %" value={dashboard?.mitre_coverage_percent ?? 0} helper="ATT&CK technique coverage" tone="safe" />
              <MetricCard label="Asset Count" value={feedSummary.asset_count ?? 0} helper="Known assets in scope" tone="accent" />
              <MetricCard label="Feed Correlations" value={feedSummary.correlation_count ?? 0} helper="Cross-domain correlation rows" tone="warning" />
              <MetricCard label="Recent Sync Runs" value={(feedSummary.recent_sync_runs || []).length} helper="Completed or failed syncs" tone="danger" />
            </div>
            <div className="mt-5 overflow-hidden rounded-[24px] border border-vt-line bg-white/3">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] border-collapse">
                  <thead>
                    <tr className="bg-white/3">
                      {["Source", "Status", "Ingested", "Updated", "Finished"].map((header, index) => (
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
                    {(feedSummary.recent_sync_runs || []).map((run, index) => (
                      <tr key={`${run.sync_type}-${index}`} className="transition hover:bg-white/3">
                        <td className="border-b border-white/6 px-[18px] py-4 align-top">{run.sync_type}</td>
                        <td className="border-b border-white/6 px-[18px] py-4 align-top">{run.status}</td>
                        <td className="border-b border-white/6 px-[18px] py-4 align-top">{run.records_ingested}</td>
                        <td className="border-b border-white/6 px-[18px] py-4 align-top">{run.records_updated}</td>
                        <td className="border-b border-white/6 px-[18px] py-4 align-top">{run.finished_at ? formatDateTime(run.finished_at) : "Running"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
