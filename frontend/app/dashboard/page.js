"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
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
import { ArrowRight } from "lucide-react";

import AppShell from "@/app/components/app-shell";
import ScanHistoryList from "@/app/components/scan-history-list";
import {
  MetricCard,
  Panel,
  SectionHeading,
  primaryButtonClassName,
  secondaryButtonClassName,
} from "@/app/components/ui";
import { fetchScans } from "@/lib/api";
import {
  buildOverviewStats,
  buildRiskDistribution,
  buildTrendSeries,
  formatDateTime,
  formatShortDay,
  normalizeScan,
} from "@/lib/scan-model";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

function chartTooltipStyle() {
  return {
    background: "rgba(6, 12, 24, 0.94)",
    border: "1px solid rgba(157, 176, 212, 0.16)",
    borderRadius: 16,
    color: "#eff4ff",
  };
}

export default function DashboardPage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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
        const response = await fetchScans(sessionUser.id);
        const nextScans = Array.isArray(response?.scans)
          ? response.scans
          : Array.isArray(response)
            ? response
            : [];
        setScans(nextScans.map(normalizeScan));
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, [router]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading dashboard...</main>;
  }

  const stats = buildOverviewStats(scans);
  const distribution = buildRiskDistribution(scans);
  const trendSeries = buildTrendSeries(scans, 8);

  return (
    <AppShell
      user={user}
      eyebrow="AI Malware Scanner"
      title="Dashboard"
      subtitle="Track total scans, verdict trends, and scan history from one clean overview."
      status={stats.malicious > 0 ? "Malicious results detected" : "No active high-risk result"}
      actions={
        <Link className={secondaryButtonClassName} href="/scan-upload">
          Open scanner
        </Link>
      }
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading scan telemetry...
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
                eyebrow="Top Section"
                title="Scan overview"
                description="Quickly monitor how many files and URLs were scanned and how they were classified."
                aside={
                  <Link className={primaryButtonClassName} href="/scan-upload">
                    Start a scan
                    <ArrowRight size={18} />
                  </Link>
                }
              />

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard label="Total Scans" value={stats.total} helper="All recorded file and URL scans" tone="accent" />
                <MetricCard label="Safe Files" value={stats.safe} helper="Results currently classified as safe" tone="safe" />
                <MetricCard label="Suspicious" value={stats.suspicious + stats.lowRisk} helper="Results that still need manual review" tone="warning" />
                <MetricCard label="Malicious" value={stats.malicious} helper="High-risk results requiring attention" tone="danger" />
              </div>
            </Panel>
          </motion.section>

          <div className="grid gap-[18px] xl:grid-cols-2">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.45, delay: 0.08 }}
            >
              <Panel>
                <SectionHeading eyebrow="Middle" title="Risk distribution" description="Pie chart of safe, suspicious, and malicious outcomes." />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="mt-2 h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Tooltip contentStyle={chartTooltipStyle()} />
                        <Pie
                          data={distribution}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={78}
                          outerRadius={116}
                          paddingAngle={3}
                          stroke="rgba(157,176,212,0.12)"
                        >
                          {distribution.map((entry, index) => (
                            <Cell key={`${entry.name}-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2.5">
                    {distribution.map((item, index) => (
                      <span key={`${item.name}-${index}`} className="inline-flex items-center gap-2 rounded-full bg-white/4 px-3 py-2 text-[0.84rem] text-[#dfe8ff]">
                        <i className="h-2.5 w-2.5 rounded-full" style={{ background: item.color }} />
                        {item.name}: {item.value}
                      </span>
                    ))}
                  </div>
                </div>
              </Panel>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.45, delay: 0.14 }}
            >
              <Panel>
                <SectionHeading eyebrow="Middle" title="Scan trend" description="Line chart showing scan volume across the last eight days." />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="mt-2 h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trendSeries} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                        <CartesianGrid stroke="rgba(157,176,212,0.10)" vertical={false} />
                        <XAxis dataKey="date" tickFormatter={(value) => formatShortDay(value)} stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} />
                        <YAxis allowDecimals={false} stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={chartTooltipStyle()} labelFormatter={(value) => formatDateTime(value)} />
                        <Line
                          type="monotone"
                          dataKey="total"
                          stroke="#73f0cf"
                          strokeWidth={3}
                          dot={{ fill: "#73f0cf", strokeWidth: 0, r: 4 }}
                          activeDot={{ r: 6, fill: "#73f0cf" }}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 inline-flex items-center gap-2 rounded-full bg-white/4 px-3 py-2 text-[0.84rem] text-[#dfe8ff]">
                    <i className="h-2.5 w-2.5 rounded-full bg-vt-accent" />
                    Daily scan volume
                  </div>
                </div>
              </Panel>
            </motion.div>
          </div>

          <motion.section
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.2 }}
          >
            <ScanHistoryList
              scans={scans}
              eyebrow="Bottom"
              title="Scan history"
              description="Each scan is shown as a card. Click any item to expand and inspect its details."
              aside={`${scans.length} items`}
            />
          </motion.section>
        </>
      ) : null}
    </AppShell>
  );
}
