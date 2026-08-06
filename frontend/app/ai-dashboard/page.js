"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import AppShell from "@/app/components/app-shell";
import {
  MetricCard,
  Panel,
  RiskBadge,
  SectionHeading,
  ghostButtonClassName,
  primaryButtonClassName,
  secondaryButtonClassName,
} from "@/app/components/ui";
import {
  askAiCopilot,
  fetchAiDashboard,
  generateAiReport,
  scoreAiRisk,
} from "@/lib/api";
import { formatDateTime, formatShortDay } from "@/lib/scan-model";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

const DEFAULT_RISK_FORM = {
  cvss_score: "9.1",
  threat_intelligence_score: "72",
  malware_reputation_score: "24",
  asset_criticality: "critical",
  exploit_available: true,
  internet_exposed: true,
};

function chartTooltipStyle() {
  return {
    background: "rgba(6, 12, 24, 0.94)",
    border: "1px solid rgba(157, 176, 212, 0.16)",
    borderRadius: 16,
    color: "#eff4ff",
  };
}

function severityTone(value) {
  const normalized = String(value || "unknown").toLowerCase();
  if (["critical", "high", "danger", "malicious"].includes(normalized)) {
    return "danger";
  }
  if (["medium", "suspicious", "watch", "warning"].includes(normalized)) {
    return "warning";
  }
  if (["low", "safe", "trusted", "low risk"].includes(normalized)) {
    return "safe";
  }
  return "neutral";
}

function formatRiskDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return formatShortDay(date);
}

export default function AiDashboardPage() {
  const router = useRouter();
  const mounted = useMounted();
  const [user, setUser] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [copilotQuestion, setCopilotQuestion] = useState("What are the top threats in VulnTrack right now?");
  const [copilotResult, setCopilotResult] = useState(null);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [reportType, setReportType] = useState("executive");
  const [reportResult, setReportResult] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [riskForm, setRiskForm] = useState(DEFAULT_RISK_FORM);
  const [riskResult, setRiskResult] = useState(null);
  const [riskLoading, setRiskLoading] = useState(false);

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
        const response = await fetchAiDashboard();
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
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading AI dashboard...</main>;
  }

  const trendRows = Array.isArray(dashboard?.security_trends) ? dashboard.security_trends : [];
  const topThreats = Array.isArray(dashboard?.top_threats) ? dashboard.top_threats : [];
  const criticalAssets = Array.isArray(dashboard?.critical_assets) ? dashboard.critical_assets : [];
  const recommendations = Array.isArray(dashboard?.ai_recommendations) ? dashboard.ai_recommendations : [];
  const recentIncidents = Array.isArray(dashboard?.recent_incidents) ? dashboard.recent_incidents : [];
  const riskScore = Number(dashboard?.organization_risk_score ?? 0);

  async function handleCopilotSubmit() {
    try {
      setCopilotLoading(true);
      setError("");
      const response = await askAiCopilot({ question: copilotQuestion, limit: 5 });
      setCopilotResult(response);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCopilotLoading(false);
    }
  }

  async function handleGenerateReport() {
    try {
      setReportLoading(true);
      setError("");
      const response = await generateAiReport({ report_type: reportType, limit: 5 });
      setReportResult(response);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setReportLoading(false);
    }
  }

  async function handleScoreRisk() {
    try {
      setRiskLoading(true);
      setError("");
      const response = await scoreAiRisk({
        cvss_score: Number(riskForm.cvss_score || 0),
        threat_intelligence_score: Number(riskForm.threat_intelligence_score || 0),
        malware_reputation_score: Number(riskForm.malware_reputation_score || 0),
        asset_criticality: riskForm.asset_criticality,
        exploit_available: Boolean(riskForm.exploit_available),
        internet_exposed: Boolean(riskForm.internet_exposed),
      });
      setRiskResult(response);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setRiskLoading(false);
    }
  }

  return (
    <AppShell
      user={user}
      eyebrow="AI Security Intelligence"
      title="Executive AI Dashboard"
      subtitle="A single view for organization risk, top threat chains, critical assets, recommendations, and AI copiloting."
      status={`Organization risk score ${riskScore}/100`}
      actions={
        <button
          type="button"
          className={secondaryButtonClassName}
          onClick={handleGenerateReport}
          disabled={reportLoading}
        >
          {reportLoading ? "Generating..." : "Generate report"}
        </button>
      }
    >
      {loading ? (
        <div className="rounded-2xl border border-white/8 bg-white/4 px-4 py-3 text-[#d6e2fb]">
          Loading AI intelligence...
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
                eyebrow="Executive"
                title="Risk posture"
                description={dashboard?.executive_summary || "No summary available."}
                aside={<RiskBadge label={dashboard?.organization_risk_score > 75 ? "High risk" : "Managed risk"} tone={severityTone(riskScore >= 85 ? "critical" : riskScore >= 65 ? "high" : riskScore >= 40 ? "medium" : "low")} />}
              />

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard label="Organization Risk" value={riskScore} helper="AI-computed blended threat posture" tone={riskScore >= 85 ? "danger" : riskScore >= 65 ? "warning" : riskScore >= 40 ? "accent" : "safe"} />
                <MetricCard label="Top Threats" value={topThreats.length} helper="Correlated exploit and malware clusters" tone="danger" />
                <MetricCard label="Critical Assets" value={criticalAssets.length} helper="Business-critical systems with highest exposure" tone="warning" />
                <MetricCard label="Recommendations" value={recommendations.length} helper="Prioritized AI-generated next actions" tone="safe" />
              </div>
            </Panel>
          </motion.section>

          <div className="grid gap-[18px] xl:grid-cols-[1.15fr_0.85fr]">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.05 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Trends"
                  title="Security trend line"
                  description="AI trend scoring across CVEs, indicators, malware, scans, and correlation activity."
                />
                <div className="rounded-[24px] border border-vt-line bg-white/3 p-5">
                  <div className="h-[320px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trendRows} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                        <CartesianGrid stroke="rgba(157,176,212,0.10)" vertical={false} />
                        <XAxis dataKey="date" stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} tickFormatter={formatRiskDate} />
                        <YAxis stroke="rgba(142,161,196,0.9)" tickLine={false} axisLine={false} domain={[0, 100]} />
                        <Tooltip contentStyle={chartTooltipStyle()} labelFormatter={formatDateTime} />
                        <Line type="monotone" dataKey="risk_score" stroke="#73f0cf" strokeWidth={3} dot={{ r: 4 }} />
                        <Line type="monotone" dataKey="cve_count" stroke="#ff5d76" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="indicator_count" stroke="#79a8ff" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="correlation_count" stroke="#c7a6ff" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
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
                  eyebrow="Actions"
                  title="AI recommendations"
                  description="The engine turns the current threat posture into focused next steps."
                />
                <div className="space-y-3">
                  {recommendations.map((item, index) => (
                    <div key={`${item}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3 text-sm leading-7 text-[#dfe8ff]">
                      {item}
                    </div>
                  ))}
                </div>
              </Panel>
            </motion.div>
          </div>

          <div className="grid gap-[18px] xl:grid-cols-[0.92fr_1.08fr]">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.12 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Threats"
                  title="Top threat clusters"
                  description="The highest-priority correlations, CVEs, and malware records driving the risk score."
                />
                <div className="space-y-3">
                  {topThreats.map((threat, index) => (
                    <div key={`${threat.title}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <strong className="block text-sm font-semibold">{threat.title}</strong>
                          <p className="mt-1 text-sm leading-7 text-vt-muted">{threat.summary}</p>
                        </div>
                        <RiskBadge label={`${threat.severity} ${threat.score}`} tone={severityTone(threat.severity)} />
                      </div>
                      <p className="mt-3 text-sm leading-7 text-[#d7e2ff]">{threat.impact}</p>
                    </div>
                  ))}
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
                  eyebrow="Assets"
                  title="Critical assets"
                  description="Assets with the strongest exposure and remediation priority."
                />
                <div className="grid gap-3">
                  {criticalAssets.map((asset, index) => (
                    <div key={`${asset.asset_id}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <strong className="block text-sm font-semibold">{asset.asset_name}</strong>
                          <p className="mt-1 text-sm text-vt-muted">Criticality: {asset.criticality}</p>
                        </div>
                        <RiskBadge label={String(asset.risk_score)} tone={severityTone(asset.risk_score >= 80 ? "critical" : asset.risk_score >= 60 ? "high" : asset.risk_score >= 40 ? "medium" : "low")} />
                      </div>
                      <p className="mt-3 text-sm leading-7 text-[#d7e2ff]">{asset.exposure}</p>
                      <p className="mt-2 text-sm leading-7 text-vt-accent">{asset.recommendation}</p>
                    </div>
                  ))}
                </div>
              </Panel>
            </motion.div>
          </div>

          <div className="grid gap-[18px] xl:grid-cols-[0.92fr_1.08fr]">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.2 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Risk"
                  title="Hybrid risk scorer"
                  description="Tune the inputs the engine uses to blend CVSS, threat intel, malware reputation, criticality, and exploit availability."
                />
                <div className="grid gap-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2 text-sm text-[#dfe8ff]">
                      CVSS
                      <input
                        className="rounded-2xl border border-vt-line bg-white/5 px-4 py-3 text-vt-text outline-none focus:border-[rgba(115,240,207,0.45)]"
                        type="number"
                        min="0"
                        max="10"
                        step="0.1"
                        value={riskForm.cvss_score}
                        onChange={(event) => setRiskForm((current) => ({ ...current, cvss_score: event.target.value }))}
                      />
                    </label>
                    <label className="grid gap-2 text-sm text-[#dfe8ff]">
                      Threat intel
                      <input
                        className="rounded-2xl border border-vt-line bg-white/5 px-4 py-3 text-vt-text outline-none focus:border-[rgba(115,240,207,0.45)]"
                        type="number"
                        min="0"
                        max="100"
                        step="1"
                        value={riskForm.threat_intelligence_score}
                        onChange={(event) => setRiskForm((current) => ({ ...current, threat_intelligence_score: event.target.value }))}
                      />
                    </label>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2 text-sm text-[#dfe8ff]">
                      Malware reputation
                      <input
                        className="rounded-2xl border border-vt-line bg-white/5 px-4 py-3 text-vt-text outline-none focus:border-[rgba(115,240,207,0.45)]"
                        type="number"
                        min="0"
                        max="100"
                        step="1"
                        value={riskForm.malware_reputation_score}
                        onChange={(event) => setRiskForm((current) => ({ ...current, malware_reputation_score: event.target.value }))}
                      />
                    </label>
                    <label className="grid gap-2 text-sm text-[#dfe8ff]">
                      Criticality
                      <select
                        className="rounded-2xl border border-vt-line bg-white/5 px-4 py-3 text-vt-text outline-none focus:border-[rgba(115,240,207,0.45)]"
                        value={riskForm.asset_criticality}
                        onChange={(event) => setRiskForm((current) => ({ ...current, asset_criticality: event.target.value }))}
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </label>
                  </div>

                  <div className="flex flex-wrap gap-4 text-sm text-[#dfe8ff]">
                    <label className="inline-flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={riskForm.exploit_available}
                        onChange={(event) => setRiskForm((current) => ({ ...current, exploit_available: event.target.checked }))}
                      />
                      Exploit available
                    </label>
                    <label className="inline-flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={riskForm.internet_exposed}
                        onChange={(event) => setRiskForm((current) => ({ ...current, internet_exposed: event.target.checked }))}
                      />
                      Internet exposed
                    </label>
                  </div>

                  <div>
                    <button type="button" className={primaryButtonClassName} onClick={handleScoreRisk} disabled={riskLoading}>
                      {riskLoading ? "Scoring..." : "Score risk"}
                    </button>
                  </div>

                  {riskResult ? (
                    <div className="rounded-[24px] border border-white/6 bg-white/4 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <strong className="text-sm uppercase tracking-[0.12em] text-vt-accent">Risk Result</strong>
                        <RiskBadge label={`${riskResult.severity} ${riskResult.risk_score}`} tone={severityTone(riskResult.severity)} />
                      </div>
                      <p className="mt-3 text-sm leading-7 text-[#dbe7ff]">{riskResult.explanation}</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {(riskResult.recommended_actions || []).map((item, index) => (
                          <span key={`${item}-${index}`} className="rounded-full border border-white/8 bg-white/5 px-3 py-1 text-xs text-[#d7e2ff]">
                            {item}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </Panel>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.24 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Copilot"
                  title="Security copilot"
                  description="Ask natural-language questions and get back matched VulnTrack data, search results, and action guidance."
                />
                <div className="grid gap-3">
                  <textarea
                    className="min-h-[120px] rounded-[24px] border border-vt-line bg-white/5 px-4 py-4 text-sm leading-7 text-vt-text outline-none placeholder:text-vt-muted focus:border-[rgba(115,240,207,0.45)]"
                    value={copilotQuestion}
                    onChange={(event) => setCopilotQuestion(event.target.value)}
                    placeholder="Ask about top threats, a CVE, an asset, a malware hash, or remediation steps..."
                  />
                  <div className="flex flex-wrap gap-2">
                    {[
                      "What are the top threats?",
                      "Explain the most critical CVE.",
                      "Recommend actions for malware risk.",
                    ].map((prompt, index) => (
                      <button
                        key={`${prompt}-${index}`}
                        type="button"
                        className={ghostButtonClassName}
                        onClick={() => setCopilotQuestion(prompt)}
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <button type="button" className={primaryButtonClassName} onClick={handleCopilotSubmit} disabled={copilotLoading}>
                      {copilotLoading ? "Thinking..." : "Ask copilot"}
                    </button>
                    <button
                      type="button"
                      className={secondaryButtonClassName}
                      onClick={handleGenerateReport}
                      disabled={reportLoading}
                    >
                      {reportLoading ? "Generating..." : "Generate report"}
                    </button>
                  </div>

                  {copilotResult ? (
                    <div className="rounded-[24px] border border-white/6 bg-white/4 p-4">
                      <strong className="text-sm uppercase tracking-[0.12em] text-vt-accent">Copilot Answer</strong>
                      <p className="mt-3 text-sm leading-7 text-[#dbe7ff]">{copilotResult.answer}</p>
                      <div className="mt-4 grid gap-2 text-sm text-[#d7e2ff]">
                        {copilotResult.search_results?.slice(0, 3).map((item, index) => (
                          <div key={`${item.entity_type}-${item.title}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-3 py-2">
                            <strong className="block text-xs uppercase tracking-[0.12em] text-vt-muted">{item.entity_type}</strong>
                            <div className="mt-1 font-medium">{item.title}</div>
                            <p className="mt-1 text-vt-muted">{item.snippet}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  {reportResult ? (
                    <div className="rounded-[24px] border border-white/6 bg-white/4 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <strong className="text-sm uppercase tracking-[0.12em] text-vt-accent">{reportResult.title}</strong>
                        <span className="text-xs uppercase tracking-[0.12em] text-vt-muted">{reportResult.report_type}</span>
                      </div>
                      <p className="mt-3 text-sm leading-7 text-[#dbe7ff]">{reportResult.executive_summary}</p>
                      <div className="mt-4 space-y-3">
                        {reportResult.sections?.map((section, sectionIndex) => (
                          <div key={`${section.heading}-${sectionIndex}`} className="rounded-2xl border border-white/6 bg-white/4 px-3 py-2">
                            <strong className="block text-sm font-semibold">{section.heading}</strong>
                            <p className="mt-2 text-sm leading-7 text-vt-muted">{section.body}</p>
                            {Array.isArray(section.bullets) && section.bullets.length ? (
                              <ul className="mt-2 space-y-1 text-sm leading-7 text-[#d7e2ff]">
                                {section.bullets.map((bullet, bulletIndex) => (
                                  <li key={`${section.heading}-${sectionIndex}-${bulletIndex}`}>• {bullet}</li>
                                ))}
                              </ul>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </Panel>
            </motion.div>
          </div>

          {recentIncidents.length ? (
            <motion.section
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.44, delay: 0.28 }}
            >
              <Panel>
                <SectionHeading
                  eyebrow="Incidents"
                  title="Recent incidents"
                  description="Short-form summaries of the latest correlated events."
                />
                <div className="grid gap-3 lg:grid-cols-2">
                  {recentIncidents.map((incident, index) => (
                    <div key={`${incident.type}-${index}`} className="rounded-2xl border border-white/6 bg-white/4 px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <strong className="block text-sm font-semibold">{incident.title}</strong>
                          <p className="mt-1 text-xs uppercase tracking-[0.12em] text-vt-muted">{incident.type}</p>
                        </div>
                        <RiskBadge label={`${incident.severity} ${incident.risk_score}`} tone={severityTone(incident.severity)} />
                      </div>
                      <p className="mt-3 text-sm leading-7 text-[#d7e2ff]">{incident.when ? formatDateTime(incident.when) : "Time unavailable"}</p>
                    </div>
                  ))}
                </div>
              </Panel>
            </motion.section>
          ) : null}
        </>
      ) : null}
    </AppShell>
  );
}
