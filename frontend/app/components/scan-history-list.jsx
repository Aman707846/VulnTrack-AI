"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, ChevronUp } from "lucide-react";

import { EmptyState, Panel, RiskBadge, SectionHeading } from "@/app/components/ui";
import { formatDateTime } from "@/lib/scan-model";

function historyCardClass() {
  return "rounded-[24px] border border-white/6 bg-[linear-gradient(180deg,rgba(255,255,255,0.07),rgba(255,255,255,0.03))] p-5 shadow-[0_18px_40px_rgba(2,6,23,0.24)] transition duration-300 hover:border-vt-line-strong hover:bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.04))]";
}

function detailCardClass() {
  return "rounded-[20px] border border-white/6 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.03))] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]";
}

function reasonPillClass(riskTone) {
  if (riskTone === "danger") {
    return "border-[rgba(255,93,118,0.26)] bg-[rgba(255,93,118,0.14)] text-[#ffdce2]";
  }
  if (riskTone === "warning") {
    return "border-[rgba(255,143,90,0.26)] bg-[rgba(255,143,90,0.14)] text-[#ffe7cf]";
  }
  if (riskTone === "watch") {
    return "border-[rgba(255,185,90,0.24)] bg-[rgba(255,185,90,0.14)] text-[#ffeec0]";
  }
  return "border-[rgba(82,224,162,0.24)] bg-[rgba(82,224,162,0.12)] text-[#d8fff0]";
}

export default function ScanHistoryList({
  scans,
  eyebrow = "History",
  title = "Scan history",
  description = "Click any item to expand and inspect its details.",
  aside,
}) {
  const [expandedScanId, setExpandedScanId] = useState(null);

  return (
    <Panel>
      <SectionHeading eyebrow={eyebrow} title={title} description={description} aside={aside} />

      {scans.length ? (
        <div className="grid gap-4">
          {scans.map((scan) => {
            const expanded = expandedScanId === scan.id;

            return (
              <div key={scan.id} className={historyCardClass()}>
                <button
                  type="button"
                  className="flex w-full items-start justify-between gap-4 text-left"
                  onClick={() =>
                    setExpandedScanId((current) => (current === scan.id ? null : scan.id))
                  }
                >
                  <div className="min-w-0">
                    <div className="truncate text-[1.02rem] font-semibold">{scan.targetValue}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-vt-muted">
                      <span>{scan.targetType} scan</span>
                      <span>Score {scan.score}</span>
                      <span>{formatDateTime(scan.createdAt)}</span>
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-3">
                    <RiskBadge label={scan.risk.label} tone={scan.risk.tone} />
                    <span className="rounded-full border border-white/10 bg-white/6 p-2 text-vt-muted">
                      {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </span>
                  </div>
                </button>

                <AnimatePresence initial={false}>
                  {expanded ? (
                    <motion.div
                      initial={{ opacity: 0, height: 0, y: -6 }}
                      animate={{ opacity: 1, height: "auto", y: 0 }}
                      exit={{ opacity: 0, height: 0, y: -6 }}
                      transition={{ duration: 0.22, ease: "easeOut" }}
                      className="overflow-hidden"
                    >
                      <div className="mt-5 grid gap-4 border-t border-white/8 pt-5 lg:grid-cols-[220px_minmax(0,1fr)]">
                        <div className="grid gap-4">
                          <div className={detailCardClass()}>
                            <span className="block text-[0.78rem] uppercase tracking-[0.14em] text-vt-muted">
                              Verdict
                            </span>
                            <div className="mt-3">
                              <RiskBadge label={scan.risk.label} tone={scan.risk.tone} />
                            </div>
                          </div>
                          <div className={detailCardClass()}>
                            <span className="block text-[0.78rem] uppercase tracking-[0.14em] text-vt-muted">
                              Score
                            </span>
                            <strong className="mt-3 block text-[1.5rem] font-semibold">{scan.score}</strong>
                          </div>
                          <div className={detailCardClass()}>
                            <span className="block text-[0.78rem] uppercase tracking-[0.14em] text-vt-muted">
                              Time
                            </span>
                            <strong className="mt-3 block text-base font-semibold">{formatDateTime(scan.createdAt)}</strong>
                          </div>
                        </div>

                        <div className="grid gap-4">
                          <div className={detailCardClass()}>
                            <span className="block text-[0.78rem] uppercase tracking-[0.14em] text-vt-muted">
                              Summary
                            </span>
                            <p className="mt-3 text-sm leading-7 text-vt-muted">
                              {scan.details ||
                                "No narrative summary was returned by the backend, so the result should be reviewed using the score and reasons below."}
                            </p>
                          </div>

                          <div className={detailCardClass()}>
                            <span className="block text-[0.78rem] uppercase tracking-[0.14em] text-vt-muted">
                              Reasons
                            </span>
                            <div className="mt-4 flex flex-wrap gap-3">
                              {scan.reasons.map((reason, index) => (
                                <span
                                  key={`${scan.id}-reason-${index}`}
                                  className={`inline-flex rounded-full border px-4 py-2 text-sm font-medium ${reasonPillClass(scan.risk.tone)}`}
                                >
                                  {reason}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ) : null}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState
          title="No scan history yet"
          description="Run a file or URL scan to populate the history view."
        />
      )}
    </Panel>
  );
}
