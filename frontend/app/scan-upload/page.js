"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { FileUp, Globe, LoaderCircle, Sparkles, UploadCloud, X } from "lucide-react";

import AppShell from "@/app/components/app-shell";
import {
  EmptyState,
  MetricCard,
  Panel,
  RiskBadge,
  SectionHeading,
  heroPanelClassName,
  primaryButtonClassName,
} from "@/app/components/ui";
import { createFileScan, createTargetScan, fetchScans } from "@/lib/api";
import { buildOverviewStats, formatDateTime, normalizeScan } from "@/lib/scan-model";
import { restoreSession } from "@/lib/session";
import { useMounted } from "@/lib/use-mounted";

function cx(...values) {
  return values.filter(Boolean).join(" ");
}

function reasonPillClass(reason, riskTone) {
  const label = String(reason).toLowerCase();

  if (
    label.includes("clean") ||
    label.includes("safe") ||
    label.includes("no issues") ||
    label.includes("no issue")
  ) {
    return "border-[rgba(82,224,162,0.24)] bg-[rgba(82,224,162,0.12)] text-[#d8fff0]";
  }

  if (
    label.includes("malicious") ||
    label.includes("infected") ||
    label.includes("trojan") ||
    label.includes("ransom") ||
    label.includes("payload")
  ) {
    return "border-[rgba(255,93,118,0.26)] bg-[rgba(255,93,118,0.14)] text-[#ffdce2]";
  }

  if (
    label.includes("suspicious") ||
    label.includes("macro") ||
    label.includes("script") ||
    label.includes("obfus") ||
    label.includes("network") ||
    label.includes("unsigned") ||
    label.includes("untrusted")
  ) {
    return "border-[rgba(255,143,90,0.26)] bg-[rgba(255,143,90,0.14)] text-[#ffe7cf]";
  }

  if (riskTone === "danger") {
    return "border-[rgba(255,93,118,0.26)] bg-[rgba(255,93,118,0.14)] text-[#ffdce2]";
  }

  if (riskTone === "warning" || riskTone === "watch") {
    return "border-[rgba(255,185,90,0.24)] bg-[rgba(255,185,90,0.14)] text-[#ffeec0]";
  }

  return "border-white/10 bg-white/7 text-[#dce8ff]";
}

function resultAccentClasses(tone) {
  if (tone === "danger") {
    return {
      badge: "border-[rgba(255,93,118,0.28)] bg-[rgba(255,93,118,0.16)] text-[#ffdce2]",
      glow: "from-[rgba(255,93,118,0.18)] via-[rgba(255,93,118,0.06)] to-transparent",
      ring: "#ff5d76",
    };
  }

  if (tone === "warning") {
    return {
      badge: "border-[rgba(255,143,90,0.28)] bg-[rgba(255,143,90,0.16)] text-[#ffe7cf]",
      glow: "from-[rgba(255,143,90,0.18)] via-[rgba(255,185,90,0.07)] to-transparent",
      ring: "#ff9d59",
    };
  }

  if (tone === "watch") {
    return {
      badge: "border-[rgba(255,185,90,0.28)] bg-[rgba(255,185,90,0.16)] text-[#fff0ca]",
      glow: "from-[rgba(255,185,90,0.16)] via-[rgba(255,185,90,0.06)] to-transparent",
      ring: "#ffb95a",
    };
  }

  return {
    badge: "border-[rgba(82,224,162,0.28)] bg-[rgba(82,224,162,0.14)] text-[#d8fff0]",
    glow: "from-[rgba(82,224,162,0.18)] via-[rgba(115,240,207,0.08)] to-transparent",
    ring: "#52e0a2",
  };
}

function buildAiExplanation(scan) {
  const assetLabel = scan.targetType === "file" ? "file" : "URL";
  const topReasons = scan.reasons.slice(0, 3);
  const reasonText = topReasons.length ? topReasons.join(", ") : "no additional reasons were returned";

  if (scan.risk.key === "malicious") {
    return `This ${assetLabel} is considered malicious because the scanner found high-risk indicators such as ${reasonText}. It should not be trusted until manually reviewed.`;
  }

  if (scan.risk.key === "suspicious" || scan.risk.key === "low_risk") {
    return `This ${assetLabel} is considered suspicious because the scanner detected warning signals such as ${reasonText}. The result is not fully benign and should be reviewed before use.`;
  }

  if (scan.risk.key === "safe") {
    return `This ${assetLabel} is considered safe because the scanner did not find strong malicious indicators. The current result leans benign, with ${reasonText}.`;
  }

  return `This ${assetLabel} needs manual review because the backend did not return a definitive classification and provided ${reasonText}.`;
}

function ScoreRing({ score, tone }) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeScore / 100) * circumference;
  const accent = resultAccentClasses(tone).ring;

  return (
    <div className="relative grid h-[156px] w-[156px] place-items-center">
      <svg className="h-[156px] w-[156px] -rotate-90" viewBox="0 0 140 140" aria-hidden="true">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" />
        <motion.circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={accent}
          strokeWidth="12"
          strokeLinecap="round"
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 0.9, ease: "easeOut" }}
          strokeDasharray={circumference}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-[2.35rem] font-semibold tracking-[-0.05em]">{safeScore}</div>
          <div className="text-[0.72rem] uppercase tracking-[0.18em] text-vt-muted">Score</div>
        </div>
      </div>
    </div>
  );
}

export default function ScanUploadPage() {
  const router = useRouter();
  const mounted = useMounted();
  const inputRef = useRef(null);
  const [user, setUser] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [urlValue, setUrlValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [analysisLabel, setAnalysisLabel] = useState("Analyzing file...");
  const [result, setResult] = useState(null);

  useEffect(() => {
    async function loadExistingScans() {
      try {
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
      }
    }

    loadExistingScans();
  }, [router]);

  if (!mounted) {
    return <main className="grid min-h-screen place-items-center text-vt-muted">Loading scanner...</main>;
  }

  const stats = buildOverviewStats(scans);

  function handleFileSelection(file) {
    if (!file) {
      return;
    }

    setSelectedFile(file);
    setError("");
  }

  async function handleScan() {
    if (!user) {
      return;
    }

    if (!selectedFile && !urlValue.trim()) {
      setError("Upload a file or enter a URL before scanning.");
      return;
    }

    setSubmitting(true);
    setError("");
    setProgress(7);
    setResult(null);
    setAnalysisLabel(selectedFile ? "Analyzing file..." : "Analyzing URL...");

    const timer = setInterval(() => {
      setProgress((current) => {
        if (current >= 94) {
          return current;
        }
        return current + Math.max(2, Math.round(Math.random() * 8));
      });
    }, 220);

    const startedAt = Date.now();

    try {
      const response = selectedFile
        ? await createFileScan(user.id, selectedFile)
        : await createTargetScan({
            user_id: user.id,
            target_type: "url",
            target_value: urlValue.trim(),
          });

      const elapsed = Date.now() - startedAt;
      if (elapsed < 1000) {
        await new Promise((resolve) => setTimeout(resolve, 1000 - elapsed));
      }

      const normalized = normalizeScan(response);
      setScans((current) => [normalized, ...current]);
      setProgress(100);
      setResult(normalized);
      setSelectedFile(null);
      if (inputRef.current) {
        inputRef.current.value = "";
      }
      if (!selectedFile) {
        setUrlValue("");
      }
    } catch (requestError) {
      setError(requestError.message);
      setProgress(0);
    } finally {
      clearInterval(timer);
      setTimeout(() => {
        setSubmitting(false);
      }, 180);
    }
  }

  const resultAccent = result ? resultAccentClasses(result.risk.tone) : null;

  return (
    <AppShell
      user={user}
      eyebrow="AI Malware Scanner"
      title="Scan a file or URL"
      subtitle="Upload a suspicious file or paste a URL, then review the backend verdict, score, reasons, and history from one streamlined experience."
      status={submitting ? "Scan in progress" : "Ready to analyze"}
      actions={null}
    >
      <motion.section
        className={cx(heroPanelClassName, "mx-auto w-full max-w-[960px]")}
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, ease: "easeOut" }}
      >
        <div className="mb-6 text-center">
          <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
            Main Experience
          </div>
          <h2 className="mt-3 text-[clamp(2rem,4vw,3.35rem)] font-semibold leading-[0.98] tracking-[-0.05em]">
            Drop a file or paste a URL, then let the scanner do the rest.
          </h2>
          <p className="mx-auto mt-4 max-w-[58ch] text-base leading-8 text-vt-muted">
            This screen is optimized for the core product flow: one input surface, one
            scan action, one animated result card.
          </p>
        </div>

        <div className="mx-auto w-full max-w-[760px] rounded-[30px] border border-vt-line bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.03))] p-6 shadow-[0_26px_70px_rgba(2,6,23,0.36)] backdrop-blur-[24px] sm:p-8">
          <button
            type="button"
            className={cx(
              "group relative grid w-full gap-3 rounded-[26px] border border-dashed px-6 py-8 text-left transition duration-300",
              dragActive
                ? "border-vt-accent bg-[rgba(115,240,207,0.10)] shadow-[0_0_0_6px_rgba(115,240,207,0.08)]"
                : "border-white/14 bg-[rgba(255,255,255,0.04)] hover:border-vt-line-strong hover:bg-[rgba(255,255,255,0.06)]",
            )}
            onDragEnter={(event) => {
              event.preventDefault();
              setDragActive(true);
            }}
            onDragOver={(event) => {
              event.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={(event) => {
              event.preventDefault();
              if (event.currentTarget === event.target) {
                setDragActive(false);
              }
            }}
            onDrop={(event) => {
              event.preventDefault();
              setDragActive(false);
              handleFileSelection(event.dataTransfer.files?.[0] || null);
            }}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              className="hidden"
              onChange={(event) => handleFileSelection(event.target.files?.[0] || null)}
            />

            <div className="mx-auto grid h-16 w-16 place-items-center rounded-[22px] bg-[linear-gradient(135deg,rgba(115,240,207,0.18),rgba(121,168,255,0.16))] text-vt-accent shadow-[inset_0_1px_0_rgba(255,255,255,0.16)] transition duration-300 group-hover:scale-[1.03]">
              <UploadCloud size={28} />
            </div>
            <div className="text-center">
              <div className="text-[1.12rem] font-semibold tracking-[-0.02em]">
                Drag and drop a file here
              </div>
              <div className="mt-2 text-sm leading-7 text-vt-muted">
                or click to browse from your device
              </div>
            </div>
          </button>

          {selectedFile ? (
            <div className="mt-4 flex items-center justify-between gap-3 rounded-[20px] border border-vt-line bg-white/5 px-4 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl bg-[rgba(115,240,207,0.12)] text-vt-accent">
                  <FileUp size={18} />
                </div>
                <div className="min-w-0">
                  <div className="truncate font-medium">{selectedFile.name}</div>
                  <div className="text-sm text-vt-muted">
                    {(selectedFile.size / 1024).toFixed(1)} KB ready to analyze
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="rounded-full border border-white/10 bg-white/6 p-2 text-vt-muted transition duration-300 hover:bg-white/10 hover:text-vt-text"
                onClick={() => {
                  setSelectedFile(null);
                  if (inputRef.current) {
                    inputRef.current.value = "";
                  }
                }}
                aria-label="Remove selected file"
              >
                <X size={16} />
              </button>
            </div>
          ) : null}

          <div className="my-5 flex items-center gap-4">
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-white/10 to-white/10" />
            <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-muted">or scan a URL</div>
            <div className="h-px flex-1 bg-gradient-to-l from-transparent via-white/10 to-white/10" />
          </div>

          <div className="grid gap-3">
            <label htmlFor="url_input" className="text-[0.82rem] font-bold uppercase tracking-[0.14em] text-[#d8e4ff]">
              URL
            </label>
            <div className="flex items-center gap-3 rounded-[20px] border border-vt-line bg-[rgba(3,10,21,0.54)] px-4 py-3.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
              <Globe size={18} className="shrink-0 text-vt-muted" />
              <input
                id="url_input"
                type="url"
                value={urlValue}
                onChange={(event) => setUrlValue(event.target.value)}
                placeholder="https://example.com"
                className="w-full bg-transparent text-vt-text outline-none placeholder:text-slate-500"
              />
            </div>
          </div>

          {error ? (
            <div className="mt-5 rounded-2xl border border-[rgba(255,93,118,0.2)] bg-[rgba(255,93,118,0.1)] px-4 py-3 text-[#ffd9de]">
              {error}
            </div>
          ) : null}

          <button
            type="button"
            className={cx(primaryButtonClassName, "mt-6 h-14 w-full text-base")}
            disabled={submitting}
            onClick={handleScan}
          >
            {selectedFile ? <FileUp size={18} /> : <Globe size={18} />}
            Scan Now
          </button>

          <AnimatePresence>
            {submitting ? (
              <motion.div
                className="mt-5 rounded-[24px] border border-vt-line bg-[rgba(255,255,255,0.05)] p-5"
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.25, ease: "easeOut" }}
              >
                <div className="flex items-center gap-3">
                  <div className="grid h-12 w-12 place-items-center rounded-2xl bg-[rgba(115,240,207,0.12)] text-vt-accent">
                    <LoaderCircle size={22} className="animate-spin" />
                  </div>
                  <div>
                    <div className="font-semibold">{analysisLabel}</div>
                    <div className="text-sm text-vt-muted">
                      The backend is processing the current asset and preparing a verdict.
                    </div>
                  </div>
                </div>

                <div className="mt-5 h-3 overflow-hidden rounded-full bg-white/8">
                  <motion.div
                    className="h-full rounded-full bg-[linear-gradient(90deg,var(--color-vt-accent)_0%,var(--color-vt-accent-cool)_55%,var(--color-vt-accent-warm)_100%)]"
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.25, ease: "easeOut" }}
                  />
                </div>
                <div className="mt-3 text-right text-sm text-vt-muted">{progress}%</div>
              </motion.div>
            ) : null}
          </AnimatePresence>
        </div>
      </motion.section>

      <AnimatePresence>
        {result && !submitting ? (
          <motion.section
            className="mx-auto w-full max-w-[960px]"
            initial={{ opacity: 0, scale: 0.96, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: 12 }}
            transition={{ duration: 0.38, ease: "easeOut" }}
          >
            <Panel className="relative overflow-hidden">
              <div className={cx("pointer-events-none absolute inset-0 bg-gradient-to-br opacity-90", resultAccent.glow)} />
              <div className="relative">
                <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
                      Scan Result
                    </div>
                    <h3 className="mt-2 text-[clamp(1.9rem,3vw,2.7rem)] font-semibold tracking-[-0.04em]">
                      {result.targetValue}
                    </h3>
                    <p className="mt-3 max-w-[56ch] text-sm leading-7 text-vt-muted">
                      Completed on {formatDateTime(result.createdAt)} as a {result.targetType} scan.
                    </p>
                  </div>

                  <div className={cx("inline-flex rounded-full border px-5 py-3 text-sm font-bold uppercase tracking-[0.18em]", resultAccent.badge)}>
                    {result.risk.label}
                  </div>
                </div>

                <div className="mt-8 grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
                  <div className="flex flex-col items-center justify-center rounded-[28px] border border-vt-line bg-[linear-gradient(180deg,rgba(255,255,255,0.07),rgba(255,255,255,0.03))] p-5 shadow-[0_18px_44px_rgba(2,6,23,0.26)]">
                    <ScoreRing score={result.score} tone={result.risk.tone} />
                    <div className="mt-2 text-sm text-vt-muted">Backend risk score</div>
                  </div>

                  <div className="grid gap-5">
                    <div className="rounded-[24px] border border-vt-line bg-[linear-gradient(180deg,rgba(255,255,255,0.06),rgba(255,255,255,0.03))] p-5">
                      <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
                        Reasons
                      </div>
                      <div className="mt-4 flex flex-wrap gap-3">
                        {result.reasons.map((reason, index) => (
                          <span
                            key={`${result.id}-reason-pill-${index}`}
                            className={cx(
                              "inline-flex rounded-full border px-4 py-2 text-sm font-medium",
                              reasonPillClass(reason, result.risk.tone),
                            )}
                          >
                            {reason}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="rounded-[24px] border border-vt-line bg-[linear-gradient(180deg,rgba(255,255,255,0.06),rgba(255,255,255,0.03))] p-5">
                      <div className="inline-flex items-center gap-2 text-[0.72rem] font-bold uppercase tracking-[0.18em] text-vt-accent">
                        <Sparkles size={14} />
                        AI Explanation
                      </div>
                      <p className="mt-4 text-sm leading-8 text-[#dbe7ff]">
                        {buildAiExplanation(result)}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </Panel>
          </motion.section>
        ) : null}
      </AnimatePresence>

      <Panel className="mx-auto w-full max-w-[1100px]">
        <SectionHeading
          eyebrow="History"
          title="Scan history"
          description="Every completed file or URL scan is recorded here for quick review."
        />

        <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Total scans" value={stats.total} helper="Files and URLs scanned by this user" tone="accent" />
          <MetricCard label="Malicious" value={stats.malicious} helper="High-risk verdicts" tone="danger" />
          <MetricCard label="Suspicious" value={stats.suspicious + stats.lowRisk} helper="Results still worth reviewing" tone="warning" />
          <MetricCard label="Safe" value={stats.safe} helper="Low-risk or clean outcomes" tone="safe" />
        </div>

        {scans.length ? (
          <div className="overflow-hidden rounded-[24px] border border-vt-line bg-white/3">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] border-collapse">
                <thead>
                  <tr className="bg-white/3">
                    {["Asset", "Verdict", "Score", "Created"].map((header, index) => (
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
                  {scans.slice(0, 10).map((scan) => (
                    <tr key={scan.id} className="transition hover:bg-white/3">
                      <td className="border-b border-white/6 px-[18px] py-4 align-top">
                        <div className="grid gap-1">
                          <strong className="text-[0.98rem] font-semibold">{scan.targetValue}</strong>
                          <small className="text-vt-muted">{scan.targetType} scan</small>
                        </div>
                      </td>
                      <td className="border-b border-white/6 px-[18px] py-4 align-top">
                        <RiskBadge label={scan.risk.label} tone={scan.risk.tone} />
                      </td>
                      <td className="border-b border-white/6 px-[18px] py-4 align-top">{scan.score}</td>
                      <td className="border-b border-white/6 px-[18px] py-4 align-top">{formatDateTime(scan.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <EmptyState
            title="No scan history yet"
            description="Your previous file and URL scans will appear here after the first successful analysis."
          />
        )}
      </Panel>
    </AppShell>
  );
}
