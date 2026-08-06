const SEVERITY_ORDER = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  unknown: -1,
};

function clampScore(value) {
  const num = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(num)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(num)));
}

export function formatDateTime(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown time";
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatShortDay(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
  }).format(date);
}

export function normalizeReasons(reasons) {
  if (Array.isArray(reasons) && reasons.length > 0) {
    return reasons.map((reason) => String(reason));
  }

  if (typeof reasons === "string" && reasons.trim()) {
    return [reasons];
  }

  return [];
}

export function mapRisk(rawLevel) {
  const level = String(rawLevel ?? "unknown").toLowerCase();

  if (["critical", "high", "infected", "malicious", "danger"].includes(level)) {
    return { key: "malicious", label: "Malicious", tone: "danger" };
  }

  if (["suspicious", "medium", "warning", "warn"].includes(level)) {
    return { key: "suspicious", label: "Suspicious", tone: "warning" };
  }

  if (["low", "low_risk", "low risk"].includes(level)) {
    return { key: "low_risk", label: "Low Risk", tone: "watch" };
  }

  if (["safe", "clean", "benign", "ok"].includes(level)) {
    return { key: "safe", label: "Safe", tone: "safe" };
  }

  return { key: "unknown", label: "Unknown", tone: "neutral" };
}

export function normalizeScan(rawScan) {
  const scan = rawScan?.scan ?? rawScan ?? {};
  const results = Array.isArray(scan.results) ? scan.results : [];
  const vulnerabilities = Array.isArray(scan.vulnerabilities) ? scan.vulnerabilities : [];
  const directReasons = normalizeReasons(scan.reasons ?? scan.reason_list ?? scan.findings);
  const derivedReasons = results
    .map((result) => String(result?.details ?? result?.verdict ?? ""))
    .filter(Boolean);
  const reasons = directReasons.length ? directReasons : derivedReasons;
  const risk = mapRisk(
    scan.risk_level ??
      scan.riskLevel ??
      scan.verdict ??
      results[0]?.verdict ??
      scan.results?.[0]?.risk_level,
  );

  let score = clampScore(
    scan.score ??
      scan.risk_score ??
      results[0]?.score ??
      results[0]?.risk_score ??
      (risk.key === "malicious"
        ? 91
        : risk.key === "suspicious"
          ? 66
          : risk.key === "low_risk"
            ? 34
            : risk.key === "safe"
              ? 12
              : 22),
  );

  if (!score && risk.key === "malicious") {
    score = 91;
  }

  const confidenceRaw = scan.confidence;
  const confidence = Number.isFinite(Number(confidenceRaw))
    ? clampScore(confidenceRaw)
    : null;

  const targetValue = String(
    scan.target_value ?? scan.target ?? scan.file_name ?? scan.filename ?? "Unknown target",
  );

  return {
    id: String(scan.id ?? `${targetValue}-${scan.created_at ?? Date.now()}`),
    targetType: String(scan.target_type ?? (scan.file_name || scan.filename ? "file" : "target")),
    targetValue,
    createdAt: scan.created_at ?? scan.createdAt ?? new Date().toISOString(),
    risk,
    score,
    confidence,
    reasons: reasons.length ? reasons : ["No supporting indicators were returned by the backend."],
    vulnerabilities,
    results,
    details: typeof scan.details === "string" ? scan.details : "",
    raw: scan,
  };
}

export function buildOverviewStats(scans) {
  const base = {
    total: scans.length,
    malicious: 0,
    suspicious: 0,
    lowRisk: 0,
    safe: 0,
    avgScore: 0,
    vulnerabilities: 0,
  };

  let totalScore = 0;

  for (const scan of scans) {
    totalScore += clampScore(scan.score);
    base.vulnerabilities += Array.isArray(scan.vulnerabilities) ? scan.vulnerabilities.length : 0;

    if (scan.risk.key === "malicious") {
      base.malicious += 1;
    } else if (scan.risk.key === "suspicious") {
      base.suspicious += 1;
    } else if (scan.risk.key === "low_risk") {
      base.lowRisk += 1;
    } else if (scan.risk.key === "safe") {
      base.safe += 1;
    }
  }

  return {
    ...base,
    avgScore: scans.length ? Math.round(totalScore / scans.length) : 0,
  };
}

export function buildRiskDistribution(scans) {
  const counts = {
    Safe: 0,
    "Low Risk": 0,
    Suspicious: 0,
    Malicious: 0,
    Unknown: 0,
  };

  for (const scan of scans) {
    counts[scan.risk.label] = (counts[scan.risk.label] ?? 0) + 1;
  }

  return [
    { name: "Safe", value: counts.Safe, color: "#3ddc97" },
    { name: "Low Risk", value: counts["Low Risk"], color: "#ffca6b" },
    { name: "Suspicious", value: counts.Suspicious, color: "#ff8f5a" },
    { name: "Malicious", value: counts.Malicious, color: "#ff5d76" },
    { name: "Unknown", value: counts.Unknown, color: "#7f8aa3" },
  ].filter((item) => item.value > 0);
}

function dayKey(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(
    date.getUTCDate(),
  ).padStart(2, "0")}`;
}

export function buildTrendSeries(scans, days = 7) {
  const today = new Date();
  const start = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
  start.setUTCDate(start.getUTCDate() - (days - 1));

  const lookup = new Map();

  for (const scan of scans) {
    const key = dayKey(scan.createdAt);
    if (!key) {
      continue;
    }

    const current = lookup.get(key) ?? { total: 0, suspicious: 0, malicious: 0 };
    current.total += 1;
    if (scan.risk.key === "suspicious") {
      current.suspicious += 1;
    }
    if (scan.risk.key === "malicious") {
      current.malicious += 1;
    }
    lookup.set(key, current);
  }

  const rows = [];
  for (let index = 0; index < days; index += 1) {
    const date = new Date(start);
    date.setUTCDate(start.getUTCDate() + index);
    const key = dayKey(date);
    const current = lookup.get(key) ?? { total: 0, suspicious: 0, malicious: 0 };
    rows.push({
      date: date.toISOString(),
      total: current.total,
      suspicious: current.suspicious,
      malicious: current.malicious,
    });
  }

  return rows;
}

export function buildReasonDigest(scans, limit = 5) {
  const counts = new Map();

  for (const scan of scans) {
    for (const reason of Array.isArray(scan.reasons) ? scan.reasons : []) {
      const label = String(reason).trim();
      if (!label) {
        continue;
      }
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
  }

  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
    .slice(0, limit);
}

export function flattenVulnerabilities(scans) {
  return scans
    .flatMap((scan) =>
      (Array.isArray(scan.vulnerabilities) ? scan.vulnerabilities : []).map((item) => ({
        id: item.id ?? `${scan.id}-${item.cve_id ?? item.title ?? Math.random()}`,
        cveId: item.cve_id ?? item.title ?? "Unlabeled finding",
        severity: String(item.severity ?? "unknown").toLowerCase(),
        summary: item.summary ?? item.description ?? "No vulnerability summary returned.",
        targetValue: scan.targetValue,
        risk: scan.risk,
      })),
    )
    .sort((left, right) => {
      const severityDelta =
        (SEVERITY_ORDER[right.severity] ?? SEVERITY_ORDER.unknown) -
        (SEVERITY_ORDER[left.severity] ?? SEVERITY_ORDER.unknown);

      if (severityDelta !== 0) {
        return severityDelta;
      }

      return left.cveId.localeCompare(right.cveId);
    });
}

export function getPriorityScans(scans, limit = 6) {
  return [...scans]
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
    })
    .slice(0, limit);
}

export function buildPostureCopy(stats) {
  if (stats.malicious > 0) {
    return "Immediate containment recommended for the highest-risk findings in the queue.";
  }
  if (stats.suspicious > 0 || stats.lowRisk > 0) {
    return "The environment is stable, but analyst review is still required for flagged assets.";
  }
  if (stats.total > 0) {
    return "Recent scans indicate a clean baseline with no active escalations.";
  }
  return "No scan telemetry has been captured yet. Start an intake to populate analyst views.";
}
