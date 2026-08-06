const TRUSTED_DOMAINS = ["google.com", "microsoft.com"];
const TRUSTED_FILE_NAMES = [
  "readme.md",
  "license",
  "license.txt",
  "package.json",
  "package-lock.json",
  "yarn.lock",
];

const PHISHING_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "password",
  "account",
  "confirm",
  "update",
];

function clampScore(score) {
  return Math.max(0, Math.min(100, score));
}

function isTrustedDomain(target) {
  try {
    const value = target.includes("://") ? target : `https://${target}`;
    const hostname = new URL(value).hostname.toLowerCase();
    return TRUSTED_DOMAINS.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    );
  } catch {
    return false;
  }
}

function isTrustedFileName(target) {
  const normalized = target.split(/[\\/]/).pop()?.toLowerCase() || "";
  return TRUSTED_FILE_NAMES.includes(normalized);
}

function hasRandomLookingString(target) {
  const compact = target.replace(/[^a-z0-9]/gi, "");
  return /([a-z0-9]{14,})/i.test(compact) && /[a-z]/i.test(compact) && /\d/.test(compact);
}

function keywordHits(text) {
  const lower = text.toLowerCase();
  return PHISHING_KEYWORDS.filter((keyword) => lower.includes(keyword)).length;
}

function parseMlOutput(mlOutput) {
  if (typeof mlOutput === "number" && Number.isFinite(mlOutput)) {
    return Math.max(0, Math.min(1, mlOutput));
  }
  if (mlOutput && typeof mlOutput === "object") {
    const candidate =
      mlOutput.probability ?? mlOutput.score ?? mlOutput.risk ?? mlOutput.confidence;
    if (typeof candidate === "number" && Number.isFinite(candidate)) {
      return Math.max(0, Math.min(1, candidate > 1 ? candidate / 100 : candidate));
    }
  }
  return null;
}

function calculateConfidence({
  detectionCount,
  mlProbability,
  suspiciousSignals,
  trustedSignals,
}) {
  const detectionFactor = Math.min(1, detectionCount / 6);
  const mlFactor = mlProbability ?? 0.5;
  const signalFactor = Math.max(0, Math.min(1, (suspiciousSignals - trustedSignals + 2) / 4));

  // Weighted blend: detections + ML output dominate, signals refine confidence.
  const confidence = Math.round(
    (detectionFactor * 0.45 + mlFactor * 0.45 + signalFactor * 0.1) * 100,
  );
  return Math.max(0, Math.min(100, confidence));
}

function buildDetails({
  riskLevel,
  trustedSignals,
  suspiciousSignals,
  keywordHitCount,
  hasRandomPattern,
}) {
  if (riskLevel === "safe") {
    if (trustedSignals > 0) {
      return "This item appears safe and matches trusted signals from known domains or file names.";
    }
    return "This item appears safe with no significant threat indicators.";
  }

  if (riskLevel === "low_risk") {
    if (trustedSignals > 0 && suspiciousSignals > 0) {
      return "This item appears low risk overall, but has minor issues that should still be noted.";
    }
    if (keywordHitCount > 0 || hasRandomPattern) {
      return "This item appears mostly safe, but it has minor suspicious patterns worth reviewing.";
    }
    return "This item appears low risk based on limited warning signals.";
  }

  if (riskLevel === "suspicious") {
    if (keywordHitCount > 0 && hasRandomPattern) {
      return "This item looks suspicious because multiple warning signals were observed.";
    }
    if (keywordHitCount > 0) {
      return "This item looks suspicious because it uses language often seen in phishing attempts.";
    }
    if (hasRandomPattern) {
      return "This item looks suspicious because the naming pattern appears random or obfuscated.";
    }
    return "This item shows multiple risk signals and should be reviewed before use.";
  }

  return "This item appears malicious based on strong high-risk indicators and should be isolated.";
}

export function analyzeThreat({
  target,
  reasons = [],
  baseScore = 0,
  baseRiskLevel = "unknown",
  detections = [],
  mlOutput = null,
}) {
  let score = Number.isFinite(baseScore) ? baseScore : 0;
  let trustedSignals = 0;
  let suspiciousSignals = 0;
  let strongSignals = 0;

  const safeTarget = String(target || "");
  const reasonsText = reasons.join(" ");
  const normalizedReasons = reasons.map((reason) => String(reason).toLowerCase());

  if (isTrustedDomain(safeTarget)) {
    trustedSignals += 1;
    score -= 18;
  }

  if (isTrustedFileName(safeTarget)) {
    trustedSignals += 1;
    score -= 12;
  }

  const randomPatternDetected = hasRandomLookingString(safeTarget);
  if (randomPatternDetected) {
    suspiciousSignals += 1;
    score += 16;
  }

  const hits = keywordHits(`${safeTarget} ${reasonsText}`);
  if (hits > 0) {
    suspiciousSignals += Math.min(2, hits);
    score += Math.min(24, hits * 8);
  }

  strongSignals += normalizedReasons.filter((reason) =>
    [
      "ip address used",
      "double extension detected",
      "suspicious behavior markers detected",
      "suspicious content keyword detected",
    ].includes(reason),
  ).length;

  // Keep risk balanced: only escalate strongly when multiple suspicious signals exist.
  if (suspiciousSignals >= 2 && trustedSignals === 0) {
    score += 8;
  }
  if (trustedSignals >= 1 && suspiciousSignals === 0) {
    score -= 6;
  }

  score = clampScore(score);

  let riskLevel = "unknown";
  if (trustedSignals > 0 && suspiciousSignals === 0 && score <= 20) {
    riskLevel = "safe";
  } else if (strongSignals >= 2 || score >= 75) {
    riskLevel = "malicious";
  } else if (strongSignals >= 1 || suspiciousSignals >= 2 || score > 50) {
    riskLevel = "suspicious";
  } else if (suspiciousSignals >= 1 || score > 20) {
    riskLevel = "low_risk";
  } else if (score <= 20) {
    riskLevel = "safe";
  } else {
    riskLevel = "low_risk";
  }

  // Preserve a high-risk backend label unless score became clearly low after trusted checks.
  const backendLevel = String(baseRiskLevel || "").toLowerCase();
  if (["critical", "high", "malicious", "infected"].includes(backendLevel) && score >= 45) {
    riskLevel = "malicious";
  } else if (["suspicious", "medium", "warning", "warn"].includes(backendLevel) && riskLevel === "low_risk") {
    riskLevel = "suspicious";
  } else if (["low", "low_risk", "low risk"].includes(backendLevel) && riskLevel === "safe") {
    riskLevel = "low_risk";
  }

  const confidence = calculateConfidence({
    detectionCount: Array.isArray(detections) ? detections.length : Number(detections) || 0,
    mlProbability: parseMlOutput(mlOutput),
    suspiciousSignals,
    trustedSignals,
  });

  const details = buildDetails({
    riskLevel,
    trustedSignals,
    suspiciousSignals,
    keywordHitCount: hits,
    hasRandomPattern: randomPatternDetected,
  });

  return { score, riskLevel, confidence, details };
}
