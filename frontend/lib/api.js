"use client";

import { getApiBaseUrl } from "./config";
import { analyzeThreat } from "./threat-analyzer";

function formatErrorDetail(detail) {
  if (!detail) {
    return "Request failed.";
  }

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }

        const location = Array.isArray(item?.loc) ? item.loc.filter(Boolean).join(".") : "";
        const message = item?.msg || item?.message || "Invalid request.";
        return location ? `${location}: ${message}` : message;
      })
      .join(" ");
  }

  if (typeof detail === "object" && detail.message) {
    return String(detail.message);
  }

  return "Request failed.";
}

async function parseResponse(response) {
  const text = await response.text();
  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      if (!response.ok) {
        throw new Error(
          response.status >= 500
            ? "The backend is unavailable. Start the FastAPI server on port 8001 and try again."
            : "Request failed.",
        );
      }
    }
  }

  if (!response.ok) {
    throw new Error(formatErrorDetail(data?.detail));
  }

  return data;
}

async function request(path, options = {}) {
  const apiBaseUrl = getApiBaseUrl();
  const headers = new Headers(options.headers || {});

  try {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      ...options,
      headers,
      credentials: "include",
    });
    return parseResponse(response);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(
        `Cannot reach the backend at ${apiBaseUrl}. Start the FastAPI server and try again.`,
      );
    }

    throw error;
  }
}

function enrichScanWithConfidence(scan) {
  if (!scan || typeof scan !== "object") {
    return scan;
  }

  if (typeof scan.confidence === "number" && typeof scan.details === "string") {
    return scan;
  }

  const reasonsRaw = scan.reasons ?? scan.reason_list ?? scan.findings ?? [];
  const normalizedReasons = Array.isArray(reasonsRaw)
    ? reasonsRaw.map((reason) => String(reason))
    : [String(reasonsRaw)];

  const analyzed = analyzeThreat({
    target: scan.target ?? scan.target_value ?? "",
    reasons: normalizedReasons,
    baseScore: Number(scan.score ?? scan.risk_score ?? 0),
    baseRiskLevel: scan.risk_level ?? scan.riskLevel ?? "unknown",
    detections: scan.detections ?? scan.results ?? [],
    mlOutput: scan.ml_output ?? scan.mlOutput ?? scan.model_output ?? null,
  });

  return {
    ...scan,
    confidence:
      typeof scan.confidence === "number" ? Math.max(0, Math.min(100, scan.confidence)) : analyzed.confidence,
    details: typeof scan.details === "string" && scan.details.trim() ? scan.details : analyzed.details,
  };
}

function enrichResponseWithConfidence(payload) {
  if (!payload || typeof payload !== "object") {
    return payload;
  }

  if (Array.isArray(payload.scans)) {
    return {
      ...payload,
      scans: payload.scans.map(enrichScanWithConfidence),
    };
  }

  if (payload.scan && typeof payload.scan === "object") {
    return {
      ...payload,
      scan: enrichScanWithConfidence(payload.scan),
    };
  }

  if (Array.isArray(payload)) {
    return payload.map(enrichScanWithConfidence);
  }

  if ("target" in payload || "target_value" in payload || "risk_score" in payload || "score" in payload) {
    return enrichScanWithConfidence(payload);
  }

  return payload;
}

export async function loginUser(payload) {
  return request("/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function registerUser(payload) {
  return request("/auth/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function logoutUser() {
  return request("/auth/logout", {
    method: "POST",
  });
}

export async function fetchCurrentUser() {
  return request("/auth/me", {
    cache: "no-store",
  });
}

export async function fetchRoles() {
  return request("/rbac/roles", {
    cache: "no-store",
  });
}

export async function fetchUsers(organizationId = null) {
  const query = organizationId ? `?organization_id=${organizationId}` : "";
  return request(`/rbac/users${query}`, {
    cache: "no-store",
  });
}

export async function assignUserRole(userId, roleId) {
  return request(`/rbac/users/${userId}/role`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ role_id: roleId }),
  });
}

export async function fetchOrganizations() {
  return request("/organizations", {
    cache: "no-store",
  });
}

export async function createOrganization(payload) {
  return request("/organizations", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function updateOrganization(organizationId, payload) {
  return request(`/organizations/${organizationId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function deleteOrganization(organizationId) {
  return request(`/organizations/${organizationId}`, {
    method: "DELETE",
  });
}

export async function fetchScans(userId) {
  const query = userId ? `?user_id=${userId}` : "";
  const response = await request(`/scans${query}`, {
    cache: "no-store",
  });
  return enrichResponseWithConfidence(response);
}

export async function createTargetScan(payload) {
  const response = await request("/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  return enrichResponseWithConfidence(response);
}

export async function createFileScan(userId, file) {
  const formData = new FormData();
  formData.append("user_id", String(userId));
  formData.append("file", file);

  const response = await request("/scan/file", {
    method: "POST",
    body: formData,
  });
  return enrichResponseWithConfidence(response);
}

export async function analyzeMalwareFile(userId, file, forceRefresh = false) {
  const formData = new FormData();
  if (userId !== null && userId !== undefined) {
    formData.append("user_id", String(userId));
  }
  formData.append("file", file);
  formData.append("force_refresh", forceRefresh ? "true" : "false");

  return request("/api/files/analyze", {
    method: "POST",
    body: formData,
  });
}

export async function fetchMalwareFileById(fileId) {
  return request(`/api/files/${fileId}`, {
    cache: "no-store",
  });
}

export async function fetchMalwareFileByHash(sha256, refresh = false, userId = null) {
  const query = new URLSearchParams();
  if (refresh) {
    query.set("refresh", "true");
  }
  if (userId !== null && userId !== undefined) {
    query.set("user_id", String(userId));
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/api/files/hash/${sha256}${suffix}`, {
    cache: "no-store",
  });
}

export async function fetchMalwareReputation(sha256, refresh = false, userId = null) {
  const query = new URLSearchParams();
  if (refresh) {
    query.set("refresh", "true");
  }
  if (userId !== null && userId !== undefined) {
    query.set("user_id", String(userId));
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/api/files/reputation/${sha256}${suffix}`, {
    cache: "no-store",
  });
}

export async function fetchMalwareDashboard() {
  return request("/api/dashboard/malware-intelligence", {
    cache: "no-store",
  });
}

export async function fetchThreatIntelDashboard() {
  return request("/api/dashboard/threat-intelligence", {
    cache: "no-store",
  });
}

export async function syncThreatIntel(payload = {}) {
  return request("/api/threat-intel/sync", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function fetchThreatIntelCves(limit = 50, severity = null, criticalOnly = false) {
  const query = new URLSearchParams();
  if (limit) {
    query.set("limit", String(limit));
  }
  if (severity) {
    query.set("severity", severity);
  }
  if (criticalOnly) {
    query.set("critical_only", "true");
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return request(`/api/threat-intel/cves${suffix}`, {
    cache: "no-store",
  });
}

export async function fetchAiDashboard() {
  return request("/api/ai/dashboard", {
    cache: "no-store",
  });
}

export async function scoreAiRisk(payload) {
  return request("/api/ai/risk-score", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function analyzeAiVulnerability(payload) {
  return request("/api/ai/vulnerabilities/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function correlateAiThreats(payload) {
  return request("/api/ai/correlate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function askAiCopilot(payload) {
  return request("/api/ai/copilot", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function summarizeAiIncident(payload) {
  return request("/api/ai/incident-summary", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function generateAiReport(payload) {
  return request("/api/ai/reports", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function searchAiData(query, limit = 5) {
  const params = new URLSearchParams();
  params.set("query", query);
  params.set("limit", String(limit));
  return request(`/api/ai/search?${params.toString()}`, {
    cache: "no-store",
  });
}
