import { NextResponse } from "next/server";

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
  readJwtPayload,
} from "@/lib/workspaces";

const BACKEND_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8001";
const COOKIE_SECURE =
  process.env.NEXT_PUBLIC_AUTH_COOKIE_SECURE === "true" || process.env.NODE_ENV === "production";

function getTokenMaxAge(token) {
  if (!token) {
    return undefined;
  }

  const payload = readJwtPayload(token);
  const expiresAt = Number(payload?.exp);
  if (!Number.isFinite(expiresAt)) {
    return undefined;
  }

  return Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
}

function setSessionCookies(response, accessToken, refreshToken) {
  const accessMaxAge = getTokenMaxAge(accessToken);
  const refreshMaxAge = getTokenMaxAge(refreshToken);

  if (accessToken) {
    response.cookies.set(AUTH_ACCESS_COOKIE_NAME, accessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
      maxAge: accessMaxAge,
    });
  }

  if (refreshToken) {
    response.cookies.set(AUTH_REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
      maxAge: refreshMaxAge,
    });
  }
}

function clearSessionCookies(response) {
  response.cookies.set(AUTH_ACCESS_COOKIE_NAME, "", {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  response.cookies.set(AUTH_REFRESH_COOKIE_NAME, "", {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

function buildBackendUrl(pathname, search = "") {
  return `${BACKEND_BASE_URL}${pathname}${search}`;
}

function readRequestTokens(request) {
  return {
    accessToken: request.cookies.get(AUTH_ACCESS_COOKIE_NAME)?.value || "",
    refreshToken: request.cookies.get(AUTH_REFRESH_COOKIE_NAME)?.value || "",
  };
}

function buildBackendHeaders(request, token = "") {
  const headers = new Headers();
  for (const [name, value] of request.headers.entries()) {
    const normalizedName = name.toLowerCase();
    if (normalizedName === "host" || normalizedName === "content-length" || normalizedName === "cookie") {
      continue;
    }
    headers.set(name, value);
  }

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  } else {
    headers.delete("Authorization");
  }

  return headers;
}

async function fetchBackend(request, backendPath, token = "") {
  const method = request.method.toUpperCase();
  const headers = buildBackendHeaders(request, token);
  const bodyRequest = request.clone();
  const body = method === "GET" || method === "HEAD" ? undefined : Buffer.from(await bodyRequest.arrayBuffer());

  return fetch(buildBackendUrl(backendPath, request.nextUrl.search), {
    method,
    headers,
    body,
    redirect: "manual",
  });
}

async function parseJsonResponse(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function sanitizeAuthPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return payload;
  }

  const { access_token, refresh_token, ...rest } = payload;
  void access_token;
  void refresh_token;
  return rest;
}

async function buildNextResponseFromBackend(response) {
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("content-encoding");
  headers.delete("transfer-encoding");
  headers.delete("connection");
  headers.delete("keep-alive");
  headers.delete("proxy-authenticate");
  headers.delete("proxy-authorization");
  headers.delete("te");
  headers.delete("trailers");
  headers.delete("upgrade");
  headers.delete("set-cookie");

  const body = await response.arrayBuffer();
  return new NextResponse(Buffer.from(body), {
    status: response.status,
    headers,
  });
}

async function refreshSession(request, refreshToken) {
  if (!refreshToken) {
    return null;
  }

  const backendResponse = await fetch(buildBackendUrl("/auth/refresh"), {
    method: "POST",
    headers: buildBackendHeaders(request, refreshToken),
    redirect: "manual",
  });

  if (!backendResponse.ok) {
    return null;
  }

  return parseJsonResponse(backendResponse);
}

async function handleAuthResponse(request, backendPath, backendResponse) {
  const payload = await parseJsonResponse(backendResponse);
  const response = NextResponse.json(sanitizeAuthPayload(payload), {
    status: backendResponse.status,
  });

  if (backendPath === "/auth/login" || backendPath === "/auth/refresh") {
    if (backendResponse.ok && payload?.access_token && payload?.refresh_token) {
      setSessionCookies(response, payload.access_token, payload.refresh_token);
    } else if (backendPath === "/auth/refresh") {
      clearSessionCookies(response);
    }
  } else if (backendPath === "/auth/logout") {
    clearSessionCookies(response);
  }

  void request;
  return response;
}

async function proxyRequest(request, context) {
  const params = await context.params;
  const backendPath = `/${(params?.path || []).join("/")}`;
  const { accessToken, refreshToken } = readRequestTokens(request);

  if (backendPath === "/auth/login" || backendPath === "/auth/register") {
    const backendResponse = await fetchBackend(request, backendPath);
    return handleAuthResponse(request, backendPath, backendResponse);
  }

  if (backendPath === "/auth/refresh") {
    const token = refreshToken || accessToken;
    const backendResponse = await fetchBackend(request, backendPath, token);
    return handleAuthResponse(request, backendPath, backendResponse);
  }

  if (backendPath === "/auth/logout") {
    const token = refreshToken || accessToken;
    const backendResponse = await fetchBackend(request, backendPath, token);
    return handleAuthResponse(request, backendPath, backendResponse);
  }

  const backendResponse = await fetchBackend(request, backendPath, accessToken);
  if (backendResponse.status !== 401 || !refreshToken) {
    return buildNextResponseFromBackend(backendResponse);
  }

  const refreshed = await refreshSession(request, refreshToken);
  if (!refreshed?.access_token || !refreshed?.refresh_token) {
    const failureResponse = await buildNextResponseFromBackend(backendResponse);
    clearSessionCookies(failureResponse);
    return failureResponse;
  }

  const retriedResponse = await fetchBackend(request, backendPath, refreshed.access_token);
  const finalResponse = await buildNextResponseFromBackend(retriedResponse);
  setSessionCookies(finalResponse, refreshed.access_token, refreshed.refresh_token);
  return finalResponse;
}

export async function GET(request, context) {
  return proxyRequest(request, context);
}

export async function POST(request, context) {
  return proxyRequest(request, context);
}

export async function PUT(request, context) {
  return proxyRequest(request, context);
}

export async function PATCH(request, context) {
  return proxyRequest(request, context);
}

export async function DELETE(request, context) {
  return proxyRequest(request, context);
}

export async function OPTIONS(request, context) {
  return proxyRequest(request, context);
}
