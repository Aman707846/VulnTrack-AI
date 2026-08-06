import { NextResponse } from "next/server";

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
  getRoleFromWorkspacePath,
  getWorkspacePathForRole,
  normalizeRoleCode,
  readJwtPayload,
} from "./lib/workspaces";

const PUBLIC_PATHS = new Set(["/login", "/register", "/favicon.ico"]);
const BACKEND_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8001";

function getCookieToken(request, cookieName) {
  return request.cookies.get(cookieName)?.value || "";
}

function readSessionTokens(request) {
  return {
    accessToken: getCookieToken(request, AUTH_ACCESS_COOKIE_NAME),
    refreshToken: getCookieToken(request, AUTH_REFRESH_COOKIE_NAME),
  };
}

function buildAuthHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
  };
}

async function resolveCurrentUser(token) {
  try {
    const response = await fetch(`${BACKEND_BASE_URL}/auth/me`, {
      headers: buildAuthHeaders(token),
      cache: "no-store",
    });

    if (!response.ok) {
      return null;
    }

    const user = await response.json();
    const roleCode = normalizeRoleCode(user?.role?.code);
    return {
      user,
      roleCode,
      workspacePath: getWorkspacePathForRole(roleCode),
    };
  } catch {
    return null;
  }
}

async function rotateSession(refreshToken) {
  try {
    const response = await fetch(`${BACKEND_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: buildAuthHeaders(refreshToken),
      cache: "no-store",
    });

    if (!response.ok) {
      return null;
    }

    const payload = await response.json();
    if (!payload?.access_token || !payload?.refresh_token) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

async function resolveSession(request) {
  const { accessToken, refreshToken } = readSessionTokens(request);

  if (accessToken) {
    const user = await resolveCurrentUser(accessToken);
    if (user) {
      return { ...user, accessToken, refreshToken, refreshed: false };
    }
  }

  if (refreshToken) {
    const rotated = await rotateSession(refreshToken);
    if (rotated?.access_token && rotated?.refresh_token) {
      const user = await resolveCurrentUser(rotated.access_token);
      if (user) {
        return {
          ...user,
          accessToken: rotated.access_token,
          refreshToken: rotated.refresh_token,
          refreshed: true,
        };
      }
    }
  }

  return null;
}

function applySessionCookies(response, session) {
  if (!session?.refreshed) {
    return response;
  }

  const accessExpiresAt = Number(readJwtPayload(session.accessToken)?.exp);
  const refreshExpiresAt = Number(readJwtPayload(session.refreshToken)?.exp);
  const nowSeconds = Math.floor(Date.now() / 1000);

  response.cookies.set(AUTH_ACCESS_COOKIE_NAME, session.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_AUTH_COOKIE_SECURE === "true",
    sameSite: "lax",
    path: "/",
    maxAge: Number.isFinite(accessExpiresAt) ? Math.max(0, accessExpiresAt - nowSeconds) : undefined,
  });
  response.cookies.set(AUTH_REFRESH_COOKIE_NAME, session.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_AUTH_COOKIE_SECURE === "true",
    sameSite: "lax",
    path: "/",
    maxAge: Number.isFinite(refreshExpiresAt) ? Math.max(0, refreshExpiresAt - nowSeconds) : undefined,
  });

  return response;
}

function clearSessionCookies(response) {
  response.cookies.set(AUTH_ACCESS_COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_AUTH_COOKIE_SECURE === "true",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  response.cookies.set(AUTH_REFRESH_COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_AUTH_COOKIE_SECURE === "true",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });

  return response;
}

export async function proxy(request) {
  const { pathname } = request.nextUrl;

  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api") ||
    pathname.startsWith("/backend") ||
    pathname === "/favicon.ico"
  ) {
    return NextResponse.next();
  }

  const isPublicPath = PUBLIC_PATHS.has(pathname);
  const workspaceRole = getRoleFromWorkspacePath(pathname);

  const session = await resolveSession(request);
  if (!session) {
    if (!isPublicPath && pathname !== "/") {
      return clearSessionCookies(NextResponse.redirect(new URL("/login", request.url)));
    }

    return NextResponse.next();
  }

  if (isPublicPath || pathname === "/") {
    return applySessionCookies(NextResponse.redirect(new URL(session.workspacePath, request.url)), session);
  }

  if (workspaceRole && session.workspacePath !== pathname) {
    return applySessionCookies(NextResponse.redirect(new URL(session.workspacePath, request.url)), session);
  }

  return applySessionCookies(NextResponse.next(), session);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api|backend).*)"],
};
