"use client";

import { getWorkspacePathForRole } from "./workspaces";
import { fetchCurrentUser } from "./api";

const STORAGE_KEY = "vulntrack-user";

export function saveUser(user, accessToken = null) {
  if (typeof window === "undefined") {
    return;
  }

  void accessToken;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
}

export function loadUser() {
  if (typeof window === "undefined") {
    return null;
  }

  const rawValue = window.localStorage.getItem(STORAGE_KEY);
  if (!rawValue) {
    return null;
  }

  try {
    return JSON.parse(rawValue);
  } catch {
    window.localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

export function clearUser() {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.removeItem(STORAGE_KEY);
}

export async function restoreSession() {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    const user = await fetchCurrentUser();
    saveUser(user);
    return user;
  } catch {
    clearUser();
    return null;
  }
}

export function getStoredRoleCode() {
  return loadUser()?.role?.code || null;
}

export function getWorkspacePathForStoredSession() {
  return getWorkspacePathForRole(getStoredRoleCode());
}
