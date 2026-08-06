import test from "node:test";
import assert from "node:assert/strict";

import {
  getRegistrationRoleConfig,
  getWorkspacePathForRole,
  readJwtPayload,
} from "../lib/workspaces.js";

function encodeBase64Url(value) {
  return Buffer.from(JSON.stringify(value))
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

test("maps roles to workspace paths", () => {
  assert.equal(getWorkspacePathForRole("USER"), "/user");
  assert.equal(getWorkspacePathForRole("ANALYST"), "/analyst");
  assert.equal(getWorkspacePathForRole("MANAGER"), "/manager");
  assert.equal(getWorkspacePathForRole("ORGANIZATION_OWNER"), "/owner");
  assert.equal(getWorkspacePathForRole("SUPER_ADMIN"), "/super-admin");
});

test("returns role specific registration fields", () => {
  const ownerConfig = getRegistrationRoleConfig("ORGANIZATION_OWNER");
  const managerConfig = getRegistrationRoleConfig("MANAGER");
  const superAdminConfig = getRegistrationRoleConfig("SUPER_ADMIN");

  assert.deepEqual(
    ownerConfig.fields.map((field) => field.name),
    ["organization_name", "industry", "company_size"],
  );
  assert.deepEqual(
    managerConfig.fields.map((field) => field.name),
    ["department", "organization_name"],
  );
  assert.deepEqual(
    superAdminConfig.fields.map((field) => field.name),
    ["organization_name"],
  );
});

test("decodes jwt payloads used by session handling", () => {
  const token = `${encodeBase64Url({ alg: "HS256", typ: "JWT" })}.${encodeBase64Url({
    sub: "42",
    role: "MANAGER",
    organization_id: 7,
  })}.signature`;

  const payload = readJwtPayload(token);

  assert.equal(payload.sub, "42");
  assert.equal(payload.role, "MANAGER");
  assert.equal(payload.organization_id, 7);
});
