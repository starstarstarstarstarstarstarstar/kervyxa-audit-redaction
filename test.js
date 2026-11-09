"use strict";
// Port of the redaction cases from Kervyxa's audit tests to node:test (no dependencies).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { REDACTED, redactAuditDetail } = require("./audit-redaction.js");

test("undefined in, undefined out", () => {
  assert.equal(redactAuditDetail(undefined), undefined);
});

test("sensitive keys are redacted, case-insensitively", () => {
  const out = redactAuditDetail({ token: "t", AccessToken: "a", Password: "p", cookie: "c" });
  assert.deepEqual(out, { token: REDACTED, AccessToken: REDACTED, Password: REDACTED, cookie: REDACTED });
});

test("nested objects are redacted too", () => {
  const out = redactAuditDetail({ request: { headers: { authorization: "Bearer x" }, path: "/a" } });
  assert.deepEqual(out, { request: { headers: { authorization: REDACTED }, path: "/a" } });
});

test("a Solana signature and ordinary fields are kept", () => {
  const detail = { signature: "5fdHQ84G", contractId: "oc_1", amount: 1000000, ok: true, none: null };
  assert.deepEqual(redactAuditDetail(detail), detail);
});

test("the input is never mutated", () => {
  const detail = { token: "t", inner: { secret: "s" } };
  redactAuditDetail(detail);
  assert.equal(detail.token, "t");
  assert.equal(detail.inner.secret, "s");
});
