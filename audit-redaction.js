"use strict";
// Port of Kervyxa's apps/web/lib/admin/audit.ts redaction. An audit trail is read by more people,
// and kept for longer, than almost anything else in the system; a bearer token that leaks into it
// leaks into every backup and every export of it.

/** Keys whose values must never reach the audit log (API-key spellings included). */
const REDACT_KEY =
  /token|secret|password|keypair|private|authorization|cookie|bearer|api[_-]?key/i;
const REDACTED = "[redacted]";

/** Values that are a Kervyxa API key by their prefix, whatever key they sit under. */
const SECRET_VALUE = /^kvx_/;

function redactValue(value) {
  if (typeof value === "string" && SECRET_VALUE.test(value)) return REDACTED;
  if (Array.isArray(value)) return value.map(redactValue);
  if (value !== null && typeof value === "object") return redactAuditDetail(value);
  return value;
}

/**
 * Returns a copy of `detail` with sensitive values replaced, descending through nested objects
 * AND arrays. `signature` is deliberately NOT redacted: a Solana transaction signature is public
 * on-chain data and one of the most useful things a money-decision row can carry. Never mutates
 * its input.
 */
function redactAuditDetail(detail) {
  if (detail === undefined) return undefined;
  const out = {};
  for (const [key, value] of Object.entries(detail)) {
    out[key] = REDACT_KEY.test(key) ? REDACTED : redactValue(value);
  }
  return out;
}

module.exports = { REDACT_KEY, REDACTED, redactAuditDetail };
