"use strict";
// Port of Kervyxa's apps/web/lib/admin/audit.ts redaction. An audit trail is read by more people,
// and kept for longer, than almost anything else in the system; a bearer token that leaks into it
// leaks into every backup and every export of it.

/** Keys whose values must never reach the audit log. */
const REDACT_KEY = /token|secret|password|keypair|private|authorization|cookie|bearer/i;
const REDACTED = "[redacted]";

/**
 * Returns a copy of `detail` with sensitive values replaced. `signature` is deliberately NOT
 * redacted: a Solana transaction signature is public on-chain data and one of the most useful
 * things a money-decision row can carry. Never mutates its input.
 */
function redactAuditDetail(detail) {
  if (detail === undefined) return undefined;
  const out = {};
  for (const [key, value] of Object.entries(detail)) {
    if (REDACT_KEY.test(key)) {
      out[key] = REDACTED;
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      out[key] = redactAuditDetail(value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

module.exports = { REDACT_KEY, REDACTED, redactAuditDetail };
