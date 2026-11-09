# kervyxa-audit-redaction

Kervyxa's admin audit-log redaction, extracted from `apps/web/lib/admin/audit.ts` as a
dependency-free CommonJS module so the next change can be bought as an Outcome Contract on
[kervyxa.com](https://kervyxa.com).

`redactAuditDetail(detail)` returns a copy of a detail object with sensitive values replaced by
`"[redacted]"`. A Solana transaction `signature` is kept on purpose: it is public on-chain data.

```
npm test   # = node test.js
```
