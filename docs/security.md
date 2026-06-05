# Security Posture

## Threat model

**What we're protecting:** the Cloudflare API tokens that control DNS/WAF/cache for the 6 MMWSS production sites. Leak = attacker can redirect domains, disable WAF, exfiltrate cache.

**Out of scope (Phase 1):** multi-tenant isolation (single-org tool), nation-state attackers, customer-side compromise.

## Controls

| Layer | Control |
|---|---|
| Network | Public ingress only via Cloudflare → Caddy. Postgres/Redis bound to 127.0.0.1. Origin EC2 security group restricts to Cloudflare IP ranges (TODO — currently open) |
| Transport | TLS 1.2+ via Caddy auto-cert. HSTS 1y preload. |
| Auth | Bcrypt password hashing (cost 12). NextAuth session cookies (HttpOnly, Secure, SameSite=Lax). |
| Authorization | Two roles (`admin`, `viewer`). Admin-only endpoints check role server-side, never trust client claims. |
| CF token storage | AES-encrypted at rest in `mmwss.cf_tokens.encrypted_token` via `pgp_sym_encrypt` (master key in env, never logged). Token is decrypted in memory only when collector needs it. UI only ever shows `last_4`. |
| Audit | All auth events + admin actions written to `mmwss.audit_log`. Trigger-enforced append-only (no UPDATE, no DELETE possible at the DB level). |
| Brute force | TODO — Phase 1.5: lockout after 5 failed attempts per email + IP. |
| Secrets in repo | None. `.gitignore` blocks `.env*`, `*.pem`, `*.key`, `secrets/`. `.env.example` documents required variable names only. |
| Dependency hygiene | `npm audit` + `pip-audit` on every CI run (TODO — when CI lands). Renovate bot for PRs. |

## Key rotation procedure

**Cloudflare token rotation:**
1. Admin generates new token in Cloudflare dashboard, scoped to required perms
2. Admin → MMWSS dashboard → Settings → Cloudflare Tokens → Add
3. After collector picks it up and a successful sync, delete the old token row
4. Audit log records both events

**MMWSS master key rotation:**
1. Generate new key: `openssl rand -hex 32`
2. Write a re-encrypt migration that decrypts every `cf_tokens.encrypted_token` with old key and re-encrypts with new
3. Set env to new key. Restart containers.

**Database password rotation:**
1. `ALTER USER mmwss WITH PASSWORD '...'` in callora-db
2. Update `DATABASE_URL` in `/srv/callora/.env`
3. Restart mmwss-app + mmwss-collector

## Backup

- Postgres `mmwss` schema is included in callora-db's existing nightly `pg_dump`
- Reports stored as files in `/srv/mmwss/reports/` — backed up with rsync to S3 (TODO)

## What we do not do (and why)

- **No MFA in Phase 1.** Internal-only tool, 1-2 users. Reasonable trade-off until Phase 2.
- **No multi-tenant RLS.** Single org, no cross-tenant isolation needed.
- **No PDF generation in the browser.** Always server-side via headless Chromium so report content can't be tampered with by a viewer's environment.
- **No password reset by email in Phase 1.** Admin manually resets passwords from the user management page. Faster ship, fewer attack surfaces (no email parsing, no token replay).
