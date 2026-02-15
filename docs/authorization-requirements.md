# Authorization & Connection Stability Requirements

This document defines implementation requirements for secure, stable provider connectivity for:
- Google CLI integration
- Antigravity CLI integration
- OpenAI Codex CLI integration

## 1) Core Security Requirements (applies to all providers)

1. **No plaintext secrets at rest**
   - Access/refresh tokens must be encrypted before DB write.
   - Encryption key must come from Kubernetes Secret, never source code.

2. **Least-privilege scopes**
   - Request only required scopes per provider use case.
   - Scope expansion requires explicit admin approval.

3. **No token exposure in logs**
   - Structured logging must redact: access tokens, refresh tokens, auth codes, device codes.
   - HTTP debug logs must sanitize `Authorization` headers.

4. **No token exposure in API responses by default**
   - Internal API should return metadata/status first.
   - Token-returning endpoints must remain restricted and auditable.

5. **Controlled retrieval path**
   - Token retrieval endpoint requires API key auth plus provider/profile constraints.
   - Optional: second factor (mTLS or signed service token) for privileged token read.

6. **Secret rotation support**
   - Rotate `AUTH_STATION_ENCRYPTION_KEY` with planned re-encryption migration.
   - API key rotation must support overlap window.

7. **Transport security**
   - TLS required for all external access.
   - If inside cluster only, enforce NetworkPolicy to n8n namespace/service account.

## 2) Token Lifecycle Requirements

1. **State model** per credential:
   - `active`, `expiring_soon`, `expired`, `refresh_failed`, `revoked`

2. **Refresh strategy**
   - Refresh when remaining lifetime < configurable threshold (example: 5 min).
   - Use single-flight locking by `(provider, profile)` to prevent refresh stampede.

3. **Failure handling**
   - Exponential backoff for transient refresh failures.
   - Circuit breaker after N failures to avoid provider lockout.
   - Emit event/alert when entering `refresh_failed`.

4. **Revocation handling**
   - If provider indicates revoked/invalid_grant, mark credential `revoked`.
   - Require re-auth bootstrap flow.

## 3) Stable Connection Requirements

1. **Provider HTTP client hardening**
   - Connection pooling + keepalive.
   - Request timeout defaults (connect/read/write).
   - Retries only for idempotent or explicitly safe operations.

2. **Backpressure and degradation**
   - If preferred provider fails, route to next eligible provider by policy.
   - Surface degradation reason in routing response metadata.

3. **Health signals**
   - Provider health score based on:
     - token validity
     - recent auth/refresh success rate
     - quota/remaining time
     - response latency

4. **Routing stability policy**
   - Optional sticky provider per profile/session window.
   - Avoid rapid provider flapping unless hard failure.

## 4) Provider-Specific Requirements

## 4.1 Google CLI

1. **Recommended flow**
   - OAuth 2.0 Device Authorization Grant for headless environments.
   - Fallback: Authorization Code + PKCE if interactive browser available.

2. **Google requirements**
   - Dedicated Google OAuth app in GCP.
   - Explicit allowed scopes documented per n8n use cases.
   - Store refresh token if issued; detect one-time/rotating behavior.

3. **Stability controls**
   - Track token endpoint quota/rate limits.
   - Cache token metadata (`expiry`, `scope`, `subject`) for quick validity checks.

4. **Security controls**
   - Never print device/user code verification URL in logs at INFO with user identifiers.
   - Store Google subject/account hint encrypted or minimally exposed.

## 4.2 Antigravity CLI

1. **Abstraction-first requirement**
   - Implement as adapter behind a provider interface:
     - `start_auth()`
     - `poll_or_exchange()`
     - `refresh()`
     - `revoke()`
     - `validate()`

2. **Protocol uncertainty handling**
   - If Antigravity is OAuth-compatible: use Device Flow/PKCE same as others.
   - If token-based custom auth: isolate in dedicated adapter with same lifecycle state model.

3. **Stability controls**
   - Explicit retry policy based on Antigravity error taxonomy.
   - Version-pin CLI/API compatibility and expose adapter version in status endpoint.

4. **Security controls**
   - Support external secret store handoff if Antigravity tokens are long-lived/high privilege.

## 4.3 OpenAI Codex CLI

1. **Auth mode requirement**
   - Support whichever Codex CLI auth mode is configured:
     - OAuth-based user flow, or
     - API key/service token mode.

2. **If OAuth mode**
   - Reuse common token lifecycle manager.
   - Enforce least-privilege scope and refresh strategy.

3. **If API key mode**
   - Store encrypted and restrict retrieval to authorized routes only.
   - Rotate keys with overlap support and zero-downtime switch.

4. **Stability controls**
   - Track model endpoint latency and rate limit headers.
   - Feed rate-limit state into routing priority.

## 5) API/Contract Requirements

1. **Auth session endpoints (new)**
   - `POST /api/auth-sessions/start`
   - `POST /api/auth-sessions/{id}/poll`
   - `POST /api/auth-sessions/{id}/complete`
   - `POST /api/auth-sessions/{id}/cancel`

2. **Credential state endpoint (new)**
   - `GET /api/providers/{provider}/credentials/{profile}/status`
   - Returns state, expires_at, last_refresh_attempt, failure_count, next_retry_at.

3. **Routing endpoint extension**
   - Include `degradation_reason`, `health_score`, `quota_snapshot`.

4. **Audit events**
   - Record who/what initiated auth, refresh, revocation, token read.

## 6) Kubernetes/Deployment Requirements

1. **Secret management**
   - Use K8s Secret at minimum; prefer SealedSecrets or External Secrets Operator.
   - RBAC: only Authorization Station service account may read relevant secrets.

2. **Pod hardening**
   - Run as non-root.
   - Read-only root filesystem where possible.
   - Drop unnecessary Linux capabilities.

3. **Operational reliability**
   - Liveness/readiness probes.
   - Resource requests/limits configured.
   - Persistent volume for token registry DB (or managed DB).

## 7) Observability Requirements

1. **Metrics**
   - `auth_refresh_success_total`, `auth_refresh_failure_total`
   - `token_expiry_seconds`
   - `provider_request_latency_ms`
   - `routing_fallback_total`
   - `quota_remaining_tokens`, `quota_remaining_seconds`

2. **Alerts**
   - High refresh failure rate.
   - Any credential in `expired` or `revoked` for critical profiles.
   - Provider latency or error spikes over SLO thresholds.

## 8) Acceptance Criteria

1. Token values never appear in logs, traces, or default API responses.
2. Provider credentials auto-refresh before expiry for healthy providers.
3. Routing falls back cleanly when preferred provider is unhealthy or unauthorized.
4. n8n webhook can request model/flags while policy constraints remain enforced.
5. Audit trail exists for all credential lifecycle operations.
6. Secrets can be rotated without service downtime.

## 9) Implementation Phases

1. **Phase 1 (now)**
   - Provider adapter interface + credential state machine + redaction middleware.

2. **Phase 2**
   - Google device flow end-to-end + refresh daemon + auth session endpoints.

3. **Phase 3**
   - Codex adapter, Antigravity adapter, health-score routing, advanced alerts.

4. **Phase 4**
   - External secret manager integration and key rotation automation.
