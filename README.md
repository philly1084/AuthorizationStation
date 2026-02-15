# Authorization Station

Authorization Station is a small service you can run in k3s/Kubernetes to sit between n8n and model providers.

It provides:
- OAuth token registry (encrypted at rest) for providers like `google`, `antigravity`, and `openai`.
- Model/provider routing decisions based on profile defaults and per-request flags.
- CLI + webhook control (`thinking`, `verbose`, `compaction`, model override, provider hints).
- Basic usage/quota accounting for remaining tokens/time.
- Optional LiteLLM upstream routing for local llama/tool-calling models with OpenAI-compatible output.
- Phase 1 security scaffolding: provider adapter interface, credential lifecycle state, and request-header redaction middleware.

## Architecture

- **FastAPI API** (`app/main.py`) for registry, routing, usage ingestion.
- **SQLite + SQLAlchemy** for persistence (swap to Postgres by env var).
- **Typer CLI** (`cli/main.py`) for preference and route operations.
- **Kubernetes manifests** in `k8s/` for deployment.

## Environment Variables

See `.env.example`.

Required:
- `AUTH_STATION_API_KEY`
- `AUTH_STATION_ENCRYPTION_KEY`

Optional:
- `AUTH_STATION_DATABASE_URL` (default sqlite)
- `AUTH_STATION_N8N_WEBHOOK_SECRET`
- `AUTH_STATION_DEFAULT_PROFILE`
- `AUTH_STATION_LITELLM_BASE_URL` (example: `http://litellm-proxy:4000`)
- `AUTH_STATION_LITELLM_API_KEY` (optional; if omitted, uses stored `litellm` provider token)

## Run locally

```bash
python -m venv .venv
. .venv/Scripts/activate  # PowerShell: .venv\Scripts\Activate.ps1
pip install -U pip
pip install .
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Health check:

```bash
curl http://localhost:8080/healthz
```

## API overview

### OAuth registry
- `POST /api/oauth/upsert`
- `GET /api/oauth/{provider}?profile=default`
- `GET /api/oauth/{provider}/token?profile=default`
- `GET /api/providers/{provider}/credentials/{profile}/status`

### Auth sessions (Phase 2)
- `POST /api/auth-sessions/start`
- `POST /api/auth-sessions/poll`
- `POST /api/auth-sessions/complete`
- `POST /api/auth-sessions/cancel`

### Preference & routing
- `POST /api/preferences/upsert`
- `GET /api/preferences/{profile}`
- `POST /api/route/decide`
- `POST /api/commands/execute` (slash-command style updates from chat tools)
- `POST /webhooks/n8n/route`
- `GET /api/providers/status?profile=default`

### OpenAI-compatible endpoints (for n8n Model credentials)
- `GET /v1/models`
- `POST /v1/chat/completions`

`/v1/chat/completions` can route to providers: `openai`, `google`/`gemini`, and `litellm`.

### Usage/quota
- `POST /api/quota/upsert`
- `GET /api/quota`
- `POST /api/usage`

All `/api/*` endpoints require `x-api-key` (or `Authorization: Bearer <key>`).
OpenAI-compatible `/v1/*` endpoints use the same key behavior, so n8n can send `Authorization: Bearer <AUTH_STATION_API_KEY>`.

## Phase 1 implementation notes

- Provider adapter stubs are in `app/providers.py` (`google`, `antigravity`, `openai`) to support a stable contract for upcoming auth flows.
- OAuth credentials now include lifecycle fields (`state`, `last_refresh_attempt`, `refresh_failure_count`, `next_retry_at`, `last_error`).
- Request logging middleware redacts sensitive header/token fields.
- If you already created a local sqlite DB before these changes, delete/recreate it (or run a migration) to add new columns.

## Phase 2 implementation notes

- Google OAuth Device Flow support is implemented via provider adapter (`app/providers.py`).
- Auth sessions are persisted in `provider_auth_sessions` and can be polled until authorized.
- Authorized sessions automatically upsert encrypted credentials for the target provider/profile.
- A background refresh loop attempts token refresh before expiry (when a refresh token exists).

### Google device-flow bootstrap

1. Set env vars:
   - `AUTH_STATION_GOOGLE_OAUTH_CLIENT_ID`
   - `AUTH_STATION_GOOGLE_OAUTH_CLIENT_SECRET`
   - optional `AUTH_STATION_GOOGLE_OAUTH_SCOPE`
2. Start a session:

```bash
curl -X POST http://localhost:8080/api/auth-sessions/start \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","profile":"default"}'
```

3. Open `verification_uri`, enter `user_code`, then poll:

```bash
curl -X POST http://localhost:8080/api/auth-sessions/poll \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"<session_id>"}'
```

### Browser redirect flow (OpenClaw-style)

If you prefer the flow where you open a URL, sign in, and receive a redirect URL with `code=...`:

1. Configure `AUTH_STATION_GOOGLE_OAUTH_REDIRECT_URI` (example: `http://localhost:3333/callback`) and register it in Google OAuth credentials.
2. Start browser auth session:

```bash
curl -X POST http://localhost:8080/api/auth-sessions/start \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider":"google",
    "profile":"default",
    "flow":"browser",
    "redirect_uri":"http://localhost:3333/callback"
  }'
```

3. Open returned `verification_uri` in your browser.
4. After login/consent, copy the `code` query param from your redirected local URL.
5. Complete session by exchanging the code:

```bash
curl -X POST http://localhost:8080/api/auth-sessions/complete \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id":"<session_id>",
    "authorization_code":"<code_from_redirect_url>"
  }'
```

## CLI examples

### Human-friendly setup once, then reuse

Initialize CLI config interactively (saves API URL/key + defaults locally):

```bash
auth-station config init
```

After this, you can run commands without repeating `--api-url` and `--api-key`.

Show/edit config later (post-setup changes):

```bash
auth-station config show
auth-station config set --profile prod --provider gemini
auth-station config set --api-url http://authorization-station:8080
auth-station config doctor
auth-station config doctor --check-auth
```

Manage multiple contexts and switch quickly:

```bash
auth-station config init --context prod --api-url http://authorization-station:8080 --api-key <key> --profile prod --provider gemini
auth-station config use prod
auth-station config show
```

Save reusable references for shorter, more human commands:

```bash
auth-station config ref-set --ref-type model --name fast --value gpt-4.1-mini
auth-station config ref-set --ref-type provider --name g --value gemini
auth-station config ref-list
```

Then use references in commands:

```bash
auth-station set-pref --model @model:fast
auth-station slash "/set-model @model:fast"
```

Show full help:

```bash
auth-station --help
auth-station auth-login --help
```

Useful endpoint-management commands:

```bash
auth-station providers --api-url http://localhost:8080 --api-key <key>
auth-station credential-status --api-url http://localhost:8080 --api-key <key> --provider gemini --profile default
auth-station auth-start --api-url http://localhost:8080 --api-key <key> --provider google --profile default --flow device
auth-station auth-poll --api-url http://localhost:8080 --api-key <key> --session-id <session_id>
auth-station auth-complete --api-url http://localhost:8080 --api-key <key> --session-id <session_id> --authorization-code <code>
```

One-command remote login flow (copy/paste URL + code):

```bash
auth-station auth-login --api-url http://localhost:8080 --api-key <key> --provider gemini --profile default
```

Browser paste-back flow (single command, then paste redirected URL when prompted):

```bash
auth-station auth-login --api-url http://localhost:8080 --api-key <key> --provider google --profile default --mode browser --redirect-uri http://localhost:3333/callback
```

Slash-command bridge (for chat programs / bots):

```bash
auth-station slash --api-url http://localhost:8080 --api-key <key> "/show-settings" --profile default
auth-station slash --api-url http://localhost:8080 --api-key <key> "/set-model gpt-4.1-mini" --profile default
auth-station slash --api-url http://localhost:8080 --api-key <key> "/set-thinking on" --profile default
```

Direct HTTP call from a chat tool:

```bash
curl -X POST http://localhost:8080/api/commands/execute \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"profile":"default","command_text":"/set-verbose off"}'
```

Supported slash commands:
- `/help` or `/commands`
- `/show-settings`
- `/set-model <model>`
- `/set-thinking <on|off>`
- `/set-verbose <on|off>`
- `/set-compaction <on|off>`
- `/set-temperature <number|none>`
- `/set-max-tokens <int|none>`

Set profile defaults:

```bash
auth-station set-pref \
  --api-url http://localhost:8080 \
  --api-key change-me \
  --profile default \
  --model gpt-4.1-mini \
  --thinking \
  --verbose
```

Get route decision:

```bash
auth-station route \
  --api-url http://localhost:8080 \
  --api-key change-me \
  --profile default \
  --provider-hints openai,google \
  --compaction
```

## n8n integration

In an n8n HTTP Request node:
- Method: `POST`
- URL: `http://authorization-station/webhooks/n8n/route`
- Header: `x-n8n-secret: <secret>` (if configured)
- JSON body example:

```json
{
  "profile": "default",
  "provider_hints": ["openai", "google"],
  "thinking": true,
  "verbose": false,
  "compaction": true
}
```

Use response fields `provider`, `selected_model`, and `flags` to route downstream model calls.

## n8n OpenAI-model integration

If you want n8n to use this service directly from its **Model** section as an OpenAI-compatible provider:

1. Base URL: `http://authorization-station`
2. API Key: your `AUTH_STATION_API_KEY`
3. Models endpoint used by n8n: `/v1/models`
4. Chat endpoint used by n8n: `/v1/chat/completions`

Before calling, store your upstream OpenAI credential in Authorization Station for the selected profile:

```bash
curl -X POST http://authorization-station/api/oauth/upsert \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "profile": "default",
    "access_token": "<OPENAI_API_KEY>",
    "scopes": []
  }'
```

For Gemini, authorize via device flow (provider `google` or `gemini`) and then force routing with provider hints:

```json
{
  "model": "gemini-2.5-pro",
  "provider_hints": ["gemini", "google"]
}
```

Gemini auth currently uses Google OAuth client credentials configured via:
- `AUTH_STATION_GOOGLE_OAUTH_CLIENT_ID`
- `AUTH_STATION_GOOGLE_OAUTH_CLIENT_SECRET`

### LiteLLM integration (for local llama models)

If you're running a LiteLLM proxy in-cluster and want Authorization Station to route there:

Default routed model for provider `litellm` is now `phi-3-mini`.

1. Set env var in Authorization Station:
   - `AUTH_STATION_LITELLM_BASE_URL=http://litellm-proxy:4000`
2. Configure a credential for provider `litellm` (used as bearer key unless `AUTH_STATION_LITELLM_API_KEY` is set):

```bash
curl -X POST http://authorization-station/api/oauth/upsert \
  -H "x-api-key: <AUTH_STATION_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "litellm",
    "profile": "default",
    "access_token": "<LITELLM_API_KEY_OR_INTERNAL_TOKEN>",
    "scopes": []
  }'
```

3. Route requests to LiteLLM from n8n/OpenAI-compatible calls with provider hints:

```json
{
  "model": "phi-3-mini",
  "provider_hints": ["litellm"]
}
```

Kubernetes manifests include defaults for this setup:
- Deployment env: `AUTH_STATION_LITELLM_BASE_URL`, `AUTH_STATION_LITELLM_API_KEY`
- Secret example key: `litellm_api_key`

## Build and push to GitHub + GHCR

Using your GitHub namespace (`philly1084`):

1. Create a GitHub repo (for example: `authorization-station`).
2. Push this code:

```bash
git init
git add .
git commit -m "Initial Authorization Station"
git branch -M main
git remote add origin https://github.com/philly1084/authorization-station.git
git push -u origin main
```

3. Build/push image:

```bash
docker build -t ghcr.io/philly1084/authorization-station:latest .
docker login ghcr.io
docker push ghcr.io/philly1084/authorization-station:latest
```

4. Confirm the container package visibility in GitHub Packages:
   - If package is **public**, Kubernetes can pull without a registry secret.
   - If package is **private**, create an image pull secret and attach it to your service account.

## Deploy to k3s

1. Edit `k8s/secret.yaml` with strong values.
2. `k8s/deployment.yaml` is already set to:
   - `ghcr.io/philly1084/authorization-station:latest`
3. If GHCR package is private, create pull secret in the target namespace:

```bash
kubectl create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=philly1084 \
  --docker-password=<GITHUB_PAT_WITH_read:packages>
```

4. Attach pull secret to service account:

```bash
kubectl patch serviceaccount authorization-station \
  -p '{"imagePullSecrets":[{"name":"ghcr-pull"}]}'
```

5. (Optional) tune `k8s/networkpolicy.yaml` to match your n8n pod labels.
6. Apply with kustomize:

```bash
kubectl apply -k k8s
```

7. Verify:

```bash
kubectl get pods -l app=authorization-station
kubectl get svc authorization-station
```

If n8n is in the same namespace, target `http://authorization-station`.

## Security notes

- `AUTH_STATION_ENCRYPTION_KEY` should be strong and secret-managed.
- Use Kubernetes Secrets (or sealed secrets / external secrets). `k8s/secret.yaml` is gitignored for this reason.
- Consider mTLS/NetworkPolicy if exposing outside cluster.
- Background refresh is enabled for providers with implemented `refresh()` adapters and stored refresh tokens.
