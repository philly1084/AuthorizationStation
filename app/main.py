import logging
import shlex
import threading
from datetime import timedelta
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import Base, SessionLocal, engine, get_db
from app.deps import require_api_key
from app.models import OAuthCredential, ProviderAuthSession, ProviderQuota, RuntimePreference, UsageEvent
from app.providers import PROVIDER_ADAPTERS
from app.redaction import redact_mapping
from app.schemas import (
    AuthSessionCancelRequest,
    AuthSessionCompleteRequest,
    AuthSessionPollRequest,
    AuthSessionStartRequest,
    AuthSessionView,
    N8NRouteWebhook,
    OAuthCredentialStatus,
    OAuthCredentialUpsert,
    OAuthCredentialView,
    ProviderQuotaUpdate,
    RouteDecisionRequest,
    RouteDecisionResponse,
    SlashCommandRequest,
    SlashCommandResponse,
    RuntimePreferenceUpsert,
    UsageEventIngest,
)
from app.security import decrypt_text, encrypt_text, utcnow

app = FastAPI(title="Authorization Station", version="0.1.0")
logger = logging.getLogger("authorization_station")
_refresh_stop = threading.Event()
_refresh_thread: threading.Thread | None = None

DEFAULT_MODELS = {
    "openai": "gpt-4.1-mini",
    "google": "gemini-2.5-pro",
    "gemini": "gemini-2.5-pro",
    "litellm": "phi-3-mini",
    "antigravity": "ag-core",
}
SUPPORTED_PROVIDERS = ["openai", "google", "gemini", "litellm", "antigravity"]
OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"
GEMINI_CHAT_COMPLETIONS_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
GEMINI_CLOUDCODE_BASE = "https://cloudcode-pa.googleapis.com/v1beta"


def _openai_to_gemini_contents(messages: list[dict]) -> list[dict]:
    """Translate OpenAI messages to Gemini generateContent 'contents' format."""
    contents = []
    system_parts = []
    for msg in messages:
        role = msg.get("role", "user")
        text = msg.get("content", "")
        if role == "system":
            system_parts.append({"text": text})
            continue
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": text}]})
    return contents, system_parts


def _gemini_response_to_openai(gemini_body: dict, model: str) -> dict:
    """Translate Gemini generateContent response to OpenAI chat completions format."""
    candidates = gemini_body.get("candidates", [])
    text = ""
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts)

    usage_meta = gemini_body.get("usageMetadata", {})
    return {
        "id": f"chatcmpl-{uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": usage_meta.get("promptTokenCount", 0),
            "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
            "total_tokens": usage_meta.get("totalTokenCount", 0),
        },
    }


@app.middleware("http")
async def redacted_request_logging(request: Request, call_next):
    sanitized_headers = redact_mapping(dict(request.headers))
    logger.info(
        "request_received",
        extra={
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "headers": sanitized_headers,
        },
    )
    return await call_next(request)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    global _refresh_thread
    if _refresh_thread is None:
        _refresh_thread = threading.Thread(target=_refresh_loop, name="credential-refresh", daemon=True)
        _refresh_thread.start()


@app.on_event("shutdown")
def shutdown() -> None:
    _refresh_stop.set()
    if _refresh_thread is not None:
        _refresh_thread.join(timeout=5)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/oauth/upsert", dependencies=[Depends(require_api_key)])
def upsert_oauth(payload: OAuthCredentialUpsert, db: Session = Depends(get_db)) -> dict[str, str]:
    row = db.scalar(
        select(OAuthCredential).where(
            OAuthCredential.provider == payload.provider,
            OAuthCredential.profile == payload.profile,
        )
    )
    now = utcnow()
    if row is None:
        row = OAuthCredential(
            provider=payload.provider,
            profile=payload.profile,
            account_hint=payload.account_hint,
            encrypted_access_token=encrypt_text(payload.access_token),
            encrypted_refresh_token=encrypt_text(payload.refresh_token) if payload.refresh_token else None,
            expires_at=payload.expires_at,
            state="active",
            refresh_failure_count=0,
            last_error=None,
            scopes=payload.scopes,
            metadata_json=payload.metadata_json,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
    else:
        row.account_hint = payload.account_hint
        row.encrypted_access_token = encrypt_text(payload.access_token)
        row.encrypted_refresh_token = encrypt_text(payload.refresh_token) if payload.refresh_token else None
        row.expires_at = payload.expires_at
        row.state = "active"
        row.refresh_failure_count = 0
        row.next_retry_at = None
        row.last_error = None
        row.scopes = payload.scopes
        row.metadata_json = payload.metadata_json
        row.updated_at = now

    db.commit()
    return {"status": "ok"}


def _to_auth_session_view(row: ProviderAuthSession) -> AuthSessionView:
    return AuthSessionView(
        id=row.id,
        provider=row.provider,
        profile=row.profile,
        status=row.status,
        flow=(row.state_json or {}).get("flow", "device"),
        verification_uri=row.verification_uri,
        user_code=row.user_code,
        expires_at=row.expires_at,
        interval_seconds=row.interval_seconds,
        error=row.error,
    )


def _normalize_expiry(expires_at):
    if not expires_at:
        return None
    if expires_at.tzinfo is None:
        return expires_at.replace(tzinfo=utcnow().tzinfo)
    return expires_at


def _refresh_loop() -> None:
    while not _refresh_stop.wait(settings.refresh_check_interval_seconds):
        db = SessionLocal()
        try:
            _refresh_due_credentials_once(db)
        except Exception:
            logger.exception("refresh_loop_failed")
        finally:
            db.close()


def _refresh_due_credentials_once(db: Session) -> None:
    now = utcnow()
    rows = db.scalars(select(OAuthCredential).where(OAuthCredential.encrypted_refresh_token.is_not(None))).all()
    changed = False

    for row in rows:
        if row.provider not in PROVIDER_ADAPTERS:
            continue
        if row.state in {"revoked"}:
            continue

        expires_at = _normalize_expiry(row.expires_at)
        if not expires_at:
            continue

        if row.next_retry_at and _normalize_expiry(row.next_retry_at) and _normalize_expiry(row.next_retry_at) > now:
            continue

        if (expires_at - now).total_seconds() > settings.refresh_lead_seconds:
            continue

        adapter = PROVIDER_ADAPTERS[row.provider]
        refresh_token = decrypt_text(row.encrypted_refresh_token)
        result = adapter.refresh(refresh_token)
        row.last_refresh_attempt = now
        changed = True

        if result.status == "authorized" and result.access_token:
            row.encrypted_access_token = encrypt_text(result.access_token)
            if result.refresh_token:
                row.encrypted_refresh_token = encrypt_text(result.refresh_token)
            if result.expires_in_seconds:
                row.expires_at = now + timedelta(seconds=int(result.expires_in_seconds))
            row.state = "active"
            row.refresh_failure_count = 0
            row.next_retry_at = None
            row.last_error = None
        else:
            failures = (row.refresh_failure_count or 0) + 1
            row.refresh_failure_count = failures
            row.state = "refresh_failed"
            row.last_error = result.error or "refresh_failed"
            backoff_seconds = min(300, 10 * (2 ** min(failures, 5)))
            row.next_retry_at = now + timedelta(seconds=backoff_seconds)

    if changed:
        db.commit()


@app.get("/api/oauth/{provider}", response_model=OAuthCredentialView, dependencies=[Depends(require_api_key)])
def get_oauth(provider: str, profile: str = Query(default="default"), db: Session = Depends(get_db)) -> OAuthCredentialView:
    row = db.scalar(
        select(OAuthCredential).where(OAuthCredential.provider == provider, OAuthCredential.profile == profile)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    return OAuthCredentialView(
        provider=row.provider,
        profile=row.profile,
        account_hint=row.account_hint,
        expires_at=row.expires_at,
        scopes=row.scopes,
        metadata_json=row.metadata_json,
    )


@app.get("/api/oauth/{provider}/token", dependencies=[Depends(require_api_key)])
def get_oauth_token(provider: str, profile: str = Query(default="default"), db: Session = Depends(get_db)) -> dict[str, str | None]:
    row = db.scalar(
        select(OAuthCredential).where(OAuthCredential.provider == provider, OAuthCredential.profile == profile)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    return {
        "provider": provider,
        "profile": profile,
        "access_token": decrypt_text(row.encrypted_access_token),
        "refresh_token": decrypt_text(row.encrypted_refresh_token) if row.encrypted_refresh_token else None,
    }


@app.post("/api/preferences/upsert", dependencies=[Depends(require_api_key)])
def upsert_preference(payload: RuntimePreferenceUpsert, db: Session = Depends(get_db)) -> dict[str, str]:
    row = db.scalar(select(RuntimePreference).where(RuntimePreference.profile == payload.profile))
    now = utcnow()

    if row is None:
        row = RuntimePreference(
            profile=payload.profile,
            model=payload.model,
            thinking=payload.thinking,
            verbose=payload.verbose,
            compaction=payload.compaction,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            updated_at=now,
        )
        db.add(row)
    else:
        row.model = payload.model
        row.thinking = payload.thinking
        row.verbose = payload.verbose
        row.compaction = payload.compaction
        row.temperature = payload.temperature
        row.max_tokens = payload.max_tokens
        row.updated_at = now

    db.commit()
    return {"status": "ok"}


@app.get("/api/preferences/{profile}", dependencies=[Depends(require_api_key)])
def get_preference(profile: str, db: Session = Depends(get_db)) -> dict:
    row = db.scalar(select(RuntimePreference).where(RuntimePreference.profile == profile))
    if row is None:
        raise HTTPException(status_code=404, detail="Profile preference not found")

    return {
        "profile": row.profile,
        "model": row.model,
        "thinking": row.thinking,
        "verbose": row.verbose,
        "compaction": row.compaction,
        "temperature": row.temperature,
        "max_tokens": row.max_tokens,
        "updated_at": row.updated_at,
    }


@app.post("/api/quota/upsert", dependencies=[Depends(require_api_key)])
def upsert_quota(payload: ProviderQuotaUpdate, db: Session = Depends(get_db)) -> dict[str, str]:
    row = db.scalar(select(ProviderQuota).where(ProviderQuota.provider == payload.provider))
    now = utcnow()
    if row is None:
        row = ProviderQuota(
            provider=payload.provider,
            remaining_seconds=payload.remaining_seconds,
            remaining_tokens=payload.remaining_tokens,
            notes=payload.notes,
            updated_at=now,
        )
        db.add(row)
    else:
        row.remaining_seconds = payload.remaining_seconds
        row.remaining_tokens = payload.remaining_tokens
        row.notes = payload.notes
        row.updated_at = now

    db.commit()
    return {"status": "ok"}


@app.get("/api/quota", dependencies=[Depends(require_api_key)])
def list_quota(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(ProviderQuota)).all()
    return [
        {
            "provider": r.provider,
            "remaining_seconds": r.remaining_seconds,
            "remaining_tokens": r.remaining_tokens,
            "notes": r.notes,
            "updated_at": r.updated_at,
        }
        for r in rows
    ]


@app.post("/api/usage", dependencies=[Depends(require_api_key)])
def ingest_usage(payload: UsageEventIngest, db: Session = Depends(get_db)) -> dict[str, str]:
    row = UsageEvent(
        provider=payload.provider,
        model=payload.model,
        profile=payload.profile,
        request_id=payload.request_id,
        prompt_tokens=payload.prompt_tokens,
        completion_tokens=payload.completion_tokens,
        total_tokens=payload.total_tokens,
        duration_seconds=payload.duration_seconds,
        metadata_json=payload.metadata_json,
        created_at=utcnow(),
    )
    db.add(row)

    quota = db.scalar(select(ProviderQuota).where(ProviderQuota.provider == payload.provider))
    if quota is not None:
        if quota.remaining_tokens is not None and payload.total_tokens is not None:
            quota.remaining_tokens = max(0, quota.remaining_tokens - payload.total_tokens)
        if quota.remaining_seconds is not None and payload.duration_seconds is not None:
            quota.remaining_seconds = max(0, quota.remaining_seconds - int(payload.duration_seconds))
        quota.updated_at = utcnow()

    db.commit()
    return {"status": "ok"}


def _is_token_available(db: Session, provider: str, profile: str) -> bool:
    token_row = db.scalar(
        select(OAuthCredential).where(OAuthCredential.provider == provider, OAuthCredential.profile == profile)
    )
    if token_row is None:
        return False
    if token_row.state in {"refresh_failed", "revoked", "expired"}:
        return False
    if token_row.expires_at:
        expires_at = token_row.expires_at
        now = utcnow()
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=now.tzinfo)
        if expires_at <= now:
            return False
    return True


def _choose_provider(db: Session, profile: str, provider_hints: list[str]) -> str:
    candidates = provider_hints or SUPPORTED_PROVIDERS
    for provider in candidates:
        if _is_token_available(db, provider, profile):
            return provider
    return candidates[0]


def _route(db: Session, payload: RouteDecisionRequest) -> RouteDecisionResponse:
    profile = payload.profile or settings.default_profile
    pref = db.scalar(select(RuntimePreference).where(RuntimePreference.profile == profile))

    provider = _choose_provider(db, profile, payload.provider_hints)
    selected_model = payload.model or (pref.model if pref and pref.model else DEFAULT_MODELS.get(provider, "gpt-4.1-mini"))

    flags = {
        "thinking": payload.thinking if payload.thinking is not None else (pref.thinking if pref else False),
        "verbose": payload.verbose if payload.verbose is not None else (pref.verbose if pref else False),
        "compaction": payload.compaction if payload.compaction is not None else (pref.compaction if pref else False),
        "temperature": pref.temperature if pref else None,
        "max_tokens": pref.max_tokens if pref else None,
    }

    return RouteDecisionResponse(
        provider=provider,
        profile=profile,
        selected_model=selected_model,
        flags=flags,
        token_available=_is_token_available(db, provider, profile),
    )


def _serialize_preference(row: RuntimePreference | None, profile: str) -> dict:
    if row is None:
        return {
            "profile": profile,
            "model": None,
            "thinking": False,
            "verbose": False,
            "compaction": False,
            "temperature": None,
            "max_tokens": None,
        }
    return {
        "profile": row.profile,
        "model": row.model,
        "thinking": row.thinking,
        "verbose": row.verbose,
        "compaction": row.compaction,
        "temperature": row.temperature,
        "max_tokens": row.max_tokens,
        "updated_at": row.updated_at,
    }


def _parse_on_off(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"on", "true", "1", "yes", "y"}:
        return True
    if normalized in {"off", "false", "0", "no", "n"}:
        return False
    raise ValueError("expected on/off")


def _slash_help_text() -> str:
    return (
        "Supported commands: "
        "/show-settings, "
        "/set-model <model>, "
        "/set-thinking <on|off>, "
        "/set-verbose <on|off>, "
        "/set-compaction <on|off>, "
        "/set-temperature <number|none>, "
        "/set-max-tokens <int|none>"
    )


@app.post("/api/route/decide", response_model=RouteDecisionResponse, dependencies=[Depends(require_api_key)])
def decide_route(payload: RouteDecisionRequest, db: Session = Depends(get_db)) -> RouteDecisionResponse:
    return _route(db, payload)


@app.post(
    "/api/commands/execute",
    response_model=SlashCommandResponse,
    dependencies=[Depends(require_api_key)],
)
def execute_slash_command(payload: SlashCommandRequest, db: Session = Depends(get_db)) -> SlashCommandResponse:
    profile = payload.profile or settings.default_profile
    text = payload.command_text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="command_text is required")

    if not text.startswith("/"):
        raise HTTPException(status_code=400, detail="Slash command must start with '/'")

    try:
        parts = shlex.split(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid command syntax: {exc}") from exc

    if not parts:
        raise HTTPException(status_code=400, detail="command_text is required")

    command = parts[0].lower()
    if command in {"/help", "/commands"}:
        row = db.scalar(select(RuntimePreference).where(RuntimePreference.profile == profile))
        return SlashCommandResponse(
            status="ok",
            message=_slash_help_text(),
            profile=profile,
            updated={},
            preference=_serialize_preference(row, profile),
        )

    row = db.scalar(select(RuntimePreference).where(RuntimePreference.profile == profile))
    now = utcnow()
    if row is None:
        row = RuntimePreference(profile=profile, updated_at=now)
        db.add(row)

    updated: dict[str, object] = {}

    if command == "/show-settings":
        db.flush()
        return SlashCommandResponse(
            status="ok",
            message="Current settings",
            profile=profile,
            updated={},
            preference=_serialize_preference(row, profile),
        )
    if command == "/set-model":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-model <model>")
        row.model = parts[1]
        updated["model"] = row.model
    elif command == "/set-thinking":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-thinking <on|off>")
        try:
            row.thinking = _parse_on_off(parts[1])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        updated["thinking"] = row.thinking
    elif command == "/set-verbose":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-verbose <on|off>")
        try:
            row.verbose = _parse_on_off(parts[1])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        updated["verbose"] = row.verbose
    elif command == "/set-compaction":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-compaction <on|off>")
        try:
            row.compaction = _parse_on_off(parts[1])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        updated["compaction"] = row.compaction
    elif command == "/set-temperature":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-temperature <number|none>")
        if parts[1].lower() == "none":
            row.temperature = None
        else:
            try:
                row.temperature = float(parts[1])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="temperature must be a number or 'none'") from exc
        updated["temperature"] = row.temperature
    elif command == "/set-max-tokens":
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Usage: /set-max-tokens <int|none>")
        if parts[1].lower() == "none":
            row.max_tokens = None
        else:
            try:
                row.max_tokens = int(parts[1])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="max_tokens must be an integer or 'none'") from exc
        updated["max_tokens"] = row.max_tokens
    else:
        raise HTTPException(status_code=400, detail=f"Unknown command '{command}'. {_slash_help_text()}")

    row.updated_at = now
    db.commit()
    db.refresh(row)
    return SlashCommandResponse(
        status="ok",
        message="Settings updated",
        profile=profile,
        updated=updated,
        preference=_serialize_preference(row, profile),
    )


@app.post("/api/auth-sessions/start", response_model=AuthSessionView, dependencies=[Depends(require_api_key)])
def auth_session_start(payload: AuthSessionStartRequest, db: Session = Depends(get_db)) -> AuthSessionView:
    adapter = PROVIDER_ADAPTERS.get(payload.provider)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {payload.provider}")

    try:
        session = adapter.start_auth(payload.profile, payload.flow, payload.redirect_uri)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to start auth session: {exc}") from exc

    now = utcnow()
    row = ProviderAuthSession(
        id=session.session_id,
        provider=payload.provider,
        profile=payload.profile,
        status="pending",
        verification_uri=session.verification_uri,
        user_code=session.user_code,
        expires_at=(now + timedelta(seconds=int(session.expires_in_seconds))) if session.expires_in_seconds else None,
        interval_seconds=session.interval_seconds,
        state_json=session.state_json or {"flow": session.flow},
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.commit()
    return _to_auth_session_view(row)


@app.post("/api/auth-sessions/poll", response_model=AuthSessionView, dependencies=[Depends(require_api_key)])
def auth_session_poll(payload: AuthSessionPollRequest, db: Session = Depends(get_db)) -> AuthSessionView:
    row = db.scalar(select(ProviderAuthSession).where(ProviderAuthSession.id == payload.session_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Auth session not found")

    if row.status in {"authorized", "expired", "failed", "canceled"}:
        return _to_auth_session_view(row)

    adapter = PROVIDER_ADAPTERS.get(row.provider)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter registered for provider: {row.provider}")

    result = adapter.poll_or_exchange(row.id, row.state_json)
    now = utcnow()
    row.last_polled_at = now
    row.updated_at = now

    if result.status == "authorized" and result.access_token:
        row.status = "authorized"
        row.error = None

        oauth = db.scalar(
            select(OAuthCredential).where(
                OAuthCredential.provider == row.provider,
                OAuthCredential.profile == row.profile,
            )
        )
        expires_at = now + timedelta(seconds=int(result.expires_in_seconds)) if result.expires_in_seconds else None
        if oauth is None:
            oauth = OAuthCredential(
                provider=row.provider,
                profile=row.profile,
                account_hint=None,
                encrypted_access_token=encrypt_text(result.access_token),
                encrypted_refresh_token=encrypt_text(result.refresh_token) if result.refresh_token else None,
                expires_at=expires_at,
                state="active",
                refresh_failure_count=0,
                scopes=[],
                metadata_json={"source": "auth_session"},
                created_at=now,
                updated_at=now,
            )
            db.add(oauth)
        else:
            oauth.encrypted_access_token = encrypt_text(result.access_token)
            if result.refresh_token:
                oauth.encrypted_refresh_token = encrypt_text(result.refresh_token)
            oauth.expires_at = expires_at
            oauth.state = "active"
            oauth.refresh_failure_count = 0
            oauth.next_retry_at = None
            oauth.last_error = None
            oauth.updated_at = now

    elif result.status == "expired":
        row.status = "expired"
        row.error = result.error or "expired"
    elif result.status == "failed":
        row.status = "failed"
        row.error = result.error or "failed"
    else:
        row.status = "pending"
        row.error = result.error

    db.commit()
    return _to_auth_session_view(row)


@app.post("/api/auth-sessions/complete", response_model=AuthSessionView, dependencies=[Depends(require_api_key)])
def auth_session_complete(payload: AuthSessionCompleteRequest, db: Session = Depends(get_db)) -> AuthSessionView:
    if payload.authorization_code:
        row = db.scalar(select(ProviderAuthSession).where(ProviderAuthSession.id == payload.session_id))
        if row is None:
            raise HTTPException(status_code=404, detail="Auth session not found")
        adapter = PROVIDER_ADAPTERS.get(row.provider)
        if adapter is None:
            raise HTTPException(status_code=400, detail=f"No adapter registered for provider: {row.provider}")

        result = adapter.exchange_code(payload.authorization_code, row.state_json)
        now = utcnow()
        row.last_polled_at = now
        row.updated_at = now

        if result.status == "authorized" and result.access_token:
            row.status = "authorized"
            row.error = None
            oauth = db.scalar(
                select(OAuthCredential).where(
                    OAuthCredential.provider == row.provider,
                    OAuthCredential.profile == row.profile,
                )
            )
            expires_at = now + timedelta(seconds=int(result.expires_in_seconds)) if result.expires_in_seconds else None
            if oauth is None:
                oauth = OAuthCredential(
                    provider=row.provider,
                    profile=row.profile,
                    account_hint=None,
                    encrypted_access_token=encrypt_text(result.access_token),
                    encrypted_refresh_token=encrypt_text(result.refresh_token) if result.refresh_token else None,
                    expires_at=expires_at,
                    state="active",
                    refresh_failure_count=0,
                    scopes=[],
                    metadata_json={"source": "auth_session_browser"},
                    created_at=now,
                    updated_at=now,
                )
                db.add(oauth)
            else:
                oauth.encrypted_access_token = encrypt_text(result.access_token)
                if result.refresh_token:
                    oauth.encrypted_refresh_token = encrypt_text(result.refresh_token)
                oauth.expires_at = expires_at
                oauth.state = "active"
                oauth.refresh_failure_count = 0
                oauth.next_retry_at = None
                oauth.last_error = None
                oauth.updated_at = now

            db.commit()
            return _to_auth_session_view(row)

        row.status = "failed"
        row.error = result.error or "authorization_code_exchange_failed"
        db.commit()
        raise HTTPException(status_code=409, detail=f"Auth session not complete. Current status: {row.status}")

    view = auth_session_poll(AuthSessionPollRequest(session_id=payload.session_id), db)
    if view.status != "authorized":
        raise HTTPException(status_code=409, detail=f"Auth session not complete. Current status: {view.status}")
    return view


@app.post("/api/auth-sessions/cancel", response_model=AuthSessionView, dependencies=[Depends(require_api_key)])
def auth_session_cancel(payload: AuthSessionCancelRequest, db: Session = Depends(get_db)) -> AuthSessionView:
    row = db.scalar(select(ProviderAuthSession).where(ProviderAuthSession.id == payload.session_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Auth session not found")

    row.status = "canceled"
    row.error = "canceled_by_request"
    row.updated_at = utcnow()
    db.commit()
    return _to_auth_session_view(row)


@app.get("/v1/models", dependencies=[Depends(require_api_key)])
def openai_models(profile: str = Query(default="default"), db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(RuntimePreference)).all()
    model_ids = {r.model for r in rows if r.model}
    model_ids.update(DEFAULT_MODELS.values())
    model_ids.add("router-auto")

    data = [
        {
            "id": model_id,
            "object": "model",
            "created": 0,
            "owned_by": "authorization-station",
        }
        for model_id in sorted(model_ids)
    ]

    return {
        "object": "list",
        "data": data,
        "profile": profile,
    }


@app.post("/v1/chat/completions", dependencies=[Depends(require_api_key)])
def openai_chat_completions(payload: dict, db: Session = Depends(get_db)) -> dict:
    profile = payload.get("profile") or settings.default_profile
    provider_hints = payload.get("provider_hints") or []
    route_request = RouteDecisionRequest(
        profile=profile,
        provider_hints=provider_hints,
        model=payload.get("model"),
        thinking=payload.get("thinking"),
        verbose=payload.get("verbose"),
        compaction=payload.get("compaction"),
        metadata_json=payload.get("metadata_json") or {},
    )
    decision = _route(db, route_request)

    if decision.provider not in {"openai", "google", "gemini", "antigravity", "litellm"}:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Provider '{decision.provider}' OpenAI-compatible proxy not implemented yet",
        )

    token_row = db.scalar(
        select(OAuthCredential).where(
            OAuthCredential.provider == decision.provider,
            OAuthCredential.profile == profile,
        )
    )
    if token_row is None:
        raise HTTPException(status_code=404, detail=f"{decision.provider} credential not found for profile")

    upstream_payload = dict(payload)
    upstream_payload["model"] = decision.selected_model
    upstream_payload.pop("provider_hints", None)
    upstream_payload.pop("profile", None)
    upstream_payload.pop("thinking", None)
    upstream_payload.pop("verbose", None)
    upstream_payload.pop("compaction", None)
    upstream_payload.pop("metadata_json", None)

    access_token = decrypt_text(token_row.encrypted_access_token)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    use_cloudcode = decision.provider in {"gemini", "antigravity"}

    if decision.provider == "openai":
        upstream_url = OPENAI_CHAT_COMPLETIONS_URL
    elif use_cloudcode:
        upstream_url = f"{GEMINI_CLOUDCODE_BASE}/models/{upstream_payload['model']}:generateContent"
    elif decision.provider == "google":
        upstream_url = GEMINI_CHAT_COMPLETIONS_URL
        if settings.google_project_id:
            headers["x-goog-user-project"] = settings.google_project_id
    else:
        base_url = (settings.litellm_base_url or "").rstrip("/")
        if not base_url:
            raise HTTPException(
                status_code=400,
                detail="AUTH_STATION_LITELLM_BASE_URL is required when routing to provider 'litellm'",
            )
        upstream_url = f"{base_url}/v1/chat/completions"
        litellm_key = settings.litellm_api_key or access_token
        headers["Authorization"] = f"Bearer {litellm_key}"

    if use_cloudcode:
        contents, system_parts = _openai_to_gemini_contents(upstream_payload.get("messages", []))
        gemini_payload = {
            "contents": contents,
            "generationConfig": {},
        }
        if system_parts:
            gemini_payload["systemInstruction"] = {"parts": system_parts}
        if upstream_payload.get("temperature") is not None:
            gemini_payload["generationConfig"]["temperature"] = upstream_payload["temperature"]
        if upstream_payload.get("max_tokens"):
            gemini_payload["generationConfig"]["maxOutputTokens"] = upstream_payload["max_tokens"]
        request_json = gemini_payload
    else:
        request_json = upstream_payload

    try:
        with httpx.Client(timeout=90) as client:
            response = client.post(upstream_url, json=request_json, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream {decision.provider} request failed: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    if use_cloudcode:
        data = _gemini_response_to_openai(response.json(), upstream_payload["model"])
    else:
        data = response.json()
    usage_payload = UsageEventIngest(
        provider=decision.provider,
        model=data.get("model", decision.selected_model),
        profile=profile,
        request_id=data.get("id"),
        prompt_tokens=(data.get("usage") or {}).get("prompt_tokens"),
        completion_tokens=(data.get("usage") or {}).get("completion_tokens"),
        total_tokens=(data.get("usage") or {}).get("total_tokens"),
        duration_seconds=None,
        metadata_json={"source": "openai_compatible_proxy", "upstream_provider": decision.provider},
    )
    ingest_usage(usage_payload, db)
    return data


@app.get("/api/providers/status", dependencies=[Depends(require_api_key)])
def provider_status(profile: str = Query(default="default"), db: Session = Depends(get_db)) -> list[dict]:
    quota_rows = {row.provider: row for row in db.scalars(select(ProviderQuota)).all()}
    response: list[dict] = []
    for provider in SUPPORTED_PROVIDERS:
        quota = quota_rows.get(provider)
        response.append(
            {
                "provider": provider,
                "adapter_registered": provider in PROVIDER_ADAPTERS,
                "token_available": _is_token_available(db, provider, profile),
                "remaining_seconds": quota.remaining_seconds if quota else None,
                "remaining_tokens": quota.remaining_tokens if quota else None,
                "notes": quota.notes if quota else None,
            }
        )
    return response


@app.get(
    "/api/providers/{provider}/credentials/{profile}/status",
    response_model=OAuthCredentialStatus,
    dependencies=[Depends(require_api_key)],
)
def credential_status(provider: str, profile: str, db: Session = Depends(get_db)) -> OAuthCredentialStatus:
    row = db.scalar(
        select(OAuthCredential).where(OAuthCredential.provider == provider, OAuthCredential.profile == profile)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    return OAuthCredentialStatus(
        provider=row.provider,
        profile=row.profile,
        state=row.state,
        expires_at=row.expires_at,
        last_refresh_attempt=row.last_refresh_attempt,
        refresh_failure_count=row.refresh_failure_count,
        next_retry_at=row.next_retry_at,
        last_error=row.last_error,
    )


@app.post("/webhooks/n8n/route", response_model=RouteDecisionResponse)
def n8n_route_webhook(
    payload: N8NRouteWebhook,
    db: Session = Depends(get_db),
    x_n8n_secret: str | None = Header(default=None),
) -> RouteDecisionResponse:
    if settings.n8n_webhook_secret and x_n8n_secret != settings.n8n_webhook_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid n8n secret")

    request = RouteDecisionRequest(
        profile=payload.profile,
        provider_hints=payload.provider_hints,
        model=payload.model,
        thinking=payload.thinking,
        verbose=payload.verbose,
        compaction=payload.compaction,
        metadata_json=payload.metadata_json,
    )
    return _route(db, request)
