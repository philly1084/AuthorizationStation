from dataclasses import dataclass
from datetime import timedelta
import base64
import hashlib
from typing import Protocol
from uuid import uuid4
from urllib.parse import urlencode

import httpx

from app.config import settings
from app.security import utcnow


@dataclass
class AuthSession:
    session_id: str
    provider: str
    profile: str
    verification_uri: str | None = None
    user_code: str | None = None
    expires_in_seconds: int | None = None
    interval_seconds: int | None = None
    state_json: dict | None = None
    flow: str = "device"


@dataclass
class AuthPollResult:
    status: str
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in_seconds: int | None = None
    error: str | None = None


class ProviderAuthAdapter(Protocol):
    provider_name: str

    def start_auth(self, profile: str, flow: str = "device", redirect_uri: str | None = None) -> AuthSession:
        ...

    def poll_or_exchange(self, session_id: str, state_json: dict | None = None) -> AuthPollResult:
        ...

    def exchange_code(self, authorization_code: str, state_json: dict | None = None) -> AuthPollResult:
        ...

    def refresh(self, refresh_token: str) -> AuthPollResult:
        ...

    def revoke(self, access_token: str) -> bool:
        ...

    def validate(self, access_token: str) -> bool:
        ...


class _BaseStubAdapter:
    provider_name = "unknown"

    def start_auth(self, profile: str, flow: str = "device", redirect_uri: str | None = None) -> AuthSession:
        return AuthSession(
            session_id=f"stub-{self.provider_name}-{profile}",
            provider=self.provider_name,
            profile=profile,
            state_json={},
            flow=flow,
        )

    def poll_or_exchange(self, session_id: str, state_json: dict | None = None) -> AuthPollResult:
        return AuthPollResult(status="pending")

    def exchange_code(self, authorization_code: str, state_json: dict | None = None) -> AuthPollResult:
        return AuthPollResult(status="failed", error="code_exchange_not_implemented")

    def refresh(self, refresh_token: str) -> AuthPollResult:
        return AuthPollResult(status="failed", error="refresh_not_implemented")

    def revoke(self, access_token: str) -> bool:
        return False

    def validate(self, access_token: str) -> bool:
        return bool(access_token)


class GoogleAdapter(_BaseStubAdapter):
    provider_name = "google"

    _AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    _DEVICE_AUTH_URL = "https://oauth2.googleapis.com/device/code"
    _TOKEN_URL = "https://oauth2.googleapis.com/token"
    _DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

    def _client_id(self) -> str:
        if not settings.google_oauth_client_id:
            raise ValueError("AUTH_STATION_GOOGLE_OAUTH_CLIENT_ID is required for Google device flow")
        return settings.google_oauth_client_id

    def _scope(self) -> str:
        return settings.google_oauth_scope or "openid email profile"

    @staticmethod
    def _pkce_pair() -> tuple[str, str]:
        verifier = uuid4().hex + uuid4().hex
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        return verifier, challenge

    def _start_browser_auth(self, profile: str, redirect_uri: str | None) -> AuthSession:
        client_id = self._client_id()
        redirect = redirect_uri or settings.google_oauth_redirect_uri
        if not redirect:
            raise ValueError("redirect_uri is required for browser auth flow")

        verifier, challenge = self._pkce_pair()
        state = uuid4().hex
        session_id = f"google-{uuid4().hex[:20]}"

        query = urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": self._scope(),
                "access_type": "offline",
                "prompt": "consent",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
            }
        )
        auth_url = f"{self._AUTH_URL}?{query}"
        return AuthSession(
            session_id=session_id,
            provider=self.provider_name,
            profile=profile,
            verification_uri=auth_url,
            user_code=None,
            expires_in_seconds=600,
            interval_seconds=None,
            flow="browser",
            state_json={
                "flow": "browser",
                "code_verifier": verifier,
                "state": state,
                "redirect_uri": redirect,
                "created_at": utcnow().isoformat(),
            },
        )

    def start_auth(self, profile: str, flow: str = "device", redirect_uri: str | None = None) -> AuthSession:
        if flow == "browser":
            return self._start_browser_auth(profile, redirect_uri)

        payload = {
            "client_id": self._client_id(),
            "scope": self._scope(),
        }
        with httpx.Client(timeout=30) as client:
            response = client.post(self._DEVICE_AUTH_URL, data=payload)
        response.raise_for_status()
        body = response.json()

        expires_in = int(body.get("expires_in", 0)) if body.get("expires_in") else None
        interval_seconds = int(body.get("interval", 5))
        session_id = f"google-{uuid4().hex[:20]}"

        return AuthSession(
            session_id=session_id,
            provider=self.provider_name,
            profile=profile,
            verification_uri=body.get("verification_url") or body.get("verification_uri"),
            user_code=body.get("user_code"),
            expires_in_seconds=expires_in,
            interval_seconds=interval_seconds,
            flow="device",
            state_json={
                "flow": "device",
                "device_code": body.get("device_code"),
                "created_at": utcnow().isoformat(),
                "expires_at": (utcnow() + timedelta(seconds=expires_in)).isoformat() if expires_in else None,
            },
        )

    def poll_or_exchange(self, session_id: str, state_json: dict | None = None) -> AuthPollResult:
        if (state_json or {}).get("flow") == "browser":
            return AuthPollResult(status="pending", error="authorization_code_required")

        device_code = (state_json or {}).get("device_code")
        if not device_code:
            return AuthPollResult(status="failed", error="missing_device_code")

        payload = {
            "client_id": self._client_id(),
            "client_secret": settings.google_oauth_client_secret,
            "device_code": device_code,
            "grant_type": self._DEVICE_GRANT_TYPE,
        }
        with httpx.Client(timeout=30) as client:
            response = client.post(self._TOKEN_URL, data=payload)
        body = response.json()

        if response.status_code >= 400:
            error = body.get("error", "unknown_error")
            if error in {"authorization_pending", "slow_down"}:
                return AuthPollResult(status="pending", error=error)
            if error == "expired_token":
                return AuthPollResult(status="expired", error=error)
            return AuthPollResult(status="failed", error=error)

        return AuthPollResult(
            status="authorized",
            access_token=body.get("access_token"),
            refresh_token=body.get("refresh_token"),
            expires_in_seconds=body.get("expires_in"),
        )

    def exchange_code(self, authorization_code: str, state_json: dict | None = None) -> AuthPollResult:
        verifier = (state_json or {}).get("code_verifier")
        redirect_uri = (state_json or {}).get("redirect_uri") or settings.google_oauth_redirect_uri
        if not verifier or not redirect_uri:
            return AuthPollResult(status="failed", error="missing_pkce_state")

        payload = {
            "client_id": self._client_id(),
            "client_secret": settings.google_oauth_client_secret,
            "code": authorization_code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
        with httpx.Client(timeout=30) as client:
            response = client.post(self._TOKEN_URL, data=payload)
        body = response.json()

        if response.status_code >= 400:
            return AuthPollResult(status="failed", error=body.get("error", "authorization_code_exchange_failed"))

        return AuthPollResult(
            status="authorized",
            access_token=body.get("access_token"),
            refresh_token=body.get("refresh_token"),
            expires_in_seconds=body.get("expires_in"),
        )

    def refresh(self, refresh_token: str) -> AuthPollResult:
        payload = {
            "client_id": self._client_id(),
            "client_secret": settings.google_oauth_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        with httpx.Client(timeout=30) as client:
            response = client.post(self._TOKEN_URL, data=payload)
        body = response.json()

        if response.status_code >= 400:
            return AuthPollResult(status="failed", error=body.get("error", "refresh_failed"))

        return AuthPollResult(
            status="authorized",
            access_token=body.get("access_token"),
            refresh_token=refresh_token,
            expires_in_seconds=body.get("expires_in"),
        )


class AntigravityAdapter(_BaseStubAdapter):
    provider_name = "antigravity"


class GeminiAdapter(GoogleAdapter):
    provider_name = "gemini"


class CodexAdapter(_BaseStubAdapter):
    provider_name = "openai"


class LiteLLMAdapter(_BaseStubAdapter):
    provider_name = "litellm"


PROVIDER_ADAPTERS: dict[str, ProviderAuthAdapter] = {
    "google": GoogleAdapter(),
    "gemini": GeminiAdapter(),
    "antigravity": AntigravityAdapter(),
    "openai": CodexAdapter(),
    "litellm": LiteLLMAdapter(),
}
