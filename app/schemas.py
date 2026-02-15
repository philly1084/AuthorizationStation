from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OAuthCredentialUpsert(BaseModel):
    provider: str
    profile: str = "default"
    account_hint: str | None = None
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    scopes: list[str] = Field(default_factory=list)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class OAuthCredentialView(BaseModel):
    provider: str
    profile: str
    account_hint: str | None = None
    expires_at: datetime | None = None
    scopes: list[str]
    metadata_json: dict[str, Any]


class OAuthCredentialStatus(BaseModel):
    provider: str
    profile: str
    state: str
    expires_at: datetime | None = None
    last_refresh_attempt: datetime | None = None
    refresh_failure_count: int
    next_retry_at: datetime | None = None
    last_error: str | None = None


class RuntimePreferenceUpsert(BaseModel):
    profile: str = "default"
    model: str | None = None
    thinking: bool = False
    verbose: bool = False
    compaction: bool = False
    temperature: float | None = None
    max_tokens: int | None = None


class SlashCommandRequest(BaseModel):
    profile: str = "default"
    command_text: str


class SlashCommandResponse(BaseModel):
    status: str
    message: str
    profile: str
    updated: dict[str, Any] = Field(default_factory=dict)
    preference: dict[str, Any] = Field(default_factory=dict)


class RouteDecisionRequest(BaseModel):
    profile: str | None = None
    provider_hints: list[str] = Field(default_factory=list)
    model: str | None = None
    thinking: bool | None = None
    verbose: bool | None = None
    compaction: bool | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class RouteDecisionResponse(BaseModel):
    provider: str
    profile: str
    selected_model: str
    flags: dict[str, Any]
    token_available: bool


class UsageEventIngest(BaseModel):
    provider: str
    model: str | None = None
    profile: str = "default"
    request_id: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    duration_seconds: float | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class ProviderQuotaUpdate(BaseModel):
    provider: str
    remaining_seconds: int | None = None
    remaining_tokens: int | None = None
    notes: str | None = None


class AuthSessionStartRequest(BaseModel):
    provider: str
    profile: str = "default"
    flow: str = "device"
    redirect_uri: str | None = None


class AuthSessionView(BaseModel):
    id: str
    provider: str
    profile: str
    status: str
    flow: str = "device"
    verification_uri: str | None = None
    user_code: str | None = None
    expires_at: datetime | None = None
    interval_seconds: int | None = None
    error: str | None = None


class AuthSessionPollRequest(BaseModel):
    session_id: str


class AuthSessionCompleteRequest(BaseModel):
    session_id: str
    authorization_code: str | None = None


class AuthSessionCancelRequest(BaseModel):
    session_id: str


class N8NRouteWebhook(BaseModel):
    profile: str | None = None
    provider_hints: list[str] = Field(default_factory=list)
    model: str | None = None
    thinking: bool | None = None
    verbose: bool | None = None
    compaction: bool | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
