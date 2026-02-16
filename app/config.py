from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="AUTH_STATION_")

    api_key: str
    encryption_key: str
    database_url: str = "sqlite:///./data/registry.db"
    n8n_webhook_secret: str | None = None
    default_profile: str = "default"
    google_oauth_client_id: str | None = None
    google_oauth_client_secret: str | None = None
    google_oauth_scope: str = "openid email profile"
    google_oauth_redirect_uri: str | None = None
    # Gemini CLI built-in OAuth (same as Cline / OpenClaw)
    gemini_cli_client_id: str = ""
    gemini_cli_client_secret: str = ""
    gemini_cli_redirect_uri: str = "http://localhost:3333/callback"
    gemini_cli_scopes: str = (
        "openid email profile "
        "https://www.googleapis.com/auth/cloud-platform "
        "https://www.googleapis.com/auth/generative-language.retriever "
        "https://www.googleapis.com/auth/generative-language.tuning"
    )
    # Antigravity / Cloud Code built-in OAuth
    antigravity_client_id: str = ""
    antigravity_redirect_uri: str = "http://localhost:36742/oauth-callback"
    antigravity_scopes: str = (
        "https://www.googleapis.com/auth/cloud-platform "
        "https://www.googleapis.com/auth/userinfo.email "
        "https://www.googleapis.com/auth/userinfo.profile "
        "https://www.googleapis.com/auth/cclog "
        "https://www.googleapis.com/auth/experimentsandconfigs"
    )
    # OpenAI Codex CLI built-in OAuth (public PKCE client)
    codex_client_id: str = ""
    codex_redirect_uri: str = "http://localhost:1455/auth/callback"
    codex_scopes: str = "openid profile email offline_access"
    litellm_base_url: str | None = None
    litellm_api_key: str | None = None
    refresh_check_interval_seconds: int = 60
    refresh_lead_seconds: int = 300


settings = Settings()
