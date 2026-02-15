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
    litellm_base_url: str | None = None
    litellm_api_key: str | None = None
    refresh_check_interval_seconds: int = 60
    refresh_lead_seconds: int = 300


settings = Settings()
