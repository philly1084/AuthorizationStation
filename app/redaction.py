import re
from typing import Any

SENSITIVE_KEYS = {
    "authorization",
    "x-api-key",
    "access_token",
    "refresh_token",
    "token",
    "client_secret",
    "code",
    "device_code",
    "user_code",
}

REDACTION = "***REDACTED***"
TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+)[^\s]+")


def redact_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return TOKEN_PATTERN.sub(rf"\1{REDACTION}", value)


def redact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            sanitized[key] = REDACTION
        elif isinstance(value, dict):
            sanitized[key] = redact_mapping(value)
        elif isinstance(value, list):
            sanitized[key] = [redact_mapping(v) if isinstance(v, dict) else redact_value(v) for v in value]
        else:
            sanitized[key] = redact_value(value)
    return sanitized
