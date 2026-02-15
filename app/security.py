import base64
import hashlib
from datetime import datetime, timezone

from cryptography.fernet import Fernet

from app.config import settings


def _fernet() -> Fernet:
    key_material = hashlib.sha256(settings.encryption_key.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(key_material)
    return Fernet(key)


def encrypt_text(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_text(value: str) -> str:
    return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
