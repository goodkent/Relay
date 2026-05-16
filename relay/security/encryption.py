from __future__ import annotations
import os
from cryptography.fernet import Fernet
import sqlalchemy as sa
from sqlalchemy.types import TypeDecorator

_fernet: Fernet | None = None

def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ.get("RELAY_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("RELAY_ENCRYPTION_KEY is not set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"")
        _fernet = Fernet(key.encode())
    return _fernet

class EncryptedString(TypeDecorator):
    impl = sa.String
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return _get_fernet().encrypt(value.encode()).decode()

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return _get_fernet().decrypt(value.encode()).decode()