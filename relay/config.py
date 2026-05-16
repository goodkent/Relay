from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY: str=os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
    SQLALCHEMY_DATABASE_URI: str=os.environ.get("DATABASE_URL",f"sqlite:///{BASE_DIR / 'relay.db'}")

    SESSION_COOKIE_SECURE: bool=True
    SESSION_COOKIE_HTTPONLY: bool=True
    SESSION_COOKIE_SAMESITE: str="Lax"

class DevelopmentConfig(Config):
    DEBUG: bool = True
    SESSION_COOKIE_SECURE: bool = False

class TestingConfig(Config):
    TESTING: bool = True
    SQLACLCHEMY_DATABASE_URI: str="sqlite:///:memory:"
    SESSION_COOKIE_SECURE: bool = False
    SECRET_KEY: str = "test-secret-key"

class ProductionConfig(Config):
    pass