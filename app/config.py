"""VOIDTRACE Application Configuration.

Separates operational settings and Switch connection parameters from business logic.
All values are loaded from environment variables or a .env file via Pydantic Settings.
No credentials are hardcoded here.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application Info
    APP_NAME: str = "VOIDTRACE"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Server Binding
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Switch Core Topology (Inspected from ports.json and switch-core.env)
    # Switch Core REST API runs on port 53450
    SWITCH_SERVER_URL: str = "http://127.0.0.1:53450"
    SWITCH_WS_URL: str = "ws://127.0.0.1:53450"

    # Bootstrap Registration Token.
    # Must be set in the environment (or .env) before registration is attempted.
    # Accepts either name so the Switch Core value can be exported directly.
    # An empty value means registration is disabled; the backend still starts normally.
    SWITCH_REGISTRATION_TOKEN: str = Field(
        default="",
        validation_alias=AliasChoices(
            "SWITCH_REGISTRATION_TOKEN",
            "AGENT_REGISTRATION_TOKEN",
        ),
    )

    # Switch Agent Identity
    AGENT_NAME: str = "voidtrace"
    AGENT_DISPLAY_NAME: str = "VOIDTRACE"
    AGENT_DESCRIPTION: str = "Defensive AI-powered security incident investigation and response platform"

    # SQLite Database Configuration
    DATABASE_PATH: Path = Path("voidtrace.db")

    # Connection Retry Parameters
    AUTO_CONNECT_SWITCH: bool = True
    SWITCH_RECONNECT_INITIAL_DELAY: float = 2.0
    SWITCH_RECONNECT_MAX_DELAY: float = 30.0
    SWITCH_HEARTBEAT_INTERVAL: float = 2.0


settings = Settings()
