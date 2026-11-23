"""Shared SQLite path resolution for the Flask app and database utilities."""

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def configured_database_path(app_env=None):
    """Return the configured database path, enforcing production requirements."""
    environment = app_env if app_env is not None else os.environ.get("APP_ENV", "development")
    production = str(environment).strip().lower() == "production"
    configured = os.environ.get("DATABASE_PATH", "").strip()

    if production and not configured:
        raise RuntimeError(
            "DATABASE_PATH must point to the existing SQLite file on persistent storage in production."
        )

    if configured:
        candidate = Path(configured).expanduser()
        if production and not candidate.is_absolute():
            raise RuntimeError("DATABASE_PATH must be an absolute path in production.")
        path = candidate.resolve()
    else:
        path = BASE_DIR / "database.db"

    if production and not path.is_file():
        raise RuntimeError(
            "The configured production SQLite database file does not exist; refusing to create an empty database."
        )
    return path
