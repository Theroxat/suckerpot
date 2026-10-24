"""Fixtures shared by the integration tests."""

import os

from .db_fixtures import engine, factory, migrated  # noqa: F401

# The cross-service tests exercise the REST routes, not the login flow: run the API with auth open.
os.environ.setdefault("API_AUTH_DISABLED", "true")
os.environ.setdefault("SUCKERPOT_DEMO", "1")
