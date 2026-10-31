"""Fixtures shared by the integration tests."""

import os
from collections.abc import Iterator

import pytest

from ingest.egress import set_gate

from .db_fixtures import engine, factory, migrated  # noqa: F401
from .helpers import fake_gate

# The cross-service tests exercise the REST routes, not the login flow: run the API with auth open.
os.environ.setdefault("API_AUTH_DISABLED", "true")
os.environ.setdefault("SUCKERPOT_DEMO", "1")


@pytest.fixture(autouse=True)
def _open_egress_gate() -> Iterator[None]:
    """Workers get an open gate with no network behind it: their HTTP clients are injected fakes.

    Tests of the closed behaviour pass their own closed gate. The default, unpatched gate is
    closed (see ``test_egress_gate.py``).
    """
    set_gate(fake_gate())
    yield
    set_gate(None)
