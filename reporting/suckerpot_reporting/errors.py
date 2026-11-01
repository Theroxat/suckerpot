"""Exceptions of the reporting package. Messages are constant codes, never values."""

from __future__ import annotations


class ReportingError(Exception):
    """Base class. ``code`` is a short constant suitable for an API answer."""

    code = "reporting_error"

    def __init__(self, code: str | None = None) -> None:
        self.code = code or type(self).code
        super().__init__(self.code)


class RenderUnavailable(ReportingError):
    """The requested format cannot be produced for this report (e.g. no reply contact)."""

    code = "render_unavailable"


class GuardFailed(ReportingError):
    """The identity guard refused an artefact. ``codes`` holds reason codes only."""

    code = "identity_guard_failed"

    def __init__(self, codes: tuple[str, ...]) -> None:
        super().__init__()
        self.codes = codes


class BundleLimitError(ReportingError):
    code = "bundle_limit"
