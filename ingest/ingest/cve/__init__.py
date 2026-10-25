"""CVE watch: a daily job that mirrors public vulnerability data into the ``cve`` table."""

from ingest.cve.watch import CveWatch

__all__ = ["CveWatch"]
