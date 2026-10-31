"""Shared pydantic models: the contract between the analysis library and the collector."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ANALYSIS_VERSION = 1

IocKind = Literal["next_url", "c2_ip", "c2_domain", "c2_url"]
IocSource = Literal["script_url", "binary_ip_port", "binary_string", "mirai_table"]
Confidence = Literal["high", "low"]
Severity = Literal["info", "notice", "warning", "severe"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Limits(_Model):
    """Hard bounds. Every parser honours these; none is ever exceeded silently."""

    max_input: int = 16 * 1024 * 1024
    string_scan_bytes: int = 16 * 1024 * 1024
    max_strings: int = 500
    string_max_len: int = 120
    yara_timeout_s: int = 10
    max_headers: int = 256
    deob_max_input: int = 1024 * 1024
    deob_max_passes: int = 5
    deob_max_out: int = 256 * 1024
    max_iocs: int = 200
    max_yara_hits: int = 50


class FileInfo(_Model):
    kind: str = "unknown"  # elf, pe, macho, script, gzip, zip, tar, xz, 7z, bzip2, text, data
    arch: str | None = None
    bits: int | None = None
    endian: Literal["little", "big"] | None = None
    linking: Literal["static", "dynamic"] | None = None
    stripped: bool | None = None
    is_dll: bool | None = None
    packer: str | None = None
    interpreter: str | None = None  # script shebang, e.g. "sh"


class Digests(_Model):
    sha256: str
    sha1: str
    md5: str
    tlsh: str | None = None


class YaraHit(_Model):
    rule: str
    namespace: str
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, str | int | bool] = Field(default_factory=dict)


class DeobStep(_Model):
    kind: str
    count: int


class Deobfuscation(_Model):
    text: str
    steps: list[DeobStep] = Field(default_factory=list)
    truncated: bool = False


class Ioc(_Model):
    kind: IocKind
    value: str = Field(max_length=1024)
    port: int | None = None
    source: IocSource
    confidence: Confidence


class AnalysisResult(_Model):
    version: int = ANALYSIS_VERSION
    file: FileInfo
    digests: Digests
    yara: list[YaraHit] = Field(default_factory=list, max_length=50)
    family: str | None = None
    tags: list[str] = Field(default_factory=list)
    severity: Severity = "notice"
    strings: list[str] = Field(default_factory=list, max_length=500)
    deobfuscated: str | None = Field(default=None, max_length=262144)
    deob_steps: list[DeobStep] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list, max_length=200)
    errors: list[str] = Field(default_factory=list)
