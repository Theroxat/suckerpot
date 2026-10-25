"""Best-effort client-tool identification from the signals we already capture.

Nothing here parses new bytes: it only combines fingerprints the handshake already produced —
the TLS ClientHello JA3, the ``mstshash`` cookie, the CredSSP protocol version, the NTLM
NEGOTIATE flags and client OS version, the requested protocols, and (on the NLA-off path) the
GCC client build and client name. The result is a single ``client_tool`` guess plus the short
reasons behind it, attached to the ``login_attempt`` / ``disconnect`` data.

The signatures below were captured from real tools run in throwaway containers against the
sensor (see the README table). Tools that share a TLS/NTLM stack collapse to that stack: hydra
and ncrack's CredSSP brute-forcing both ride FreeRDP, so at the per-connection level they look
like FreeRDP; their brute-force *pattern* (many short sessions) is what ingest tags, not this
per-connection guess. Anything unmatched is ``unknown``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# JA3 MD5 hashes observed from real tools (FreeRDP 2.x, nmap 7.94, rdesktop 1.9).
_JA3: dict[str, str] = {
    "24b17abb1c18a4c5eb806eb218774f32": "nmap",  # nmap rdp-ntlm-info / rdp-enum-encryption
    "a3afc2c46ba4a7d7fbe1cfb7a3031c2f": "FreeRDP",  # xfreerdp, and hydra/ncrack built on libfreerdp
    "b19598fb776b9d0e9d2f428f249858c7": "rdesktop",
}

# NTLM NEGOTIATE flag words observed from real tools (extend as captures are added).
_NTLM_FLAGS: dict[int, str] = {}

# mstshash cookie user names that some tools send verbatim.
_COOKIE_NAMES: dict[str, str] = {
    "nmap": "nmap",
    "ncrack_user": "ncrack",
}

# clientName substrings (case-insensitive) that pin a tool (GCC CS_CORE, NLA-off path).
_NAME_HINTS: tuple[tuple[str, str], ...] = (
    ("freerdp", "FreeRDP"),
    ("rdesktop", "rdesktop"),
    ("ncrack", "ncrack"),
)

# Well-known clientBuild values; a weak, late signal (build numbers are trivially spoofed).
_BUILDS: dict[int, str] = {
    2600: "mstsc",  # Windows XP / Server 2003 mstsc (rdesktop also mimics it)
    6002: "mstsc",
    7601: "mstsc",
}


@dataclass
class Signals:
    ja3_hash: str | None = None
    cookie_name: str | None = None
    cookie_username: bool = False
    credssp_version: int | None = None
    ntlm_flags: int | None = None
    ntlm_os_version: str | None = None
    requested_protocols: int = 0
    reached_ntlm: bool = False
    gcc_client_name: str | None = None
    gcc_client_build: int | None = None


@dataclass
class Guess:
    tool: str
    reasons: list[str] = field(default_factory=list)


def identify(sig: Signals) -> Guess:
    """Return the best ``client_tool`` guess for the captured signals."""
    reasons: list[str] = []

    # 1) A tool-specific mstshash cookie value is the most reliable pin.
    if sig.cookie_name is not None:
        tool = _COOKIE_NAMES.get(sig.cookie_name.strip().lower())
        if tool is not None:
            reasons.append(f"cookie={sig.cookie_name}")
            return Guess(tool, reasons)

    # 2) GCC client name hints (NLA-off path).
    if sig.gcc_client_name:
        low = sig.gcc_client_name.lower()
        for needle, tool in _NAME_HINTS:
            if needle in low:
                reasons.append(f"client_name~{needle}")
                return Guess(tool, reasons)

    # 3) The TLS JA3 fingerprint pins the client's TLS stack.
    if sig.ja3_hash and sig.ja3_hash in _JA3:
        reasons.append("ja3")
        return Guess(_JA3[sig.ja3_hash], reasons)

    # 4) An exact NTLM NEGOTIATE flag word.
    if sig.ntlm_flags is not None and sig.ntlm_flags in _NTLM_FLAGS:
        reasons.append(f"ntlm_flags=0x{sig.ntlm_flags:08x}")
        return Guess(_NTLM_FLAGS[sig.ntlm_flags], reasons)

    # 5) A known clientBuild (weak, late).
    if sig.gcc_client_build is not None and sig.gcc_client_build in _BUILDS:
        reasons.append(f"client_build={sig.gcc_client_build}")
        return Guess(_BUILDS[sig.gcc_client_build], reasons)

    # 6) Coarse behavioural fallbacks.
    #    A client that negotiates CredSSP but sends no cookie and stops at the challenge is the
    #    classic rdp-ntlm-info / rdp-enum-encryption scanner behaviour.
    if sig.reached_ntlm and not sig.cookie_username:
        reasons.append("ntlm_info_probe")
        return Guess("nmap", reasons)
    #    An OS version in the NEGOTIATE points at a Windows-stack client (mstsc / Windows).
    if sig.ntlm_os_version and sig.ntlm_os_version.startswith("10.0"):
        reasons.append(f"ntlm_os={sig.ntlm_os_version}")
        return Guess("mstsc", reasons)

    return Guess("unknown", reasons)
