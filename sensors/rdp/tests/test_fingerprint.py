"""Client-tool identification from captured signals.

The signatures asserted here are taken from captures of real tools run in throwaway containers;
see sensors/rdp/README.md ("Client tool identification") and tests/fixtures/fingerprints.json
for the raw signals. When a new capture is added, extend the table in rdp_sensor/fingerprint.py
and a case here.
"""

from __future__ import annotations

from rdp_sensor import fingerprint
from rdp_sensor.fingerprint import Signals

# JA3 hashes captured from real tools (see README "Client tool identification").
NMAP_JA3 = "24b17abb1c18a4c5eb806eb218774f32"
FREERDP_JA3 = "a3afc2c46ba4a7d7fbe1cfb7a3031c2f"
RDESKTOP_JA3 = "b19598fb776b9d0e9d2f428f249858c7"


def test_nmap_cookie_and_ja3() -> None:
    # nmap's rdp-ntlm-info / rdp-enum-encryption send the literal cookie "mstshash=nmap".
    assert fingerprint.identify(Signals(cookie_name="nmap", cookie_username=True)).tool == "nmap"
    assert fingerprint.identify(Signals(ja3_hash=NMAP_JA3)).tool == "nmap"


def test_ncrack_cookie() -> None:
    # ncrack sends the literal cookie "mstshash=NCRACK_USER".
    sig = Signals(cookie_name="NCRACK_USER", cookie_username=True)
    assert fingerprint.identify(sig).tool == "ncrack"


def test_freerdp_ja3_covers_xfreerdp_and_freerdp_bruteforcers() -> None:
    # xfreerdp (and hydra/ncrack's CredSSP path, built on libfreerdp) share this TLS stack.
    assert fingerprint.identify(Signals(ja3_hash=FREERDP_JA3)).tool == "FreeRDP"
    # Also holds on the NLA-off path, where the same ClientHello is seen.
    sig = Signals(ja3_hash=FREERDP_JA3, gcc_client_build=18363, gcc_client_name="a6792c027f5c")
    assert fingerprint.identify(sig).tool == "FreeRDP"


def test_rdesktop_ja3() -> None:
    assert fingerprint.identify(Signals(ja3_hash=RDESKTOP_JA3)).tool == "rdesktop"


def test_gcc_client_name_hints_win_the_match() -> None:
    assert fingerprint.identify(Signals(gcc_client_name="FreeRDP-WS")).tool == "FreeRDP"
    assert fingerprint.identify(Signals(gcc_client_name="rdesktop")).tool == "rdesktop"


def test_client_build_table() -> None:
    assert fingerprint.identify(Signals(gcc_client_build=2600)).tool == "mstsc"


def test_mstsc_from_os_version() -> None:
    sig = Signals(reached_ntlm=True, cookie_username=True, ntlm_os_version="10.0.19041")
    assert fingerprint.identify(sig).tool == "mstsc"


def test_nmap_behavioural_fallback_without_cookie() -> None:
    sig = Signals(reached_ntlm=True, cookie_username=False, credssp_version=6)
    assert fingerprint.identify(sig).tool == "nmap"


def test_unknown_when_no_signal() -> None:
    assert fingerprint.identify(Signals()).tool == "unknown"
