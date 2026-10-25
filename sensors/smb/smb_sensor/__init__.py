"""SuckerPot SMB sensor: a low-interaction observation sink for SMB2/3 and legacy SMB1.

It parses NetBIOS session framing and SMB headers, answers NEGOTIATE and SESSION_SETUP like a
modern Windows file server, records what clients send (dialects, NTLM credentials, commands,
probes) and then closes. It never grants a session, never executes anything, never reproduces
any vulnerable behaviour and never makes an outbound connection.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
