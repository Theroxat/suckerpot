"""Anonymous egress: every outbound call goes through the VPN proxy, behind a kill-switch gate."""

from suckerpot_egress.client import GateTransport, egress_client
from suckerpot_egress.gate import REASONS, EgressClosed, EgressGate, GateStatus
from suckerpot_egress.settings import EgressSettings
from suckerpot_egress.smtp import TunnelSMTP, TunnelSMTP_SSL
from suckerpot_egress.tunnel import TunnelError, open_tunnel

__all__ = [
    "REASONS",
    "EgressClosed",
    "EgressGate",
    "EgressSettings",
    "GateStatus",
    "GateTransport",
    "TunnelError",
    "TunnelSMTP",
    "TunnelSMTP_SSL",
    "egress_client",
    "open_tunnel",
]
