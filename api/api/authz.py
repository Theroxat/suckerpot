"""Roles: who may call what. Default deny.

* ``admin`` may do everything; ``viewer`` may read everything an admin can read, except the
  administration screens (users, audit log), and change nothing.
* ``authorize`` runs on **every** ``/api/v1`` HTTP route (``main.create_app`` adds it when it
  includes a router): any method other than GET, HEAD and OPTIONS needs an admin unless the
  endpoint is marked ``@allow_any_role`` (sign in, sign out, change one's own password). So a
  new write route is admin-only without anybody remembering to say so.
* ``require_admin`` is added by hand to the GET routes that are for administrators only.
* ``tests/test_authz.py`` walks the route table and fails when a route escapes these rules.

The WebSocket (``/api/v1/live``) is read-only and open to both roles.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.auth import Principal, current_principal

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class AdminRequiredError(Exception):
    """The signed-in account is not an administrator."""


async def require_admin(request: Request) -> Principal:
    principal = await current_principal(request)
    if principal is None:
        raise AdminRequiredError
    if not principal.is_admin:
        raise AdminRequiredError
    return principal


async def authorize(request: Request) -> None:
    """The default-deny rule for state-changing routes (see the module docstring)."""
    endpoint = request.scope.get("endpoint")
    if getattr(endpoint, "__allow_any_role__", False):
        return
    if request.method in SAFE_METHODS:
        return
    await require_admin(request)


async def _admin_required(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"detail": "Administrator access required", "code": "admin_required"}, status_code=403
    )


def install(app: FastAPI) -> None:
    app.add_exception_handler(AdminRequiredError, _admin_required)
