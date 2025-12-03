from typing import Callable

from starlette.types import ASGIApp, Receive, Scope, Send


class JwtGuardMiddleware:
    """
    P3 JWT Guard middleware.

    For now this is just a pass-through so we can boot the service.
    Later we will add:
      - alg:none blocking
      - PQC / alg allow-list
      - structural validation
      - calls to P1/P2/P4
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # we only want to guard HTTP requests; let other protocols pass untouched
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # TODO: here we will implement all JWT guard logic
        # For now: just forward the request to the next app
        await self.app(scope, receive, send)
