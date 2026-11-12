"""identity's FastAPI routers. ``Identity.auth_router()`` builds the public sign-in routes."""

from warden.identity.routers.auth import build_auth_router

__all__ = ["build_auth_router"]
