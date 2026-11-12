"""Creating the first administrator.

warden's own CLI cannot do this, because the roles are the product's: a
product creates its first administrator with its own command, through
``Identity.users`` and ``Identity.roles``. Everyone after that is invited
through the administration routes.
"""

from __future__ import annotations

from examples.console.product import ADMINISTRATOR
from warden.identity import Identity, User

__all__ = ["create_administrator"]

ACTOR = "console-bootstrap"


async def create_administrator(identity: Identity, email: str, password: str) -> User:
    """Create an active user with ``password`` holding the administrator role.

    Running it again for the same address changes nothing but makes sure the
    role is held, so a bootstrap step can be repeated safely.
    """
    user = await identity.users.get_by_email(email)
    if user is None:
        user = await identity.users.create(email, actor=ACTOR, password=password)
    if ADMINISTRATOR not in await identity.roles.roles_of(user.id):
        await identity.roles.assign(user.id, ADMINISTRATOR, actor=ACTOR)
    return user
