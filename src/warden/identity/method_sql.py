"""The one resolution of a user's sign-in method in force, as SQL (ruling CS13 and CS18).

Every query that decides how a user may sign in reads the method through
``effective_method_sql``: while a change is pending the method it moves
from stays in force; otherwise the user's own setting, or, when that is
null, the instance default. It depends on nothing but warden's schema
names, so any identity module can use it without an import cycle;
``warden.identity.users`` re-exports it.
"""

from __future__ import annotations

from psycopg import sql

from warden.db import schema, table

__all__ = ["INITIAL_DEFAULT", "effective_method_sql", "pending_method_sql"]

# The method every user followed before 0.2.0, and the default's initial
# value (ruling CS16). Only a missing settings row (never written by warden)
# falls back to it.
INITIAL_DEFAULT = "password_and_sso"

_SETTINGS = table(schema.SIGN_IN_SETTINGS)
_CHANGES = table(schema.SIGN_IN_METHOD_CHANGES)


def effective_method_sql(users: str = "users") -> sql.Composable:
    """The method in force for the users row named ``users`` in a query, as SQL.

    ``users`` is the row's alias, or ``users`` for an unaliased ``warden.users``.
    """
    row = sql.Identifier(users)
    return sql.SQL(
        "COALESCE((SELECT c.from_method FROM {changes} c WHERE c.user_id = {row}.id),"
        " {row}.sign_in_method,"
        " (SELECT s.default_sign_in_method FROM {settings} s), {initial})"
    ).format(changes=_CHANGES, settings=_SETTINGS, row=row, initial=sql.Literal(INITIAL_DEFAULT))


def pending_method_sql(users: str = "users") -> sql.Composable:
    """The method a pending change moves the ``users`` row to, or NULL, as SQL."""
    return sql.SQL("(SELECT c.to_method FROM {changes} c WHERE c.user_id = {row}.id)").format(
        changes=_CHANGES, row=sql.Identifier(users)
    )
