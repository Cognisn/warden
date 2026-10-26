"""Append-only database grants for warden's schema.

warden's migrations run as the schema's owner. The product's application,
the syslog forwarder and the retention purge should each connect as a
different, non-owning role, because a table's owner bypasses grants. This
module produces the SQL that gives each role exactly what it needs:

- **application:** read and write warden's tables, except that on
  ``audit_events`` it holds only ``INSERT`` and ``SELECT``, so it can append
  to the trail but never edit or delete it. It may read the migration
  version table but not write it.
- **forwarder:** ``SELECT`` on ``audit_events``, and ``SELECT``, ``INSERT``
  and ``UPDATE`` on ``settings``, where it keeps its cursor.
- **purger:** ``SELECT``, ``INSERT`` and ``DELETE`` on ``audit_events``, so the
  retention purge can append its checkpoint and delete the purged prefix,
  and ``SELECT`` on ``signing_keys`` to sign it. Only the purge deletes.

Each block first revokes everything the role holds on warden's tables, so
the SQL is safe to re-run, and should be re-run after every migration so
that new tables are covered. Run it as the schema owner or a superuser.
"""

from __future__ import annotations

from psycopg import sql

from warden.db import AUDIT_EVENTS, SCHEMA, SETTINGS, SIGNING_KEYS, VERSION_TABLE

__all__ = ["append_only_grants", "grants_sql"]


def _ident(*parts: str) -> sql.Identifier:
    return sql.Identifier(*parts)


def _reset(role: sql.Identifier) -> list[sql.Composable]:
    schema = _ident(SCHEMA)
    return [
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}").format(schema, role),
        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}").format(schema, role),
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(schema, role),
    ]


def _application(role: sql.Identifier) -> list[sql.Composable]:
    schema = _ident(SCHEMA)
    return [
        *_reset(role),
        sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}").format(
            schema, role
        ),
        sql.SQL("REVOKE UPDATE, DELETE ON {} FROM {}").format(_ident(SCHEMA, AUDIT_EVENTS), role),
        sql.SQL("REVOKE INSERT, UPDATE, DELETE ON {} FROM {}").format(
            _ident(SCHEMA, VERSION_TABLE), role
        ),
        # USAGE allows nextval but not setval.
        sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}").format(schema, role),
    ]


def _forwarder(role: sql.Identifier) -> list[sql.Composable]:
    return [
        *_reset(role),
        sql.SQL("GRANT SELECT ON {} TO {}").format(_ident(SCHEMA, AUDIT_EVENTS), role),
        sql.SQL("GRANT SELECT, INSERT, UPDATE ON {} TO {}").format(_ident(SCHEMA, SETTINGS), role),
    ]


def _purger(role: sql.Identifier) -> list[sql.Composable]:
    return [
        *_reset(role),
        sql.SQL("GRANT SELECT, INSERT, DELETE ON {} TO {}").format(
            _ident(SCHEMA, AUDIT_EVENTS), role
        ),
        sql.SQL("GRANT SELECT ON {} TO {}").format(_ident(SCHEMA, SIGNING_KEYS), role),
        sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}").format(_ident(SCHEMA), role),
    ]


def append_only_grants(
    *, app_role: str, forwarder_role: str | None = None, purger_role: str | None = None
) -> sql.Composed:
    """The grant statements for the given roles, ``;``-separated."""
    names = [r for r in (app_role, forwarder_role, purger_role) if r is not None]
    if len(set(names)) != len(names):
        raise ValueError("the application, forwarder and purger roles must be distinct")
    statements = _application(_ident(app_role))
    if forwarder_role is not None:
        statements += _forwarder(_ident(forwarder_role))
    if purger_role is not None:
        statements += _purger(_ident(purger_role))
    return sql.SQL(";\n").join(statements) + sql.SQL(";\n")


def grants_sql(
    *, app_role: str, forwarder_role: str | None = None, purger_role: str | None = None
) -> str:
    """``append_only_grants`` as text, for an operator or a migration step to run."""
    return append_only_grants(
        app_role=app_role, forwarder_role=forwarder_role, purger_role=purger_role
    ).as_string()
