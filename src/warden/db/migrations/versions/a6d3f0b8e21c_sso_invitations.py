"""SSO invitations: a login transaction may carry an invitation.

Revision ID: a6d3f0b8e21c
Revises: e3a9c5d17f42
Create Date: 2026-10-28

Added by the SSO invitations workstream. A sign-in started from an
invitation link records the invitation token's SHA-256 hash, never the
token. The integration session re-chains ``down_revision`` when workstreams
merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "a6d3f0b8e21c"
down_revision: str | None = "e3a9c5d17f42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    """
    ALTER TABLE warden.sso_login_transactions
        ADD COLUMN invitation_hash bytea
        CONSTRAINT sso_login_invitation_hash_length
            CHECK (invitation_hash IS NULL OR octet_length(invitation_hash) = 32)
    """,
]

_DOWNGRADE = [
    "ALTER TABLE warden.sso_login_transactions DROP COLUMN invitation_hash",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
