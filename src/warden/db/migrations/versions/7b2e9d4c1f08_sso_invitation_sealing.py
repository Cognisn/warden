"""SSO invitation sealing: a login transaction carries its invitation sealed, not hashed.

Revision ID: 7b2e9d4c1f08
Revises: a6d3f0b8e21c
Create Date: 2026-10-28

Added by the SSO invitation sealing workstream. The invitation token waits
in the login transaction sealed (AES-256-GCM under a key derived from the
browser's login binding, which the database holds only as a hash), so the
second cookie that held it is gone, and with it the token's hash.

Neither form can be turned into the other inside the database: a hash
cannot be opened, and a sealed token cannot be opened without the
browser's binding. So each direction removes the in-flight acceptances of
the other form (a plain sign-in's transaction is kept); their browsers land
on the fixed failure and start again. Transactions live for minutes.

The integration session re-chains ``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "7b2e9d4c1f08"
down_revision: str | None = "a6d3f0b8e21c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    "DELETE FROM warden.sso_login_transactions WHERE invitation_hash IS NOT NULL",
    "ALTER TABLE warden.sso_login_transactions DROP COLUMN invitation_hash",
    """
    ALTER TABLE warden.sso_login_transactions
        ADD COLUMN invitation_sealed bytea
        CONSTRAINT sso_login_invitation_sealed_length
            CHECK (invitation_sealed IS NULL OR octet_length(invitation_sealed) = 71)
    """,
]

_DOWNGRADE = [
    "DELETE FROM warden.sso_login_transactions WHERE invitation_sealed IS NOT NULL",
    "ALTER TABLE warden.sso_login_transactions DROP COLUMN invitation_sealed",
    """
    ALTER TABLE warden.sso_login_transactions
        ADD COLUMN invitation_hash bytea
        CONSTRAINT sso_login_invitation_hash_length
            CHECK (invitation_hash IS NULL OR octet_length(invitation_hash) = 32)
    """,
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
