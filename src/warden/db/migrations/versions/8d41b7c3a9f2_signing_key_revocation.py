"""Signing key revocation.

Revision ID: 8d41b7c3a9f2
Revises: 5c2f9a1e7b04
Create Date: 2026-10-25

A retired key no longer signs or verifies live credentials but still verifies
historical artefacts such as audit checkpoints. A revoked key (compromised)
is trusted for nothing, so it needs its own timestamp. A revoked key is
always retired too, so a check that refuses retired keys also refuses it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8d41b7c3a9f2"
down_revision: str | None = "5c2f9a1e7b04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "warden"


def upgrade() -> None:
    op.add_column(
        "signing_keys",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "signing_keys_revoked_after",
        "signing_keys",
        "revoked_at IS NULL OR revoked_at >= created_at",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "signing_keys_revoked_is_retired",
        "signing_keys",
        "revoked_at IS NULL OR retired_at IS NOT NULL",
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_constraint(
        "signing_keys_revoked_is_retired", "signing_keys", schema=SCHEMA, type_="check"
    )
    op.drop_constraint("signing_keys_revoked_after", "signing_keys", schema=SCHEMA, type_="check")
    op.drop_column("signing_keys", "revoked_at", schema=SCHEMA)
