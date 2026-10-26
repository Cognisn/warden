"""Audit hash chain: server-side recorded_at, required chain hashes, outcome check.

Revision ID: 3f7a2c9d1b6e
Revises: 8d41b7c3a9f2
Create Date: 2026-10-25

``recorded_at`` is the server's time when the row was appended; unlike the
caller-supplied ``occurred_at`` it cannot be backdated, and it is what the
retention purge measures age by. Chain order follows ``id``.

The unique index on ``prev_hash`` means two rows can never claim the same
predecessor, so the chain cannot fork even if a writer reads a stale head.

Rows written before this revision carry no hashes and cannot be chained
after the fact, so the upgrade refuses to run while any exist.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3f7a2c9d1b6e"
down_revision: str | None = "8d41b7c3a9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "warden"


def upgrade() -> None:
    unchained = op.get_bind().execute(
        sa.text("SELECT count(*) FROM warden.audit_events WHERE row_hash IS NULL")
    )
    if unchained.scalar_one():
        raise RuntimeError(
            "warden.audit_events holds rows written before the hash chain;"
            " they cannot be chained, so this revision refuses to upgrade"
        )
    op.add_column(
        "audit_events",
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        schema=SCHEMA,
    )
    op.alter_column("audit_events", "prev_hash", nullable=False, schema=SCHEMA)
    op.alter_column("audit_events", "row_hash", nullable=False, schema=SCHEMA)
    op.create_check_constraint(
        "audit_events_outcome", "audit_events", "outcome IN ('success', 'failure')", schema=SCHEMA
    )
    op.create_check_constraint(
        "audit_events_hash_lengths",
        "audit_events",
        "octet_length(prev_hash) = 32 AND octet_length(row_hash) = 32",
        schema=SCHEMA,
    )
    op.create_index(
        "audit_events_prev_hash_unique", "audit_events", ["prev_hash"], unique=True, schema=SCHEMA
    )
    op.create_index("audit_events_recorded_at", "audit_events", ["recorded_at"], schema=SCHEMA)


def downgrade() -> None:
    op.drop_index("audit_events_recorded_at", table_name="audit_events", schema=SCHEMA)
    op.drop_index("audit_events_prev_hash_unique", table_name="audit_events", schema=SCHEMA)
    op.drop_constraint("audit_events_hash_lengths", "audit_events", schema=SCHEMA, type_="check")
    op.drop_constraint("audit_events_outcome", "audit_events", schema=SCHEMA, type_="check")
    op.alter_column("audit_events", "row_hash", nullable=True, schema=SCHEMA)
    op.alter_column("audit_events", "prev_hash", nullable=True, schema=SCHEMA)
    op.drop_column("audit_events", "recorded_at", schema=SCHEMA)
