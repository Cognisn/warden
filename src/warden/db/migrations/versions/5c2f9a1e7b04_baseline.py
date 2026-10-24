"""Baseline: audit events, signing keys and settings.

Revision ID: 5c2f9a1e7b04
Revises:
Create Date: 2026-10-25

The ``warden`` schema itself is created by the migration environment, because
the version table lives in it. Downgrading to base removes every table this
revision creates and leaves the (then empty) schema and its version table.

The audit chain columns (prev_hash, row_hash, key_id) are nullable until the
audit core arc fills them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "5c2f9a1e7b04"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "warden"


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger, sa.Identity(always=True), primary_key=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("actor", sa.Text, nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("resource_type", sa.Text, nullable=True),
        sa.Column("resource_id", sa.Text, nullable=True),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("source_ip", postgresql.INET, nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("prev_hash", postgresql.BYTEA, nullable=True),
        sa.Column("row_hash", postgresql.BYTEA, nullable=True),
        sa.Column("key_id", sa.Text, nullable=True),
        sa.CheckConstraint("jsonb_typeof(details) = 'object'", name="audit_events_details_object"),
        schema=SCHEMA,
    )
    op.create_index("audit_events_occurred_at", "audit_events", ["occurred_at"], schema=SCHEMA)
    op.create_index("audit_events_action", "audit_events", ["action"], schema=SCHEMA)
    op.create_index("audit_events_actor", "audit_events", ["actor"], schema=SCHEMA)

    op.create_table(
        "signing_keys",
        sa.Column("key_id", sa.Text, primary_key=True),
        sa.Column("algorithm", sa.Text, nullable=False, server_default=sa.text("'Ed25519'")),
        sa.Column("public_key", postgresql.BYTEA, nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("algorithm = 'Ed25519'", name="signing_keys_algorithm"),
        sa.CheckConstraint("octet_length(public_key) = 32", name="signing_keys_public_key_length"),
        sa.CheckConstraint(
            "retired_at IS NULL OR retired_at >= created_at", name="signing_keys_retired_after"
        ),
        schema=SCHEMA,
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("value", postgresql.JSONB, nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("settings", schema=SCHEMA)
    op.drop_table("signing_keys", schema=SCHEMA)
    op.drop_index("audit_events_actor", table_name="audit_events", schema=SCHEMA)
    op.drop_index("audit_events_action", table_name="audit_events", schema=SCHEMA)
    op.drop_index("audit_events_occurred_at", table_name="audit_events", schema=SCHEMA)
    op.drop_table("audit_events", schema=SCHEMA)
