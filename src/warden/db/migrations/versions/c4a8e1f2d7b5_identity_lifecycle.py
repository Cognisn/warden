"""Identity lifecycle: single-use tokens, staged invitation grants, API keys.

Revision ID: c4a8e1f2d7b5
Revises: b7e14a2c9d30
Create Date: 2026-10-28

Added by the identity lifecycle workstream. The integration session re-chains
``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "c4a8e1f2d7b5"
down_revision: str | None = "b7e14a2c9d30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    """
    CREATE TABLE warden.single_use_tokens (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        token_hash bytea NOT NULL UNIQUE CONSTRAINT single_use_token_hash_length
            CHECK (octet_length(token_hash) = 32),
        purpose text NOT NULL CONSTRAINT single_use_token_purpose
            CHECK (purpose IN ('invitation', 'password_reset')),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL DEFAULT now(),
        created_by text,
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        revoked_at timestamptz,
        CONSTRAINT single_use_token_expiry_after_creation CHECK (expires_at > created_at),
        CONSTRAINT single_use_token_consumed_or_revoked
            CHECK (consumed_at IS NULL OR revoked_at IS NULL)
    )
    """,
    "CREATE INDEX single_use_tokens_user_idx ON warden.single_use_tokens (user_id, purpose)",
    "CREATE INDEX single_use_tokens_expiry_idx ON warden.single_use_tokens (expires_at)",
    """
    CREATE TABLE warden.invitation_grants (
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        role text NOT NULL CONSTRAINT invitation_grant_role_length
            CHECK (char_length(role) BETWEEN 1 AND 64),
        expires_at timestamptz,
        staged_at timestamptz NOT NULL DEFAULT now(),
        staged_by text,
        PRIMARY KEY (user_id, role)
    )
    """,
    """
    CREATE TABLE warden.api_keys (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        name text NOT NULL CONSTRAINT api_key_name_length
            CHECK (char_length(name) BETWEEN 1 AND 100),
        key_hash bytea NOT NULL UNIQUE CONSTRAINT api_key_hash_length
            CHECK (octet_length(key_hash) = 32),
        hint text NOT NULL CONSTRAINT api_key_hint_length
            CHECK (char_length(hint) BETWEEN 1 AND 32),
        scopes text[] NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        created_by text,
        expires_at timestamptz,
        revoked_at timestamptz,
        revoked_by text,
        last_used_at timestamptz,
        CONSTRAINT api_key_expiry_after_creation
            CHECK (expires_at IS NULL OR expires_at > created_at),
        CONSTRAINT api_key_revoker_needs_revocation
            CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
    )
    """,
    "CREATE INDEX api_keys_user_idx ON warden.api_keys (user_id)",
]

_DOWNGRADE = [
    "DROP TABLE warden.api_keys",
    "DROP TABLE warden.invitation_grants",
    "DROP TABLE warden.single_use_tokens",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
