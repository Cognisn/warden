"""Single sign-on: pinned subjects, login transactions and handoff codes.

Revision ID: e3a9c5d17f42
Revises: b7e14a2c9d30
Create Date: 2026-10-28

Added by the single sign-on workstream. The integration session re-chains
``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e3a9c5d17f42"
down_revision: str | None = "b7e14a2c9d30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    """
    CREATE TABLE warden.sso_identities (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        issuer text NOT NULL CONSTRAINT sso_identities_issuer_length
            CHECK (char_length(issuer) BETWEEN 1 AND 2048),
        subject text NOT NULL CONSTRAINT sso_identities_subject_length
            CHECK (char_length(subject) BETWEEN 1 AND 255),
        pinned_at timestamptz NOT NULL DEFAULT now(),
        last_sign_in_at timestamptz,
        CONSTRAINT sso_identities_subject_unique UNIQUE (issuer, subject)
    )
    """,
    """
    CREATE TABLE warden.sso_login_transactions (
        state_hash bytea PRIMARY KEY CONSTRAINT sso_login_state_hash_length
            CHECK (octet_length(state_hash) = 32),
        binding_hash bytea NOT NULL CONSTRAINT sso_login_binding_hash_length
            CHECK (octet_length(binding_hash) = 32),
        nonce text NOT NULL CONSTRAINT sso_login_nonce_length
            CHECK (char_length(nonce) BETWEEN 1 AND 128),
        code_verifier text NOT NULL CONSTRAINT sso_login_verifier_length
            CHECK (char_length(code_verifier) BETWEEN 43 AND 128),
        issuer text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz
    )
    """,
    "CREATE INDEX sso_login_transactions_expiry_idx ON warden.sso_login_transactions (expires_at)",
    """
    CREATE TABLE warden.sso_handoff_codes (
        code_hash bytea PRIMARY KEY CONSTRAINT sso_handoff_code_hash_length
            CHECK (octet_length(code_hash) = 32),
        binding_hash bytea NOT NULL CONSTRAINT sso_handoff_binding_hash_length
            CHECK (octet_length(binding_hash) = 32),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz
    )
    """,
    "CREATE INDEX sso_handoff_codes_expiry_idx ON warden.sso_handoff_codes (expires_at)",
]

_DOWNGRADE = [
    "DROP TABLE warden.sso_handoff_codes",
    "DROP TABLE warden.sso_login_transactions",
    "DROP TABLE warden.sso_identities",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
