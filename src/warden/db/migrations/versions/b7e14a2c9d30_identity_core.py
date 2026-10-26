"""Identity core: users, TOTP, recovery codes, MFA challenges, sessions, roles, throttling.

Revision ID: b7e14a2c9d30
Revises: 8d41b7c3a9f2
Create Date: 2026-10-25

Added by the identity core arc. The integration session re-chains
``down_revision`` when arcs merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b7e14a2c9d30"
down_revision: str | None = "8d41b7c3a9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    """
    CREATE TABLE warden.users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email text NOT NULL CONSTRAINT users_email_length
            CHECK (char_length(email) BETWEEN 1 AND 320),
        display_name text,
        status text NOT NULL CONSTRAINT users_status
            CHECK (status IN ('invited', 'active', 'suspended', 'deactivated')),
        sign_in_method text NOT NULL DEFAULT 'password_and_sso' CONSTRAINT users_sign_in_method
            CHECK (sign_in_method IN ('password_and_sso', 'sso_only')),
        password_hash text,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE UNIQUE INDEX users_email_key ON warden.users (lower(email))",
    """
    CREATE TABLE warden.totp_credentials (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        secret_sealed bytea NOT NULL CONSTRAINT totp_secret_sealed_length
            CHECK (octet_length(secret_sealed) BETWEEN 44 AND 92),
        key_id text NOT NULL CONSTRAINT totp_key_id_length
            CHECK (char_length(key_id) BETWEEN 1 AND 64),
        created_at timestamptz NOT NULL DEFAULT now(),
        confirmed_at timestamptz,
        last_used_step bigint,
        CONSTRAINT totp_step_needs_confirmation
            CHECK (last_used_step IS NULL OR confirmed_at IS NOT NULL)
    )
    """,
    """
    CREATE TABLE warden.recovery_codes (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        code_hash bytea NOT NULL CONSTRAINT recovery_code_hash_length
            CHECK (octet_length(code_hash) = 32),
        created_at timestamptz NOT NULL DEFAULT now(),
        used_at timestamptz,
        CONSTRAINT recovery_codes_unique UNIQUE (user_id, code_hash)
    )
    """,
    """
    CREATE TABLE warden.mfa_challenges (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        token_hash bytea NOT NULL UNIQUE CONSTRAINT mfa_challenge_hash_length
            CHECK (octet_length(token_hash) = 32),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        purpose text NOT NULL CONSTRAINT mfa_challenge_purpose
            CHECK (purpose IN ('verify', 'enrol')),
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        failed_attempts integer NOT NULL DEFAULT 0 CONSTRAINT mfa_challenge_attempts
            CHECK (failed_attempts >= 0)
    )
    """,
    "CREATE INDEX mfa_challenges_user_idx ON warden.mfa_challenges (user_id)",
    """
    CREATE TABLE warden.sessions (
        id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        last_refreshed_at timestamptz,
        revoked_at timestamptz,
        revoked_reason text,
        amr text[] NOT NULL DEFAULT '{}',
        CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at),
        CONSTRAINT sessions_reason_needs_revocation
            CHECK (revoked_reason IS NULL OR revoked_at IS NOT NULL)
    )
    """,
    "CREATE INDEX sessions_user_idx ON warden.sessions (user_id)",
    """
    CREATE TABLE warden.refresh_tokens (
        token_hash bytea PRIMARY KEY CONSTRAINT refresh_token_hash_length
            CHECK (octet_length(token_hash) = 32),
        session_id uuid NOT NULL REFERENCES warden.sessions (id) ON DELETE CASCADE,
        generation integer NOT NULL CONSTRAINT refresh_token_generation
            CHECK (generation >= 0),
        issued_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        used_at timestamptz,
        CONSTRAINT refresh_tokens_generation_unique UNIQUE (session_id, generation)
    )
    """,
    """
    CREATE TABLE warden.role_assignments (
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        role text NOT NULL CONSTRAINT role_assignment_role_length
            CHECK (char_length(role) BETWEEN 1 AND 64),
        granted_at timestamptz NOT NULL DEFAULT now(),
        granted_by text,
        expires_at timestamptz,
        PRIMARY KEY (user_id, role)
    )
    """,
    "CREATE INDEX role_assignments_role_idx ON warden.role_assignments (role)",
    """
    CREATE TABLE warden.sign_in_attempts (
        key_hash bytea PRIMARY KEY CONSTRAINT sign_in_attempts_key_length
            CHECK (octet_length(key_hash) = 32),
        window_started_at timestamptz NOT NULL DEFAULT now(),
        attempts integer NOT NULL CONSTRAINT sign_in_attempts_positive CHECK (attempts > 0)
    )
    """,
]

_DOWNGRADE = [
    "DROP TABLE warden.sign_in_attempts",
    "DROP TABLE warden.role_assignments",
    "DROP TABLE warden.refresh_tokens",
    "DROP TABLE warden.sessions",
    "DROP TABLE warden.mfa_challenges",
    "DROP TABLE warden.recovery_codes",
    "DROP TABLE warden.totp_credentials",
    "DROP TABLE warden.users",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
