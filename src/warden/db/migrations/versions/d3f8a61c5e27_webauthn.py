"""WebAuthn: credentials, user handles and ceremony challenges.

Revision ID: d3f8a61c5e27
Revises: 7b2e9d4c1f08
Create Date: 2026-11-06

Added by the WebAuthn core workstream (rulings P0 to P12 of 6 November
2026), with the whole feature's schema so later workstreams add none:

- ``webauthn_credentials``: a passkey or security key, its COSE public key,
  signature counter, AAGUID, transports and flags;
- ``webauthn_user_handles``: each user's 64 random bytes, the WebAuthn user
  handle, never derived from the user id;
- ``webauthn_challenges``: registration and sign-in challenges, held as
  SHA-256 hashes, each used up by one guarded write;
- ``passkey_only`` as a sign-in method, and ``passkey_registration`` as a
  single-use token purpose, for passkey-only sign-in.

The downgrade removes passkey registration links, which mean nothing below
this revision. It refuses while any user is ``passkey_only``: no other sign-in
method is theirs to take, so an operator changes them first.

The integration session re-chains ``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "d3f8a61c5e27"
down_revision: str | None = "7b2e9d4c1f08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    "ALTER TABLE warden.users DROP CONSTRAINT users_sign_in_method",
    """
    ALTER TABLE warden.users ADD CONSTRAINT users_sign_in_method
        CHECK (sign_in_method IN ('password_and_sso', 'sso_only', 'passkey_only'))
    """,
    "ALTER TABLE warden.single_use_tokens DROP CONSTRAINT single_use_token_purpose",
    """
    ALTER TABLE warden.single_use_tokens ADD CONSTRAINT single_use_token_purpose
        CHECK (purpose IN ('invitation', 'password_reset', 'passkey_registration'))
    """,
    """
    CREATE TABLE warden.webauthn_user_handles (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        handle bytea NOT NULL UNIQUE CONSTRAINT webauthn_user_handle_length
            CHECK (octet_length(handle) = 64),
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE warden.webauthn_credentials (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        credential_id bytea NOT NULL UNIQUE CONSTRAINT webauthn_credential_id_length
            CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
        public_key bytea NOT NULL CONSTRAINT webauthn_public_key_length
            CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
        algorithm integer NOT NULL,
        sign_count bigint NOT NULL DEFAULT 0 CONSTRAINT webauthn_sign_count_range
            CHECK (sign_count BETWEEN 0 AND 4294967295),
        aaguid uuid NOT NULL,
        transports text[] NOT NULL DEFAULT '{}',
        backup_eligible boolean NOT NULL,
        backup_state boolean NOT NULL,
        discoverable boolean NOT NULL,
        user_verified boolean NOT NULL,
        attestation_verified boolean NOT NULL,
        nickname text CONSTRAINT webauthn_nickname_length
            CHECK (nickname IS NULL OR char_length(nickname) BETWEEN 1 AND 64),
        created_at timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz,
        CONSTRAINT webauthn_backup_state_needs_eligibility
            CHECK (backup_eligible OR NOT backup_state)
    )
    """,
    "CREATE INDEX webauthn_credentials_user_idx ON warden.webauthn_credentials (user_id)",
    """
    CREATE TABLE warden.webauthn_challenges (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        challenge_hash bytea NOT NULL UNIQUE CONSTRAINT webauthn_challenge_hash_length
            CHECK (octet_length(challenge_hash) = 32),
        purpose text NOT NULL CONSTRAINT webauthn_challenge_purpose
            CHECK (purpose IN ('registration', 'authentication')),
        user_id uuid REFERENCES warden.users (id) ON DELETE CASCADE,
        user_verification_required boolean NOT NULL,
        resident_key_required boolean NOT NULL DEFAULT false,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        CONSTRAINT webauthn_challenge_registration_has_user
            CHECK (purpose = 'authentication' OR user_id IS NOT NULL),
        CONSTRAINT webauthn_challenge_expiry_after_creation CHECK (expires_at > created_at)
    )
    """,
    "CREATE INDEX webauthn_challenges_user_idx ON warden.webauthn_challenges (user_id)",
    "CREATE INDEX webauthn_challenges_expiry_idx ON warden.webauthn_challenges (expires_at)",
]

_DOWNGRADE = [
    """
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM warden.users WHERE sign_in_method = 'passkey_only') THEN
            RAISE EXCEPTION 'cannot downgrade: users with sign_in_method passkey_only exist';
        END IF;
    END
    $$
    """,
    "DROP TABLE warden.webauthn_challenges",
    "DROP TABLE warden.webauthn_credentials",
    "DROP TABLE warden.webauthn_user_handles",
    "DELETE FROM warden.single_use_tokens WHERE purpose = 'passkey_registration'",
    "ALTER TABLE warden.single_use_tokens DROP CONSTRAINT single_use_token_purpose",
    """
    ALTER TABLE warden.single_use_tokens ADD CONSTRAINT single_use_token_purpose
        CHECK (purpose IN ('invitation', 'password_reset'))
    """,
    "ALTER TABLE warden.users DROP CONSTRAINT users_sign_in_method",
    """
    ALTER TABLE warden.users ADD CONSTRAINT users_sign_in_method
        CHECK (sign_in_method IN ('password_and_sso', 'sso_only'))
    """,
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
