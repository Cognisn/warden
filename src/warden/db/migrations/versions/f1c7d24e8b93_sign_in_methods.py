"""Sign-in methods: the instance default, ``password``, and pending method changes.

Revision ID: f1c7d24e8b93
Revises: a9e4c27f13d8
Create Date: 2026-11-23

Added by the sign-in methods workstream of warden 0.2.0 (rulings CS13 to
CS18 of 23 November 2026):

- ``sign_in_settings``: one row, the instance's default sign-in method
  (initially ``password_and_sso``) and the second factors an administrator
  allows (initially both ``totp`` and ``passkey``);
- ``sign_in_method_changes``: a user's pending change, from the method still
  in force to the one waiting for its credential, at most one per user;
- ``password`` as a sign-in method (Password + MFA, never single sign-on),
  and a user's own method nullable, null meaning the user follows the
  default.

Nothing about how anyone signs in changes on upgrade (ruling CS16): every
``password_and_sso`` user follows the default, which starts as
``password_and_sso``, and ``sso_only`` and ``passkey_only`` users keep their
method as their own setting.

The downgrade restores the 0.1.x shape: a pending change gives way to the
method in force, and a user following the default, or on ``password``,
becomes ``password_and_sso``.

The integration session re-chains ``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "f1c7d24e8b93"
down_revision: str | None = "a9e4c27f13d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_METHODS = "('password', 'password_and_sso', 'sso_only', 'passkey_only')"

_UPGRADE = [
    f"""
    CREATE TABLE warden.sign_in_settings (
        singleton boolean PRIMARY KEY DEFAULT true CONSTRAINT sign_in_settings_singleton
            CHECK (singleton),
        default_sign_in_method text NOT NULL DEFAULT 'password_and_sso'
            CONSTRAINT sign_in_settings_default_method CHECK (default_sign_in_method IN {_METHODS}),
        allowed_second_factors text[] NOT NULL DEFAULT ARRAY['totp', 'passkey']
            CONSTRAINT sign_in_settings_second_factors CHECK (
                cardinality(allowed_second_factors) BETWEEN 1 AND 2
                AND allowed_second_factors <@ ARRAY['totp', 'passkey']
            ),
        updated_at timestamptz NOT NULL DEFAULT now(),
        updated_by text CONSTRAINT sign_in_settings_updated_by_length
            CHECK (updated_by IS NULL OR char_length(updated_by) BETWEEN 1 AND 320)
    )
    """,
    "INSERT INTO warden.sign_in_settings DEFAULT VALUES",
    f"""
    CREATE TABLE warden.sign_in_method_changes (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        from_method text NOT NULL CONSTRAINT sign_in_method_changes_from
            CHECK (from_method IN {_METHODS}),
        to_method text NOT NULL CONSTRAINT sign_in_method_changes_to
            CHECK (to_method IN {_METHODS}),
        previous_setting text CONSTRAINT sign_in_method_changes_previous
            CHECK (previous_setting IS NULL OR previous_setting IN {_METHODS}),
        requested_by text CONSTRAINT sign_in_method_changes_requested_by_length
            CHECK (requested_by IS NULL OR char_length(requested_by) BETWEEN 1 AND 320),
        requested_at timestamptz NOT NULL DEFAULT now(),
        link_sent_at timestamptz,
        CONSTRAINT sign_in_method_changes_moves CHECK (from_method <> to_method)
    )
    """,
    "ALTER TABLE warden.users DROP CONSTRAINT users_sign_in_method",
    """
    ALTER TABLE warden.users
        ALTER COLUMN sign_in_method DROP NOT NULL,
        ALTER COLUMN sign_in_method DROP DEFAULT
    """,
    f"""
    ALTER TABLE warden.users ADD CONSTRAINT users_sign_in_method
        CHECK (sign_in_method IS NULL OR sign_in_method IN {_METHODS})
    """,
    # Ruling CS16: password_and_sso users follow the default, which starts as
    # password_and_sso; updated_at stays, since nothing about them changed.
    "UPDATE warden.users SET sign_in_method = NULL WHERE sign_in_method = 'password_and_sso'",
]

_DOWNGRADE = [
    # A pending change gives way to the method in force.
    """
    UPDATE warden.users u SET sign_in_method = c.from_method
        FROM warden.sign_in_method_changes c WHERE c.user_id = u.id
    """,
    """
    UPDATE warden.users SET sign_in_method = 'password_and_sso'
        WHERE sign_in_method IS NULL OR sign_in_method = 'password'
    """,
    "DROP TABLE warden.sign_in_method_changes",
    "DROP TABLE warden.sign_in_settings",
    "ALTER TABLE warden.users DROP CONSTRAINT users_sign_in_method",
    """
    ALTER TABLE warden.users
        ALTER COLUMN sign_in_method SET DEFAULT 'password_and_sso',
        ALTER COLUMN sign_in_method SET NOT NULL
    """,
    """
    ALTER TABLE warden.users ADD CONSTRAINT users_sign_in_method
        CHECK (sign_in_method IN ('password_and_sso', 'sso_only', 'passkey_only'))
    """,
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
