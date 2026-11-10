"""Password policies and watch lists: the whole feature's schema.

Revision ID: a9e4c27f13d8
Revises: d3f8a61c5e27
Create Date: 2026-11-10

Added by the password policy core workstream (rulings PW0 to PW14 of 10
November 2026), with the whole feature's schema so later workstreams add
none:

- ``password_policies``: rules, passphrase settings, ordered tiers, history,
  watch-list and fingerprint settings; exactly one default, which has no
  priority, and a unique priority on every other policy;
- ``password_policy_roles``, ``password_policy_pins`` and
  ``password_policy_watch_lists``: role mappings, per-user pins and attached
  watch lists;
- ``password_states``: each user's tier name, set and expiry times, the
  reason a change is required, the watch list that matched (its id only) and
  the sealed fingerprint. Never a password's length or makeup;
- ``password_history``: previous Argon2id hashes;
- ``watch_lists``, ``watch_list_entries`` (SHA-1 digests and nothing else),
  ``watch_list_terms`` and ``watch_list_staging`` (an import's digests before
  they are swapped in);
- ``password_change_challenges``: forced-change challenges, held as SHA-256
  hashes, each used up by one guarded write.

The downgrade drops every table: policies, history and watch lists mean
nothing below this revision.

The integration session re-chains ``down_revision`` when workstreams merge.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "a9e4c27f13d8"
down_revision: str | None = "d3f8a61c5e27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UPGRADE = [
    """
    CREATE TABLE warden.password_policies (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name text NOT NULL CONSTRAINT password_policy_name_length
            CHECK (char_length(name) BETWEEN 1 AND 64),
        description text NOT NULL DEFAULT '' CONSTRAINT password_policy_description_length
            CHECK (char_length(description) <= 500),
        priority integer CONSTRAINT password_policy_priority_range
            CHECK (priority IS NULL OR priority BETWEEN 1 AND 10000),
        is_default boolean NOT NULL DEFAULT false,
        min_length integer NOT NULL CONSTRAINT password_policy_min_length
            CHECK (min_length BETWEEN 1 AND 1024),
        max_length integer NOT NULL DEFAULT 1024,
        min_classes integer NOT NULL DEFAULT 0 CONSTRAINT password_policy_min_classes
            CHECK (min_classes BETWEEN 0 AND 5),
        max_repeat integer CONSTRAINT password_policy_max_repeat
            CHECK (max_repeat IS NULL OR max_repeat BETWEEN 1 AND 1024),
        forbid_user_details boolean NOT NULL DEFAULT false,
        passphrase_min_length integer CONSTRAINT password_policy_passphrase_length
            CHECK (passphrase_min_length IS NULL OR passphrase_min_length BETWEEN 1 AND 1024),
        passphrase_min_words integer CONSTRAINT password_policy_passphrase_words
            CHECK (passphrase_min_words IS NULL OR passphrase_min_words BETWEEN 2 AND 64),
        passphrase_relaxes_classes boolean NOT NULL DEFAULT false,
        tiers jsonb NOT NULL DEFAULT '[]' CONSTRAINT password_policy_tiers_array
            CHECK (jsonb_typeof(tiers) = 'array'),
        warning_days integer NOT NULL DEFAULT 14 CONSTRAINT password_policy_warning_days
            CHECK (warning_days BETWEEN 0 AND 365),
        history_count integer NOT NULL DEFAULT 0 CONSTRAINT password_policy_history_count
            CHECK (history_count BETWEEN 0 AND 24),
        min_age_hours integer NOT NULL DEFAULT 0 CONSTRAINT password_policy_min_age
            CHECK (min_age_hours BETWEEN 0 AND 8760),
        include_builtin boolean NOT NULL DEFAULT true,
        hibp_enabled boolean NOT NULL DEFAULT false,
        hibp_on_unavailable text NOT NULL DEFAULT 'allow'
            CONSTRAINT password_policy_hibp_on_unavailable
            CHECK (hibp_on_unavailable IN ('allow', 'refuse')),
        fingerprint_enabled boolean NOT NULL DEFAULT false,
        end_sessions_on_match boolean NOT NULL DEFAULT false,
        enforce_on_sign_in boolean NOT NULL DEFAULT false,
        version integer NOT NULL DEFAULT 1 CONSTRAINT password_policy_version
            CHECK (version >= 1),
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT password_policy_max_length
            CHECK (max_length BETWEEN min_length AND 1024),
        CONSTRAINT password_policy_passphrase_complete
            CHECK ((passphrase_min_length IS NULL) = (passphrase_min_words IS NULL)),
        CONSTRAINT password_policy_default_has_no_priority
            CHECK (is_default = (priority IS NULL)),
        CONSTRAINT password_policies_priority_key UNIQUE (priority)
            DEFERRABLE INITIALLY IMMEDIATE
    )
    """,
    "CREATE UNIQUE INDEX password_policies_name_key ON warden.password_policies (lower(name))",
    """
    CREATE UNIQUE INDEX password_policies_one_default
        ON warden.password_policies (is_default) WHERE is_default
    """,
    """
    CREATE TABLE warden.password_policy_roles (
        role text PRIMARY KEY CONSTRAINT password_policy_role_length
            CHECK (char_length(role) BETWEEN 1 AND 64),
        policy_id uuid NOT NULL REFERENCES warden.password_policies (id) ON DELETE CASCADE,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX password_policy_roles_policy_idx ON warden.password_policy_roles (policy_id)",
    """
    CREATE TABLE warden.password_policy_pins (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        policy_id uuid NOT NULL REFERENCES warden.password_policies (id) ON DELETE CASCADE,
        pinned_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX password_policy_pins_policy_idx ON warden.password_policy_pins (policy_id)",
    """
    CREATE TABLE warden.watch_lists (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        name text NOT NULL CONSTRAINT watch_list_name_length
            CHECK (char_length(name) BETWEEN 1 AND 64),
        reason text NOT NULL CONSTRAINT watch_list_reason_length
            CHECK (char_length(reason) BETWEEN 1 AND 200),
        kind text NOT NULL CONSTRAINT watch_list_kind CHECK (kind IN ('manual', 'imported')),
        entry_count bigint NOT NULL DEFAULT 0 CONSTRAINT watch_list_entry_count
            CHECK (entry_count >= 0),
        import_threshold integer CONSTRAINT watch_list_import_threshold
            CHECK (import_threshold IS NULL OR import_threshold >= 1),
        last_imported_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE UNIQUE INDEX watch_lists_name_key ON warden.watch_lists (lower(name))",
    """
    CREATE TABLE warden.watch_list_entries (
        list_id uuid NOT NULL REFERENCES warden.watch_lists (id) ON DELETE CASCADE,
        hash bytea NOT NULL CONSTRAINT watch_list_entry_length CHECK (octet_length(hash) = 20),
        PRIMARY KEY (list_id, hash)
    )
    """,
    """
    CREATE TABLE warden.watch_list_terms (
        list_id uuid NOT NULL REFERENCES warden.watch_lists (id) ON DELETE CASCADE,
        term text NOT NULL CONSTRAINT watch_list_term_length
            CHECK (char_length(term) BETWEEN 3 AND 64),
        PRIMARY KEY (list_id, term)
    )
    """,
    """
    CREATE TABLE warden.watch_list_staging (
        import_id uuid NOT NULL,
        hash bytea NOT NULL CONSTRAINT watch_list_staging_length CHECK (octet_length(hash) = 20)
    )
    """,
    "CREATE INDEX watch_list_staging_import_idx ON warden.watch_list_staging (import_id)",
    """
    CREATE TABLE warden.password_policy_watch_lists (
        policy_id uuid NOT NULL REFERENCES warden.password_policies (id) ON DELETE CASCADE,
        list_id uuid NOT NULL REFERENCES warden.watch_lists (id) ON DELETE CASCADE,
        PRIMARY KEY (policy_id, list_id)
    )
    """,
    """
    CREATE INDEX password_policy_watch_lists_list_idx
        ON warden.password_policy_watch_lists (list_id)
    """,
    """
    CREATE TABLE warden.password_states (
        user_id uuid PRIMARY KEY REFERENCES warden.users (id) ON DELETE CASCADE,
        tier text CONSTRAINT password_state_tier_length
            CHECK (tier IS NULL OR char_length(tier) BETWEEN 1 AND 64),
        password_set_at timestamptz,
        expires_at timestamptz,
        change_reason text CONSTRAINT password_state_change_reason
            CHECK (change_reason IN ('expired', 'watch_list', 'administrator', 'policy')),
        watch_list_source text CONSTRAINT password_state_watch_list_source
            CHECK (watch_list_source IN ('builtin', 'list', 'term', 'hibp')),
        watch_list_id uuid REFERENCES warden.watch_lists (id) ON DELETE SET NULL,
        fingerprint_sealed bytea CONSTRAINT password_state_fingerprint_length
            CHECK (fingerprint_sealed IS NULL OR octet_length(fingerprint_sealed) = 48),
        fingerprint_key_id text CONSTRAINT password_state_fingerprint_key_length
            CHECK (fingerprint_key_id IS NULL OR char_length(fingerprint_key_id) BETWEEN 1 AND 64),
        updated_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT password_state_source_needs_watch_list
            CHECK (watch_list_source IS NULL OR change_reason IS NOT DISTINCT FROM 'watch_list'),
        CONSTRAINT password_state_list_needs_local_source
            CHECK (watch_list_id IS NULL OR coalesce(watch_list_source IN ('list', 'term'), false)),
        CONSTRAINT password_state_fingerprint_has_key
            CHECK ((fingerprint_sealed IS NULL) = (fingerprint_key_id IS NULL))
    )
    """,
    """
    CREATE TABLE warden.password_history (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        password_hash text NOT NULL CONSTRAINT password_history_argon2id
            CHECK (left(password_hash, 10) = '$argon2id$' AND char_length(password_hash) <= 512),
        set_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE INDEX password_history_user_idx
        ON warden.password_history (user_id, set_at DESC, id DESC)
    """,
    """
    CREATE TABLE warden.password_change_challenges (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        token_hash bytea NOT NULL UNIQUE CONSTRAINT password_change_challenge_hash_length
            CHECK (octet_length(token_hash) = 32),
        user_id uuid NOT NULL REFERENCES warden.users (id) ON DELETE CASCADE,
        reason text NOT NULL CONSTRAINT password_change_challenge_reason
            CHECK (reason IN ('expired', 'watch_list', 'administrator', 'policy')),
        watch_list_source text CONSTRAINT password_change_challenge_source
            CHECK (watch_list_source IN ('builtin', 'list', 'term', 'hibp')),
        watch_list_id uuid REFERENCES warden.watch_lists (id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        consumed_at timestamptz,
        failed_attempts integer NOT NULL DEFAULT 0 CONSTRAINT password_change_challenge_attempts
            CHECK (failed_attempts >= 0),
        CONSTRAINT password_change_challenge_source_needs_watch_list
            CHECK (watch_list_source IS NULL OR reason = 'watch_list'),
        CONSTRAINT password_change_challenge_list_needs_local_source
            CHECK (watch_list_id IS NULL OR coalesce(watch_list_source IN ('list', 'term'), false)),
        CONSTRAINT password_change_challenge_expiry_after_creation
            CHECK (expires_at > created_at)
    )
    """,
    """
    CREATE INDEX password_change_challenges_user_idx
        ON warden.password_change_challenges (user_id)
    """,
    """
    CREATE INDEX password_change_challenges_expiry_idx
        ON warden.password_change_challenges (expires_at)
    """,
]

_DOWNGRADE = [
    "DROP TABLE warden.password_change_challenges",
    "DROP TABLE warden.password_history",
    "DROP TABLE warden.password_states",
    "DROP TABLE warden.password_policy_watch_lists",
    "DROP TABLE warden.watch_list_staging",
    "DROP TABLE warden.watch_list_terms",
    "DROP TABLE warden.watch_list_entries",
    "DROP TABLE warden.watch_lists",
    "DROP TABLE warden.password_policy_pins",
    "DROP TABLE warden.password_policy_roles",
    "DROP TABLE warden.password_policies",
]


def upgrade() -> None:
    for statement in _UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in _DOWNGRADE:
        op.execute(statement)
