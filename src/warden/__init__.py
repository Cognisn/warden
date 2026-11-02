"""warden: identity and audit for Python web applications.

The public API lives in the subpackages, each exporting its names in
``__all__``:

- ``warden.config``: the typed configuration and its loaders.
- ``warden.db``: the pool adapter, schema names and migrations.
- ``warden.keys``: the Ed25519 key store; ``warden.jwks``: its publication
  router.
- ``warden.proxy``: the trusted-proxy middleware.
- ``warden.audit``: the audit recorder, chain, query, retention and anchors;
  ``warden.audit.syslog``: syslog forwarding.
- ``warden.identity``: users, sign-in, sessions, roles, the user lifecycle
  and single sign-on.

This module deliberately imports none of them: ``import warden.audit`` runs
this file first, so anything imported here would break audit's independence
from identity (design D11).
"""

__version__ = "0.1.0b7"

__all__ = ["__version__"]
