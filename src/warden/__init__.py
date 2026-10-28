"""warden: identity and audit for Python web applications.

The public API lives in the subpackages ``warden.config``, ``warden.db``,
``warden.keys`` and ``warden.audit``. This module deliberately imports none
of them: ``import warden.audit`` runs this file first, so anything imported
here would break audit's independence from identity.
"""

__version__ = "0.1.0a8"

__all__ = ["__version__"]
