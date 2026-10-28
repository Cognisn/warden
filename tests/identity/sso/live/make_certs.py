"""Write a throwaway CA and a TLS keystore for the stub identity provider.

    python tests/identity/sso/live/make_certs.py <directory>

Creates ``ca.pem`` and ``idp.p12`` (a PKCS12 keystore for localhost and
127.0.0.1, password ``warden-dev-only``) in ``<directory>``. Test use only.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from syslogfwd.certs import Authority

PASSWORD = b"warden-dev-only"


def main() -> int:
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    authority = Authority("warden live single sign-on test CA")
    issued = authority.issue("localhost", "127.0.0.1")
    key = serialization.load_pem_private_key(issued.key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(issued.cert_pem.encode())
    keystore = pkcs12.serialize_key_and_certificates(
        b"idp",
        key,  # type: ignore[arg-type]
        cert,
        None,
        serialization.BestAvailableEncryption(PASSWORD),
    )
    (target / "ca.pem").write_text(authority.pem, encoding="utf-8", newline="\n")
    (target / "idp.p12").write_bytes(keystore)
    print(f"wrote ca.pem and idp.p12 to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
