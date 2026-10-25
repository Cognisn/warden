"""Write a throwaway CA and a server certificate for the live collector.

    python tests/syslogfwd/live/make_certs.py <directory>

Creates ``ca.pem``, ``server.pem`` and ``server.key`` (for localhost and
127.0.0.1) in ``<directory>``. Test use only.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from syslogfwd.certs import Authority


def main() -> int:
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    authority = Authority("warden live syslog test CA")
    issued = authority.issue("localhost", "127.0.0.1")
    (target / "ca.pem").write_text(authority.pem, encoding="utf-8", newline="\n")
    (target / "server.pem").write_text(issued.cert_pem, encoding="utf-8", newline="\n")
    (target / "server.key").write_text(issued.key_pem, encoding="utf-8", newline="\n")
    print(f"wrote ca.pem, server.pem and server.key to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
