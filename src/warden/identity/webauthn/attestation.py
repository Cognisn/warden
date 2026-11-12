"""Trusted attestation roots (ruling P3).

With roots configured, a registration is accepted only when its attestation
statement verifies (fido2's format verifiers) and its certificate chain
leads to one of the roots: every certificate is in its validity period,
each is issued by the next (name and signature), every issuer is a CA, and
the last is issued by a configured root. Self attestation and "none" carry
no chain, so they are refused. warden never fetches attestation metadata.
"""

from __future__ import annotations

import datetime
import itertools

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from fido2.attestation.base import Attestation, AttestationType, InvalidAttestation
from fido2.webauthn import AttestationObject

_CHAINED = frozenset({AttestationType.BASIC, AttestationType.ATT_CA})


class AttestationNotTrusted(Exception):
    """The attestation does not chain to a trusted root."""


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return constraints.value.ca


def _issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


class TrustedRoots:
    def __init__(self, pem: str | None) -> None:
        self._roots: tuple[x509.Certificate, ...] = (
            () if pem is None else tuple(x509.load_pem_x509_certificates(pem.encode("ascii")))
        )

    def __bool__(self) -> bool:
        return bool(self._roots)

    def check(self, attestation: AttestationObject, client_data_hash: bytes) -> None:
        """Raise ``AttestationNotTrusted`` unless the attestation chains to a root."""
        if attestation.fmt == "none":
            raise AttestationNotTrusted
        verifier = Attestation.for_type(attestation.fmt)()
        try:
            result = verifier.verify(attestation.att_stmt, attestation.auth_data, client_data_hash)
        except (InvalidAttestation, ValueError, TypeError, KeyError, NotImplementedError):
            raise AttestationNotTrusted from None
        if result.attestation_type not in _CHAINED or not result.trust_path:
            raise AttestationNotTrusted
        try:
            chain = [x509.load_der_x509_certificate(der) for der in result.trust_path]
        except ValueError:
            raise AttestationNotTrusted from None
        now = datetime.datetime.now(datetime.UTC)
        if any(not c.not_valid_before_utc <= now <= c.not_valid_after_utc for c in chain):
            raise AttestationNotTrusted
        for child, issuer in itertools.pairwise(chain):
            if not _is_ca(issuer) or not _issued_by(child, issuer):
                raise AttestationNotTrusted
        if not any(_issued_by(chain[-1], root) for root in self._roots):
            raise AttestationNotTrusted
