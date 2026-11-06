"""A software WebAuthn authenticator and browser for tests (ruling P10).

It builds genuine registration and authentication responses from real key
pairs (ES256, Ed25519 and RS256), in the JSON a browser's ``toJSON()``
returns, so every ceremony is checked end to end with no recorded fixture
to go stale. Every field a relying party checks can be set wrongly on
purpose: the client data's type, challenge, origin and crossOrigin; the
relying party id hashed into the authenticator data; the UP, UV, BE and BS
flags; the signature counter; the user handle; and the attestation, which
is "none", self "packed", or "packed" with a certificate chain from a test
CA (``TestCa``) to exercise trusted attestation roots.

Waves 10 to 12 reuse it (imported as ``soft_authenticator``).
"""

from __future__ import annotations

import datetime
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from fido2 import cbor
from fido2.cose import ES256, RS256, CoseKey, EdDSA
from fido2.utils import sha256, websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)

Algorithm = Literal["ES256", "EdDSA", "RS256"]
AttestationFormat = Literal["none", "self", "packed"]

ORIGIN = "https://app.example.com"
RP_ID = "app.example.com"
AAGUID = uuid.UUID("2fc0579f-8113-47ea-b116-bb5a8db9202a")

_FLAG = AuthenticatorData.FLAG
_AAGUID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
_COSE: dict[str, type[CoseKey]] = {"ES256": ES256, "EdDSA": EdDSA, "RS256": RS256}


PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey


def _new_key(algorithm: Algorithm) -> PrivateKey:
    if algorithm == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "EdDSA":
        return ed25519.Ed25519PrivateKey.generate()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _sign(key: PrivateKey, data: bytes) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(data)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _name(common_name: str, *, attestation: bool = False) -> x509.Name:
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Authenticators"),
    ]
    if attestation:
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation")
        )
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def _certificate(
    subject: x509.Name,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    aaguid: uuid.UUID | None = None,
    days: int = 365,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aaguid is not None:
        # id-fido-gen-ce-aaguid: an OCTET STRING holding the 16 bytes.
        value = b"\x04\x10" + aaguid.bytes
        builder = builder.add_extension(
            x509.UnrecognizedExtension(_AAGUID_OID, value), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


@dataclass
class TestCa:
    """A vendor's attestation hierarchy: root, intermediate, attestation certificate.

    ``root_pem`` is what a product would configure as a trusted attestation
    root; ``chain`` is the ``x5c`` an authenticator sends (leaf first).
    """

    __test__ = False  # not a pytest class

    root: x509.Certificate
    intermediate: x509.Certificate
    leaf: x509.Certificate
    leaf_key: ec.EllipticCurvePrivateKey

    @classmethod
    def create(cls, vendor: str = "Example", *, aaguid: uuid.UUID | None = AAGUID) -> TestCa:
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = _name(f"{vendor} Attestation Root")
        root = _certificate(root_name, root_key, root_name, root_key, ca=True)
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_name = _name(f"{vendor} Attestation CA")
        intermediate = _certificate(
            intermediate_name, intermediate_key, root_name, root_key, ca=True
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _certificate(
            _name(f"{vendor} Key", attestation=True),
            leaf_key,
            intermediate_name,
            intermediate_key,
            ca=False,
            aaguid=aaguid,
        )
        return cls(root=root, intermediate=intermediate, leaf=leaf, leaf_key=leaf_key)

    @property
    def root_pem(self) -> str:
        return _pem(self.root)

    @property
    def chain(self) -> list[bytes]:
        return [_der(self.leaf), _der(self.intermediate)]

    def forged_chain(self) -> tuple[list[bytes], ec.EllipticCurvePrivateKey]:
        """A certificate issued by this CA's attestation (leaf) certificate.

        The leaf is not a CA, so a chain through it must not be trusted even
        though every signature in it is genuine.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        forged = _certificate(
            _name("Forged Key", attestation=True),
            key,
            self.leaf.subject,
            self.leaf_key,
            ca=False,
        )
        return [_der(forged), _der(self.leaf), _der(self.intermediate)], key


@dataclass
class StoredCredential:
    """What the authenticator keeps for one credential."""

    credential_id: bytes
    key: PrivateKey
    algorithm: Algorithm
    rp_id: str
    user_handle: bytes
    resident: bool
    counter: int = 0


@dataclass
class SoftwareAuthenticator:
    """One authenticator, holding the credentials it has created.

    ``counter_step`` is how much the signature counter rises per use; 0 is an
    authenticator without a counter (synced passkeys usually are).
    """

    algorithm: Algorithm = "ES256"
    attestation: AttestationFormat = "none"
    ca: TestCa | None = None
    aaguid: uuid.UUID = AAGUID
    resident: bool = False
    user_verifying: bool = True
    backup_eligible: bool = False
    backed_up: bool = False
    counter_step: int = 1
    transports: Sequence[str] = ("usb",)
    credentials: dict[bytes, StoredCredential] = field(default_factory=dict)

    def _flags(
        self, *, up: bool, uv: bool | None, be: bool | None, bs: bool | None
    ) -> AuthenticatorData.FLAG:
        flags = _FLAG(0)
        if up:
            flags |= _FLAG.UP
        if self.user_verifying if uv is None else uv:
            flags |= _FLAG.UV
        if self.backup_eligible if be is None else be:
            flags |= _FLAG.BE
        if self.backed_up if bs is None else bs:
            flags |= _FLAG.BS
        return flags

    def register(
        self,
        options: Mapping[str, Any],
        *,
        origin: str = ORIGIN,
        type: str = "webauthn.create",
        challenge: bytes | None = None,
        cross_origin: bool = False,
        rp_id: str | None = None,
        up: bool = True,
        uv: bool | None = None,
        be: bool | None = None,
        bs: bool | None = None,
        resident: bool | None = None,
        credential_id: bytes | None = None,
        attestation: AttestationFormat | None = None,
        x5c: list[bytes] | None = None,
        attestation_key: ec.EllipticCurvePrivateKey | None = None,
        report_rk: bool | None = True,
        transports: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Answer ``navigator.credentials.create()`` with ``options`` (the publicKey part)."""
        relying_party = rp_id if rp_id is not None else options["rp"].get("id", RP_ID)
        selection = options.get("authenticatorSelection") or {}
        is_resident = (
            resident
            if resident is not None
            else self.resident or selection.get("residentKey") == "required"
        )
        key = _new_key(self.algorithm)
        cose = _COSE[self.algorithm].from_cryptography_key(key.public_key())
        new_id = credential_id if credential_id is not None else os.urandom(32)
        stored = StoredCredential(
            credential_id=new_id,
            key=key,
            algorithm=self.algorithm,
            rp_id=relying_party,
            user_handle=websafe_decode(options["user"]["id"]),
            resident=is_resident,
        )
        self.credentials[new_id] = stored

        client_data = CollectedClientData.create(
            type=type,
            challenge=challenge if challenge is not None else websafe_decode(options["challenge"]),
            origin=origin,
            cross_origin=cross_origin,
        )
        auth_data = AuthenticatorData.create(
            sha256(relying_party.encode("utf-8")),
            self._flags(up=up, uv=uv, be=be, bs=bs) | _FLAG.AT,
            0,
            AttestedCredentialData.create(self.aaguid.bytes, new_id, cose),
        )
        statement = self._statement(
            attestation or self.attestation,
            auth_data,
            client_data,
            key,
            x5c=x5c,
            attestation_key=attestation_key,
        )
        fmt = "none" if (attestation or self.attestation) == "none" else "packed"
        attestation_object = AttestationObject.create(fmt, auth_data, statement)
        results: dict[str, Any] = {}
        if report_rk is not None:
            results["credProps"] = {"rk": is_resident if report_rk else False}
        return {
            "id": websafe_encode(new_id),
            "rawId": websafe_encode(new_id),
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "response": {
                "clientDataJSON": websafe_encode(bytes(client_data)),
                "attestationObject": websafe_encode(bytes(attestation_object)),
                "transports": list(self.transports if transports is None else transports),
            },
            "clientExtensionResults": results,
        }

    def _statement(
        self,
        fmt: AttestationFormat,
        auth_data: AuthenticatorData,
        client_data: CollectedClientData,
        key: PrivateKey,
        *,
        x5c: list[bytes] | None,
        attestation_key: ec.EllipticCurvePrivateKey | None,
    ) -> dict[str, Any]:
        signed = bytes(auth_data) + client_data.hash
        if fmt == "none":
            return {}
        if fmt == "self":
            alg = _COSE[self.algorithm].ALGORITHM
            return {"alg": alg, "sig": _sign(key, signed)}
        chain = x5c if x5c is not None else (self.ca.chain if self.ca is not None else None)
        signer = attestation_key or (self.ca.leaf_key if self.ca is not None else None)
        if chain is None or signer is None:
            raise ValueError("packed attestation with a chain needs a TestCa")
        return {"alg": ES256.ALGORITHM, "sig": _sign(signer, signed), "x5c": chain}

    def authenticate(
        self,
        options: Mapping[str, Any],
        *,
        credential_id: bytes | None = None,
        origin: str = ORIGIN,
        type: str = "webauthn.get",
        challenge: bytes | None = None,
        cross_origin: bool = False,
        rp_id: str | None = None,
        up: bool = True,
        uv: bool | None = None,
        be: bool | None = None,
        bs: bool | None = None,
        counter: int | None = None,
        user_handle: bytes | Literal["stored"] | None = "stored",
        signing_key: PrivateKey | None = None,
    ) -> dict[str, Any]:
        """Answer ``navigator.credentials.get()`` with ``options`` (the publicKey part).

        Without ``credential_id`` it uses the first allowed credential it
        holds or, with no allow list, its first resident credential.
        """
        stored = self._choose(options, credential_id)
        if counter is None:
            stored.counter += self.counter_step
            counter = stored.counter
        client_data = CollectedClientData.create(
            type=type,
            challenge=challenge if challenge is not None else websafe_decode(options["challenge"]),
            origin=origin,
            cross_origin=cross_origin,
        )
        relying_party = rp_id if rp_id is not None else stored.rp_id
        auth_data = AuthenticatorData.create(
            sha256(relying_party.encode("utf-8")),
            self._flags(up=up, uv=uv, be=be, bs=bs),
            counter,
        )
        signature = _sign(signing_key or stored.key, bytes(auth_data) + client_data.hash)
        handle = stored.user_handle if user_handle == "stored" else user_handle
        response: dict[str, Any] = {
            "clientDataJSON": websafe_encode(bytes(client_data)),
            "authenticatorData": websafe_encode(bytes(auth_data)),
            "signature": websafe_encode(signature),
        }
        if handle is not None:
            response["userHandle"] = websafe_encode(handle)
        return {
            "id": websafe_encode(stored.credential_id),
            "rawId": websafe_encode(stored.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "cross-platform",
            "response": response,
            "clientExtensionResults": {},
        }

    def _choose(self, options: Mapping[str, Any], credential_id: bytes | None) -> StoredCredential:
        if credential_id is not None:
            return self.credentials[credential_id]
        allowed = [websafe_decode(d["id"]) for d in options.get("allowCredentials") or []]
        if allowed:
            for candidate in allowed:
                if candidate in self.credentials:
                    return self.credentials[candidate]
            raise LookupError("no allowed credential on this authenticator")
        for stored in self.credentials.values():
            if stored.resident:
                return stored
        raise LookupError("no resident credential on this authenticator")

    def only_credential(self) -> StoredCredential:
        (stored,) = self.credentials.values()
        return stored


def other_key(algorithm: Algorithm = "ES256") -> PrivateKey:
    """A key no credential holds, for signatures that must not verify."""
    return _new_key(algorithm)


def decode_cose(public_key: bytes) -> CoseKey:
    return CoseKey.parse(cbor.decode(public_key))
