# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify and transform the pinned OpenSC generation-2 credential data.

The array parser, manifest framing and PKCS#1 serialization reproduce the proven
preparer at Validation/Spikes/SecureChannel/Scripts/prepare-local-credential-fixture.py.
This module uses only the Python standard library.
"""

import hashlib
import json
import math
import re

SOURCE_SHA256 = "6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a"
OFFICIAL_BINARY_SHA256 = "d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2"
MANIFEST_V2_SHA256 = "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d"

FIELD_NAMES = (
    "icc_root_ca_modulus_1",
    "ifd_modulus_1",
    "ifd_pin_modulus_1",
    "ifd_private_exponent_1",
    "ifd_pin_private_exponent_1",
    "C_CV_CA_CS_AUT_cert_1",
    "C_CV_IFDUser_AUT_cert_1",
    "C_CV_IFDUser_AUT_pin_cert_1",
    "cvc_intca_keyref_1",
    "cvc_ifd_keyref_1",
    "cvc_ifd_keyref_pin_1",
    "sn_ifd_1",
    "sn_ifd_pin_1",
    "icc_root_ca_public_exponent",
    "ifd_public_exponent",
    "ifd_pin_public_exponent",
    "root_ca_keyref",
    "icc_priv_keyref",
)

EXCERPT_HEADER = """/*
 * DNIe generation-2 terminal credential data from OpenSC src/libopensc/cwa-dnie.c
 * OpenSC revision bc9a74a44565c091fc473d87193ec3a35c55b1f0
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 * Generation-2 data contribution: rickyepoderi, OpenSC pull request #2109.
 *
 * Modified 2026-11-19 by the dnie-macos project: selected and reformatted the
 * 18 generation-2 credential declarations and omitted all other OpenSC code.
 * For this copy, GNU LGPL version 2.1 section 3 is used to apply the GNU
 * General Public License, version 3 or any later version, instead.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"""


class CredentialFormatError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def extract(source: str, name: str) -> bytes:
    match = re.search(
        r"(?:unsigned\s+char|u8)\s+" + re.escape(name) + r"\s*\[[^]]*\]\s*=\s*\{(.*?)\};",
        source,
        re.S,
    )
    if match is None:
        raise CredentialFormatError("A required credential field is absent.")
    values = re.findall(r"0x([0-9A-Fa-f]{1,2})", match.group(1))
    if not values:
        raise CredentialFormatError("A required credential field is empty.")
    return bytes(int(value, 16) for value in values)

def manifest_digest(fields: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in FIELD_NAMES:
        value = fields[name]
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()

def encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded

def encode_der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative DER integer")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return b"\x02" + encode_der_length(len(encoded)) + encoded

def recover_rsa_factors(modulus: int, public_exponent: int, private_exponent: int) -> tuple[int, int]:
    # PKCS#1 import requires CRT factors although the authorized source records n/e/d.
    # Since e*d - 1 is a multiple of lambda(n), a bounded deterministic search recovers
    # the two factors without performing any protocol RSA operation.
    multiple = public_exponent * private_exponent - 1
    if multiple < 2 or modulus < 3:
        raise ValueError("invalid RSA parameters")
    odd = multiple
    powers_of_two = 0
    while odd & 1 == 0:
        odd >>= 1
        powers_of_two += 1
    for base in range(2, 4096):
        value = pow(base, odd, modulus)
        if value in (1, modulus - 1):
            continue
        for _ in range(powers_of_two):
            squared = pow(value, 2, modulus)
            if squared == 1:
                factor = math.gcd(value - 1, modulus)
                if 1 < factor < modulus and modulus % factor == 0:
                    return tuple(sorted((factor, modulus // factor), reverse=True))
                break
            if squared == modulus - 1:
                break
            value = squared
    raise ValueError("unable to recover RSA factors from authorized n/e/d")

def rsa_private_key_pkcs1(modulus_bytes: bytes, exponent_bytes: bytes, private_bytes: bytes) -> bytes:
    modulus = int.from_bytes(modulus_bytes, "big")
    public_exponent = int.from_bytes(exponent_bytes, "big")
    private_exponent = int.from_bytes(private_bytes, "big")
    p, q = recover_rsa_factors(modulus, public_exponent, private_exponent)
    if p * q != modulus:
        raise ValueError("recovered RSA factors do not match modulus")
    values = (
        0,
        modulus,
        public_exponent,
        private_exponent,
        p,
        q,
        private_exponent % (p - 1),
        private_exponent % (q - 1),
        pow(q, -1, p),
    )
    body = b"".join(encode_der_integer(value) for value in values)
    return b"\x30" + encode_der_length(len(body)) + body

def encode_fixture(fields: dict[str, bytes]) -> bytes:
    payload = {
        "fixture_version": 2,
        "set_id": "generation_2",
        "source_sha256": SOURCE_SHA256,
        "official_binary_sha256": OFFICIAL_BINARY_SHA256,
        "manifest_sha256": manifest_digest(fields),
        "ordered_field_names": FIELD_NAMES,
        "fields_hex": {name: fields[name].hex() for name in FIELD_NAMES},
        "local_private_keys_pkcs1_hex": {
            "user": rsa_private_key_pkcs1(
                fields["ifd_modulus_1"],
                fields["ifd_public_exponent"],
                fields["ifd_private_exponent_1"],
            ).hex(),
            "pin": rsa_private_key_pkcs1(
                fields["ifd_pin_modulus_1"],
                fields["ifd_pin_public_exponent"],
                fields["ifd_pin_private_exponent_1"],
            ).hex(),
        },
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def extract_fields(source: bytes) -> dict[str, bytes]:
    try:
        source_text = source.decode("utf-8")
    except UnicodeDecodeError:
        raise CredentialFormatError("Credential source encoding is invalid.") from None
    return {name: extract(source_text, name) for name in FIELD_NAMES}


def verify_manifest(fields: dict[str, bytes]) -> None:
    if manifest_digest(fields) != MANIFEST_V2_SHA256:
        raise CredentialFormatError("Generation-2 manifest does not match the reviewed pin.")


def verify_upstream_source(source: bytes) -> None:
    if sha256(source) != SOURCE_SHA256:
        raise CredentialFormatError("Pinned OpenSC source hash mismatch.")


def fixture_from_inputs(source: bytes, official: bytes) -> bytes:
    verify_upstream_source(source)
    if sha256(official) != OFFICIAL_BINARY_SHA256:
        raise CredentialFormatError("Pinned official DGP binary hash mismatch.")
    fields = extract_fields(source)
    if any(value not in official for value in fields.values()):
        raise CredentialFormatError("A credential field is absent from the official DGP binary.")
    verify_manifest(fields)
    return encode_fixture(fields)


def encode_source_excerpt(fields: dict[str, bytes]) -> bytes:
    declarations = [EXCERPT_HEADER]
    for name in FIELD_NAMES:
        value = fields[name]
        rows = [value[offset:offset + 12] for offset in range(0, len(value), 12)]
        byte_rows = ["    " + ", ".join(f"0x{byte:02x}" for byte in row) + ",\n" for row in rows]
        declarations.append(f"static const unsigned char {name}[] = {{\n"
                            + "".join(byte_rows) + "};\n")
    return "\n".join(declarations).encode("ascii")


def source_excerpt_from_fixture(data: bytes) -> bytes:
    try:
        fixture = json.loads(data)
        fields = {name: bytes.fromhex(fixture["fields_hex"][name]) for name in FIELD_NAMES}
    except (ValueError, KeyError, TypeError):
        raise CredentialFormatError("Credential fixture fields are invalid.") from None
    verify_manifest(fields)
    if encode_fixture(fields) != data:
        raise CredentialFormatError("Credential fixture differs from the reproducible encoding.")
    return encode_source_excerpt(fields)


def fixture_from_excerpt(source: bytes) -> bytes:
    fields = extract_fields(source)
    verify_manifest(fields)
    if encode_source_excerpt(fields) != source:
        raise CredentialFormatError("Credential source excerpt differs from the reviewed format.")
    return encode_fixture(fields)
