# SPDX-License-Identifier: MIT

"""Meshtastic PKI (Curve25519) helpers.

Implements the same X25519 ECDH + SHA-256 KDF + AES-256-CCM scheme the
Meshtastic firmware uses for direct-message ("PKI") encryption
(``CryptoEngine::encryptCurve25519``/``decryptCurve25519``), plus a minimal
hand-rolled encoder/decoder for the ``SharedContact`` protobuf message the
Meshtastic app scans as a QR code to add a contact ("Add Contact").
``SharedContact`` isn't part of this integration's existing generated
protobuf bundle (``admin_pb2`` predates it), and its wire format is small
and stable enough that adding a protoc build step just for one message
isn't worth it - it's hand-encoded/decoded here instead.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PKI_TAG_LENGTH = 8
PKI_EXTRA_NONCE_LENGTH = 4
# Matches MESHTASTIC_PKC_OVERHEAD in firmware: ciphertext || 8-byte tag || 4-byte extraNonce
PKI_OVERHEAD = PKI_TAG_LENGTH + PKI_EXTRA_NONCE_LENGTH

CONTACT_URL_PREFIX = "https://meshtastic.org/v/#"


# ---------------------------------------------------------------------------
# X25519 keypairs
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new X25519 keypair.

    Returns:
        A ``(private_key, public_key)`` tuple of 32 raw bytes each.
    """
    private_key = X25519PrivateKey.generate()
    return _private_raw(private_key), _public_raw(private_key.public_key())


def public_key_for_private_key(private_key_raw: bytes) -> bytes:
    """Derive the public key bytes for a raw 32-byte X25519 private key."""
    private_key = X25519PrivateKey.from_private_bytes(private_key_raw)
    return _public_raw(private_key.public_key())


def _private_raw(private_key: X25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _public_raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _shared_key(our_private_raw: bytes, their_public_raw: bytes) -> bytes:
    """ECDH + SHA-256 KDF, matching firmware's CryptoEngine::hash(Curve25519::dh2(...))."""
    our_private = X25519PrivateKey.from_private_bytes(our_private_raw)
    their_public = X25519PublicKey.from_public_bytes(their_public_raw)
    shared_secret = our_private.exchange(their_public)
    return hashlib.sha256(shared_secret).digest()


def _build_nonce(packet_id: int, extra_nonce: bytes, from_node_id: int) -> bytes:
    """Build the 13-byte AES-CCM nonce used by CryptoEngine::initNonce for PKI packets."""
    return (
        (packet_id & 0xFFFFFFFF).to_bytes(4, "little")
        + extra_nonce
        + (from_node_id & 0xFFFFFFFF).to_bytes(4, "little")
        + b"\x00"
    )


# ---------------------------------------------------------------------------
# AES-256-CCM encrypt/decrypt (Curve25519/PKI packet payloads)
# ---------------------------------------------------------------------------


def decrypt_pki_payload(
    encrypted: bytes,
    our_private_raw: bytes,
    their_public_raw: bytes,
    packet_id: int,
    from_node_id: int,
) -> bytes | None:
    """Decrypt a PKI (Curve25519) encrypted MeshPacket payload.

    Wire layout: ``ciphertext || 8-byte AES-CCM tag || 4-byte extraNonce``.

    Returns:
        The decrypted plaintext, or None if the ciphertext is too short or
        authentication fails (wrong keys, corrupted data, etc).
    """
    if len(encrypted) < PKI_OVERHEAD:
        return None

    ciphertext_and_tag = encrypted[:-PKI_EXTRA_NONCE_LENGTH]
    extra_nonce = encrypted[-PKI_EXTRA_NONCE_LENGTH:]

    key = _shared_key(our_private_raw, their_public_raw)
    nonce = _build_nonce(packet_id, extra_nonce, from_node_id)

    try:
        return AESCCM(key, tag_length=PKI_TAG_LENGTH).decrypt(
            nonce, ciphertext_and_tag, None
        )
    except Exception:
        return None


def encrypt_pki_payload(
    plaintext: bytes,
    our_private_raw: bytes,
    their_public_raw: bytes,
    packet_id: int,
    from_node_id: int,
    extra_nonce: bytes | None = None,
) -> bytes:
    """Encrypt a payload the same way firmware's CryptoEngine::encryptCurve25519 does.

    This integration never originates PKI-encrypted mesh traffic itself;
    this is provided to build realistic fixtures for testing
    decrypt_pki_payload() against real ciphertext.
    """
    if extra_nonce is None:
        extra_nonce = os.urandom(PKI_EXTRA_NONCE_LENGTH)
    elif len(extra_nonce) != PKI_EXTRA_NONCE_LENGTH:
        msg = "extra_nonce must be 4 bytes"
        raise ValueError(msg)

    key = _shared_key(our_private_raw, their_public_raw)
    nonce = _build_nonce(packet_id, extra_nonce, from_node_id)
    ciphertext_and_tag = AESCCM(key, tag_length=PKI_TAG_LENGTH).encrypt(
        nonce, plaintext, None
    )
    return ciphertext_and_tag + extra_nonce


# ---------------------------------------------------------------------------
# SharedContact protobuf (admin.proto) - hand-encoded, see module docstring
# ---------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _encode_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_varint_field(field_number: int, value: int) -> bytes:
    return _encode_tag(field_number, 0) + _encode_varint(value)


def _encode_bytes_field(field_number: int, data: bytes) -> bytes:
    return _encode_tag(field_number, 2) + _encode_varint(len(data)) + data


def _encode_string_field(field_number: int, value: str) -> bytes:
    return _encode_bytes_field(field_number, value.encode("utf-8"))


def _encode_user(
    node_id: int, long_name: str, short_name: str, public_key: bytes
) -> bytes:
    # Field numbers per meshtastic_User in mesh.proto: id=1, long_name=2, short_name=3, public_key=8
    out = bytearray()
    out += _encode_string_field(1, f"!{node_id:08x}")
    if long_name:
        out += _encode_string_field(2, long_name)
    if short_name:
        out += _encode_string_field(3, short_name)
    out += _encode_bytes_field(8, public_key)
    return bytes(out)


def encode_shared_contact(node_id: int, name: str, public_key: bytes) -> bytes:
    """Encode a SharedContact protobuf message (admin.proto) for QR/URL sharing.

    Only the fields the Meshtastic app's "Add Contact" QR scanner needs are
    populated: node_num (field 1), and a User (field 2) with
    id/long_name/short_name/public_key.
    """
    long_name = name or f"Node {node_id:08x}"
    short_name = (name or f"{node_id:08x}")[:4]
    user_bytes = _encode_user(node_id, long_name, short_name, public_key)

    out = bytearray()
    out += _encode_varint_field(1, node_id)
    out += _encode_bytes_field(2, user_bytes)
    return bytes(out)


def shared_contact_url(node_id: int, name: str, public_key: bytes) -> str:
    """Build the ``https://meshtastic.org/v/#...`` URL the Meshtastic app's QR scanner expects.

    This is the same URL scheme (and path segment, ``/v/``) the official
    Meshtastic apps use for their own "Share Contact" QR codes - confirmed
    against the Android app's ``MeshtasticUrlConstants``/``UriUtils`` source.
    """
    encoded = encode_shared_contact(node_id, name, public_key)
    return CONTACT_URL_PREFIX + base64.urlsafe_b64encode(encoded).decode(
        "ascii"
    ).rstrip("=")


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7


def _iter_fields(data: bytes) -> Any:
    pos = 0
    length = len(data)
    while pos < length:
        tag, pos = _decode_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
        elif wire_type == 2:
            field_length, pos = _decode_varint(data, pos)
            value = data[pos : pos + field_length]
            pos += field_length
        elif wire_type == 1:
            value = data[pos : pos + 8]
            pos += 8
        elif wire_type == 5:
            value = data[pos : pos + 4]
            pos += 4
        else:
            msg = f"Unsupported protobuf wire type {wire_type}"
            raise ValueError(msg)
        yield field_number, value


def decode_user(data: bytes) -> dict[str, Any]:
    """Decode a User protobuf message. Inverse of _encode_user(), for tests/import."""
    user: dict[str, Any] = {
        "id": "",
        "long_name": "",
        "short_name": "",
        "public_key": b"",
    }
    for field_number, value in _iter_fields(data):
        if field_number == 1:
            user["id"] = value.decode("utf-8", errors="replace")
        elif field_number == 2:
            user["long_name"] = value.decode("utf-8", errors="replace")
        elif field_number == 3:
            user["short_name"] = value.decode("utf-8", errors="replace")
        elif field_number == 8:
            user["public_key"] = value
    return user


def decode_shared_contact(data: bytes) -> dict[str, Any]:
    """Decode a SharedContact protobuf message. Inverse of encode_shared_contact(), for tests/import."""
    contact: dict[str, Any] = {"node_num": 0, "user": None}
    for field_number, value in _iter_fields(data):
        if field_number == 1:
            contact["node_num"] = value
        elif field_number == 2:
            contact["user"] = decode_user(value)
    return contact
