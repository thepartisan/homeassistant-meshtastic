# Feature: meshtastic-pki-decoder, PKI (Curve25519) crypto and SharedContact QR encoding
"""Tests for aiomeshtastic.pki: the X25519/AES-256-CCM scheme used to decrypt
Meshtastic PKI (direct-message) traffic, and the hand-rolled SharedContact
protobuf encoder used to build "Add Contact" QR codes for the Meshtastic app.
"""

from __future__ import annotations

import base64

from aiomeshtastic import pki
from hypothesis import given, settings
from hypothesis import strategies as st

_uint32 = st.integers(min_value=0, max_value=2**32 - 1)
_data_payload = st.binary(min_size=0, max_size=200)
_extra_nonce = st.binary(min_size=4, max_size=4)


# ---------------------------------------------------------------------------
# Keypairs / ECDH
# ---------------------------------------------------------------------------


def test_generate_keypair_returns_32_byte_keys() -> None:
    private_key, public_key = pki.generate_keypair()
    assert len(private_key) == 32
    assert len(public_key) == 32
    assert private_key != public_key


def test_generate_keypair_is_random() -> None:
    priv_a, pub_a = pki.generate_keypair()
    priv_b, pub_b = pki.generate_keypair()
    assert priv_a != priv_b
    assert pub_a != pub_b


def test_public_key_for_private_key_matches_generated_pair() -> None:
    private_key, public_key = pki.generate_keypair()
    assert pki.public_key_for_private_key(private_key) == public_key


def test_ecdh_shared_key_is_symmetric() -> None:
    """shared_secret = A_private * B_public must equal B_private * A_public."""
    priv_a, pub_a = pki.generate_keypair()
    priv_b, pub_b = pki.generate_keypair()
    assert pki._shared_key(priv_a, pub_b) == pki._shared_key(priv_b, pub_a)


# ---------------------------------------------------------------------------
# Nonce construction (CryptoEngine::initNonce for PKI packets)
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(packet_id=_uint32, extra_nonce=_extra_nonce, from_node_id=_uint32)
def test_build_nonce_layout(
    packet_id: int, extra_nonce: bytes, from_node_id: int
) -> None:
    nonce = pki._build_nonce(packet_id, extra_nonce, from_node_id)

    assert len(nonce) == 13
    assert nonce[0:4] == (packet_id & 0xFFFFFFFF).to_bytes(4, "little")
    assert nonce[4:8] == extra_nonce
    assert nonce[8:12] == (from_node_id & 0xFFFFFFFF).to_bytes(4, "little")
    assert nonce[12] == 0


# ---------------------------------------------------------------------------
# encrypt_pki_payload / decrypt_pki_payload round trip
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    plaintext=_data_payload,
    packet_id=_uint32,
    from_node_id=_uint32,
    extra_nonce=_extra_nonce,
)
def test_pki_encrypt_decrypt_round_trip(
    plaintext: bytes, packet_id: int, from_node_id: int, extra_nonce: bytes
) -> None:
    """Encrypting with (our_private, their_public) and decrypting with the
    swapped (their_private, our_public) pair - as ECDH symmetry requires -
    must recover the original plaintext, matching firmware's
    CryptoEngine::encryptCurve25519/decryptCurve25519.
    """
    sender_private, sender_public = pki.generate_keypair()
    receiver_private, receiver_public = pki.generate_keypair()

    ciphertext = pki.encrypt_pki_payload(
        plaintext, sender_private, receiver_public, packet_id, from_node_id, extra_nonce
    )
    assert len(ciphertext) == len(plaintext) + pki.PKI_OVERHEAD

    decrypted = pki.decrypt_pki_payload(
        ciphertext, receiver_private, sender_public, packet_id, from_node_id
    )
    assert decrypted == plaintext


def test_pki_decrypt_fails_with_wrong_private_key() -> None:
    sender_private, sender_public = pki.generate_keypair()
    _receiver_private, receiver_public = pki.generate_keypair()
    wrong_private, _wrong_public = pki.generate_keypair()

    ciphertext = pki.encrypt_pki_payload(
        b"secret position data", sender_private, receiver_public, 1, 2
    )

    assert (
        pki.decrypt_pki_payload(ciphertext, wrong_private, sender_public, 1, 2) is None
    )


def test_pki_decrypt_fails_with_wrong_sender_public_key() -> None:
    sender_private, _sender_public = pki.generate_keypair()
    receiver_private, receiver_public = pki.generate_keypair()
    _wrong_private, wrong_public = pki.generate_keypair()

    ciphertext = pki.encrypt_pki_payload(
        b"secret position data", sender_private, receiver_public, 1, 2
    )

    assert (
        pki.decrypt_pki_payload(ciphertext, receiver_private, wrong_public, 1, 2)
        is None
    )


def test_pki_decrypt_fails_with_wrong_packet_id() -> None:
    """packet_id feeds the nonce, so decrypting with the wrong one must fail auth."""
    sender_private, sender_public = pki.generate_keypair()
    receiver_private, receiver_public = pki.generate_keypair()

    ciphertext = pki.encrypt_pki_payload(
        b"secret position data", sender_private, receiver_public, 42, 2
    )

    assert (
        pki.decrypt_pki_payload(ciphertext, receiver_private, sender_public, 43, 2)
        is None
    )


def test_pki_decrypt_rejects_tampered_ciphertext() -> None:
    sender_private, sender_public = pki.generate_keypair()
    receiver_private, receiver_public = pki.generate_keypair()

    ciphertext = bytearray(
        pki.encrypt_pki_payload(
            b"secret position data", sender_private, receiver_public, 1, 2
        )
    )
    ciphertext[0] ^= 0xFF

    assert (
        pki.decrypt_pki_payload(
            bytes(ciphertext), receiver_private, sender_public, 1, 2
        )
        is None
    )


def test_pki_decrypt_rejects_too_short_input() -> None:
    receiver_private, _receiver_public = pki.generate_keypair()
    sender_private, _sender_public = pki.generate_keypair()
    too_short = b"\x00" * pki.PKI_OVERHEAD
    assert (
        pki.decrypt_pki_payload(too_short, receiver_private, sender_private, 1, 2)
        is None
    )


def test_encrypt_pki_payload_rejects_bad_extra_nonce_length() -> None:
    priv, pub = pki.generate_keypair()
    try:
        pki.encrypt_pki_payload(b"x", priv, pub, 1, 2, extra_nonce=b"\x00\x00\x00")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for a non-4-byte extra_nonce")


# ---------------------------------------------------------------------------
# SharedContact protobuf encode/decode (Meshtastic "Add Contact" QR format)
# ---------------------------------------------------------------------------

_node_id = _uint32
_public_key_32 = st.binary(min_size=32, max_size=32)
_name = st.text(
    min_size=0, max_size=20, alphabet=st.characters(blacklist_categories=("Cs",))
)


def test_shared_contact_url_uses_meshtastic_contact_prefix() -> None:
    _priv, pub = pki.generate_keypair()
    url = pki.shared_contact_url(0x209DCEAB, "HA Sink", pub)
    assert url.startswith("https://meshtastic.org/v/#")


@settings(max_examples=200)
@given(node_id=_node_id, name=_name, public_key=_public_key_32)
def test_shared_contact_round_trip(node_id: int, name: str, public_key: bytes) -> None:
    encoded = pki.encode_shared_contact(node_id, name, public_key)
    decoded = pki.decode_shared_contact(encoded)

    assert decoded["node_num"] == node_id
    assert decoded["user"]["public_key"] == public_key
    assert decoded["user"]["id"] == f"!{node_id:08x}"


@settings(max_examples=200)
@given(node_id=_node_id, name=_name, public_key=_public_key_32)
def test_shared_contact_url_round_trip(
    node_id: int, name: str, public_key: bytes
) -> None:
    """The base64url payload after the URL fragment must decode back to the
    same SharedContact that was encoded - this is what the Meshtastic app's
    QR scanner parses (see MeshtasticUrlConstants/UriUtils in the Android app).
    """
    url = pki.shared_contact_url(node_id, name, public_key)
    encoded_part = url[len(pki.CONTACT_URL_PREFIX) :]
    padded = encoded_part + "=" * (-len(encoded_part) % 4)
    raw = base64.urlsafe_b64decode(padded)

    decoded = pki.decode_shared_contact(raw)
    assert decoded["node_num"] == node_id
    assert decoded["user"]["public_key"] == public_key
