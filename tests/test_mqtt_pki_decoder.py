# Feature: meshtastic-pki-decoder, PKI (Curve25519) decrypt path in MqttPacketDecoder
"""Tests for MqttPacketDecoder's handling of PKI-encrypted (pki_encrypted)
MeshPackets: decrypting direct-message traffic addressed to a configured
PKI identity, and auto-learning senders' own public keys from decrypted
NodeInfo broadcasts (the only place a node's public key appears on the wire
for PKI traffic - see aiomeshtastic/pki.py's module docstring).
"""

from __future__ import annotations

import base64

from aiomeshtastic import pki
from aiomeshtastic.connection.decoder import MqttPacketDecoder
from aiomeshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2
from hypothesis import given, settings
from hypothesis import strategies as st

_uint32 = st.integers(min_value=0, max_value=2**32 - 1)
_data_payload = st.binary(min_size=0, max_size=200)

_SINK_NODE_ID = 0x209DCEAB
_SENDER_NODE_ID = 0x11223344


def _make_decoder(sink_private_key: bytes) -> MqttPacketDecoder:
    return MqttPacketDecoder(
        channel_keys=[],
        pki_identities=[
            {
                "node_id": str(_SINK_NODE_ID),
                "private_key": base64.b64encode(sink_private_key).decode(),
            }
        ],
    )


def _wrap_in_envelope(packet: mesh_pb2.MeshPacket, channel_id: str = "PKI") -> bytes:
    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.packet.CopyFrom(packet)
    envelope.channel_id = channel_id
    envelope.gateway_id = "!deadbeef"
    return envelope.SerializeToString()


def _build_pki_packet(
    plaintext_data: bytes,
    sender_private: bytes,
    receiver_public: bytes,
    packet_id: int,
    from_node_id: int,
    to_node_id: int,
) -> mesh_pb2.MeshPacket:
    encrypted = pki.encrypt_pki_payload(
        plaintext_data, sender_private, receiver_public, packet_id, from_node_id
    )

    packet = mesh_pb2.MeshPacket()
    packet.__setattr__("from", from_node_id)
    packet.to = to_node_id
    packet.id = packet_id
    packet.pki_encrypted = True
    packet.encrypted = encrypted
    return packet


def test_pki_packet_dropped_without_configured_identity() -> None:
    """No pki_identities configured at all -> the packet can't be decrypted."""
    decoder = MqttPacketDecoder(channel_keys=[])
    sender_private, _sender_public = pki.generate_keypair()
    _receiver_private, receiver_public = pki.generate_keypair()

    data = mesh_pb2.Data(portnum=portnums_pb2.PortNum.POSITION_APP, payload=b"lat/lon")
    packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        receiver_public,
        1,
        _SENDER_NODE_ID,
        _SINK_NODE_ID,
    )

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(packet)
    )
    assert result is None


def test_pki_packet_dropped_without_learned_sender_public_key() -> None:
    """Identity is configured, but this sender's public key hasn't been seen yet."""
    sink_private, sink_public = pki.generate_keypair()
    decoder = _make_decoder(sink_private)
    sender_private, _sender_public = pki.generate_keypair()

    data = mesh_pb2.Data(portnum=portnums_pb2.PortNum.POSITION_APP, payload=b"lat/lon")
    packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        sink_public,
        1,
        _SENDER_NODE_ID,
        _SINK_NODE_ID,
    )

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(packet)
    )
    assert result is None


def test_pki_packet_decrypts_after_learn_public_key() -> None:
    sink_private, sink_public = pki.generate_keypair()
    decoder = _make_decoder(sink_private)
    sender_private, sender_public = pki.generate_keypair()
    decoder.learn_public_key(_SENDER_NODE_ID, sender_public)

    data = mesh_pb2.Data(portnum=portnums_pb2.PortNum.POSITION_APP, payload=b"lat/lon")
    packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        sink_public,
        7,
        _SENDER_NODE_ID,
        _SINK_NODE_ID,
    )

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(packet)
    )

    assert result is not None
    assert result.decoded.portnum == portnums_pb2.PortNum.POSITION_APP
    assert result.decoded.payload == b"lat/lon"
    assert not result.HasField("encrypted")


def test_pki_packet_decrypt_fails_for_different_sink_identity() -> None:
    """Encrypted to a sink we don't hold the private key for -> stays undecrypted."""
    _other_sink_private, other_sink_public = pki.generate_keypair()
    our_sink_private, _our_sink_public = pki.generate_keypair()
    decoder = _make_decoder(our_sink_private)
    sender_private, sender_public = pki.generate_keypair()
    decoder.learn_public_key(_SENDER_NODE_ID, sender_public)

    data = mesh_pb2.Data(portnum=portnums_pb2.PortNum.POSITION_APP, payload=b"lat/lon")
    # to = _SINK_NODE_ID but actually encrypted to a *different* keypair than ours
    packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        other_sink_public,
        1,
        _SENDER_NODE_ID,
        _SINK_NODE_ID,
    )

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(packet)
    )
    assert result is None


def test_node_public_key_auto_learned_from_decrypted_nodeinfo() -> None:
    """NodeInfo (User) is broadcast on the regular channel-PSK path (firmware
    excludes NODEINFO_APP from PKC), so decoding one should teach the decoder
    that sender's public key for later PKI decryption - without ever calling
    learn_public_key() directly.
    """
    channel_key = base64.b64encode(
        b"\x01"
    ).decode()  # expands to the default Meshtastic key
    sink_private, sink_public = pki.generate_keypair()
    sender_private, sender_public = pki.generate_keypair()

    decoder = MqttPacketDecoder(
        channel_keys=[{"name": "LongFast", "key": channel_key}],
        pki_identities=[
            {
                "node_id": str(_SINK_NODE_ID),
                "private_key": base64.b64encode(sink_private).decode(),
            }
        ],
    )

    # -- First: a NodeInfo broadcast on the regular channel, carrying the sender's public key --
    user = mesh_pb2.User(
        id=f"!{_SENDER_NODE_ID:08x}", long_name="Tracker", public_key=sender_public
    )
    node_info_data = mesh_pb2.Data(
        portnum=portnums_pb2.PortNum.NODEINFO_APP, payload=user.SerializeToString()
    )

    prepared_key = decoder.prepare_key(base64.b64decode(channel_key))
    nonce = decoder.build_nonce(99, _SENDER_NODE_ID)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(prepared_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_node_info = (
        encryptor.update(node_info_data.SerializeToString()) + encryptor.finalize()
    )

    node_info_packet = mesh_pb2.MeshPacket()
    node_info_packet.__setattr__("from", _SENDER_NODE_ID)
    node_info_packet.to = 0xFFFFFFFF
    node_info_packet.id = 99
    node_info_packet.channel = 0
    node_info_packet.encrypted = encrypted_node_info

    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.packet.CopyFrom(node_info_packet)
    envelope.channel_id = "LongFast"
    envelope.gateway_id = "!deadbeef"

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/LongFast/#", envelope.SerializeToString()
    )
    assert result is not None
    assert result.decoded.portnum == portnums_pb2.PortNum.NODEINFO_APP

    # -- Now: a PKI packet from the same sender should decrypt without ever
    #    calling learn_public_key() explicitly --
    data = mesh_pb2.Data(portnum=portnums_pb2.PortNum.POSITION_APP, payload=b"lat/lon")
    pki_packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        sink_public,
        100,
        _SENDER_NODE_ID,
        _SINK_NODE_ID,
    )
    pki_result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(pki_packet)
    )

    assert pki_result is not None
    assert pki_result.decoded.payload == b"lat/lon"


def test_learn_public_key_ignores_wrong_length_keys() -> None:
    decoder = MqttPacketDecoder(channel_keys=[])
    decoder.learn_public_key(_SENDER_NODE_ID, b"too-short")
    assert _SENDER_NODE_ID not in decoder._node_public_keys


@settings(max_examples=100)
@given(
    plaintext_payload=_data_payload,
    packet_id=_uint32,
    from_node_id=_uint32,
)
def test_pki_decrypt_round_trip_property(
    plaintext_payload: bytes, packet_id: int, from_node_id: int
) -> None:
    """For any payload/packet_id/sender, a packet PKI-encrypted to a
    configured identity from a sender whose public key is known must decode
    back to the original Data payload through the full decoder pipeline.
    """
    sink_private, sink_public = pki.generate_keypair()
    sender_private, sender_public = pki.generate_keypair()

    decoder = _make_decoder(sink_private)
    decoder.learn_public_key(from_node_id, sender_public)

    data = mesh_pb2.Data(
        portnum=portnums_pb2.PortNum.POSITION_APP, payload=plaintext_payload
    )
    packet = _build_pki_packet(
        data.SerializeToString(),
        sender_private,
        sink_public,
        packet_id,
        from_node_id,
        _SINK_NODE_ID,
    )

    result = decoder.decode_to_mesh_packet(
        "msh/EU_868/2/e/PKI/#", _wrap_in_envelope(packet)
    )

    assert result is not None
    assert result.decoded.payload == plaintext_payload
