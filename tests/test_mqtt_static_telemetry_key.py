# Feature: meshtastic-static-telemetry-key, per-device static-key decrypt layer
# for Position/Telemetry
"""Tests for MqttPacketDecoder's static telemetry key: an optional extra AES-CTR
layer applied to Position/Telemetry Data.payload bytes, matching the firmware
fork's channel-7 static telemetry key (StaticTelemetryKey.h). Unlike channel-PSK
decryption this is a second pass applied *after* the normal channel decrypt
already recovered a plausible Data message, and the key used is looked up by
the packet's sender node ID - different nodes may be configured with
different static telemetry keys (or none at all).
"""

from __future__ import annotations

import base64

from aiomeshtastic.connection.decoder import MqttPacketDecoder
from aiomeshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hypothesis import given, settings
from hypothesis import strategies as st

_uint32 = st.integers(min_value=0, max_value=2**32 - 1)
_CHANNEL_KEY_B64 = base64.b64encode(b"\x01").decode()  # expands to the default Meshtastic key
_STATIC_KEY = b"\x11" * 32
_STATIC_KEY_B64 = base64.b64encode(_STATIC_KEY).decode()
_CHANNEL_NAME = "LongFast"
_NODE_ID = 0x11223344


def _make_decoder(static_telemetry_keys: dict[int, str] | None = None) -> MqttPacketDecoder:
    if static_telemetry_keys is None:
        static_telemetry_keys = {_NODE_ID: _STATIC_KEY_B64}
    return MqttPacketDecoder(
        channel_keys=[{"name": _CHANNEL_NAME, "key": _CHANNEL_KEY_B64}],
        static_telemetry_keys=static_telemetry_keys,
    )


def _channel_encrypt(decoder: MqttPacketDecoder, plaintext: bytes, packet_id: int, from_node_id: int) -> bytes:
    key = decoder.prepare_key(base64.b64decode(_CHANNEL_KEY_B64))
    nonce = decoder.build_nonce(packet_id, from_node_id)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _static_key_encrypt(key: bytes, decoder: MqttPacketDecoder, plaintext: bytes, packet_id: int, from_node_id: int) -> bytes:
    nonce = decoder.build_nonce(packet_id, from_node_id)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _build_envelope(
    decoder: MqttPacketDecoder,
    data_payload: bytes,
    portnum: int,
    packet_id: int,
    from_node_id: int,
) -> bytes:
    """Build a ServiceEnvelope wrapping a channel-PSK encrypted Data message, the
    way it would actually arrive over MQTT."""
    data = mesh_pb2.Data(portnum=portnum, payload=data_payload)
    encrypted = _channel_encrypt(decoder, data.SerializeToString(), packet_id, from_node_id)

    packet = mesh_pb2.MeshPacket()
    packet.__setattr__("from", from_node_id)
    packet.id = packet_id
    packet.channel = 0
    packet.encrypted = encrypted

    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.packet.CopyFrom(packet)
    envelope.channel_id = _CHANNEL_NAME
    envelope.gateway_id = "!deadbeef"
    return envelope.SerializeToString()


_TOPIC = f"msh/EU_868/2/e/{_CHANNEL_NAME}/#"


def test_static_key_decrypts_double_encrypted_position() -> None:
    decoder = _make_decoder()
    position = mesh_pb2.Position(latitude_i=407128000, longitude_i=-740060000)
    plaintext = position.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, 42, _NODE_ID)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.POSITION_APP, 42, _NODE_ID)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.portnum == portnums_pb2.PortNum.POSITION_APP
    assert result.decoded.payload == plaintext

    decoded_position = mesh_pb2.Position()
    decoded_position.ParseFromString(result.decoded.payload)
    assert decoded_position.latitude_i == 407128000
    assert decoded_position.longitude_i == -740060000


def test_static_key_decrypts_double_encrypted_telemetry() -> None:
    decoder = _make_decoder()
    telemetry = telemetry_pb2.Telemetry(time=1700000000, device_metrics=telemetry_pb2.DeviceMetrics(battery_level=80))
    plaintext = telemetry.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, 43, _NODE_ID)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.TELEMETRY_APP, 43, _NODE_ID)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == plaintext


def test_plaintext_position_from_stock_node_passes_through_unchanged() -> None:
    """A stock (unmodified) sender's plaintext Position must still work when
    the receiver has a static key configured for that sender - the decoder
    should recognize it's already valid and not touch it."""
    decoder = _make_decoder()
    position = mesh_pb2.Position(latitude_i=1, longitude_i=2)
    plaintext = position.SerializeToString()

    envelope = _build_envelope(decoder, plaintext, portnums_pb2.PortNum.POSITION_APP, 1, _NODE_ID)
    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == plaintext


def test_no_static_key_configured_leaves_ciphertext_untouched() -> None:
    decoder = _make_decoder(static_telemetry_keys={})
    position = mesh_pb2.Position(latitude_i=407128000, longitude_i=-740060000)
    plaintext = position.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, 42, _NODE_ID)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.POSITION_APP, 42, _NODE_ID)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload != plaintext
    assert result.decoded.payload == ciphertext


def test_no_key_configured_for_this_sender_leaves_ciphertext_untouched() -> None:
    """A key configured for one node must not be applied to another node's
    packets, even though both arrive over the same channel."""
    other_node_id = 0xAABBCCDD
    decoder = _make_decoder(static_telemetry_keys={_NODE_ID: _STATIC_KEY_B64})
    position = mesh_pb2.Position(latitude_i=407128000, longitude_i=-740060000)
    plaintext = position.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, 42, other_node_id)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.POSITION_APP, 42, other_node_id)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == ciphertext


def test_different_nodes_can_use_different_keys() -> None:
    node_a, node_b = _NODE_ID, 0xAABBCCDD
    key_a, key_b = _STATIC_KEY, b"\x22" * 32
    decoder = _make_decoder(
        static_telemetry_keys={node_a: base64.b64encode(key_a).decode(), node_b: base64.b64encode(key_b).decode()}
    )

    position_a = mesh_pb2.Position(latitude_i=1, longitude_i=2, altitude=3, time=1700000000, sats_in_view=4)
    plaintext_a = position_a.SerializeToString()
    ciphertext_a = _static_key_encrypt(key_a, decoder, plaintext_a, 1, node_a)
    envelope_a = _build_envelope(decoder, ciphertext_a, portnums_pb2.PortNum.POSITION_APP, 1, node_a)
    result_a = decoder.decode_to_mesh_packet(_TOPIC, envelope_a)
    assert result_a is not None
    assert result_a.decoded.payload == plaintext_a

    position_b = mesh_pb2.Position(latitude_i=5, longitude_i=6, altitude=7, time=1700000001, sats_in_view=8)
    plaintext_b = position_b.SerializeToString()
    ciphertext_b = _static_key_encrypt(key_b, decoder, plaintext_b, 2, node_b)
    envelope_b = _build_envelope(decoder, ciphertext_b, portnums_pb2.PortNum.POSITION_APP, 2, node_b)
    result_b = decoder.decode_to_mesh_packet(_TOPIC, envelope_b)
    assert result_b is not None
    assert result_b.decoded.payload == plaintext_b


def test_wrong_static_key_leaves_ciphertext_undecrypted() -> None:
    decoder = _make_decoder(static_telemetry_keys={_NODE_ID: base64.b64encode(b"\x22" * 32).decode()})
    position = mesh_pb2.Position(
        latitude_i=407128000, longitude_i=-740060000, altitude=42, time=1700000000, sats_in_view=7
    )
    plaintext = position.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, 42, _NODE_ID)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.POSITION_APP, 42, _NODE_ID)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload != plaintext


def test_static_key_does_not_apply_to_other_portnums() -> None:
    """Only POSITION_APP/TELEMETRY_APP get the extra layer - text messages etc
    must never be run through this at all, matching the firmware's gating."""
    decoder = _make_decoder()
    text_bytes = b"hello mesh"

    envelope = _build_envelope(decoder, text_bytes, portnums_pb2.PortNum.TEXT_MESSAGE_APP, 1, _NODE_ID)
    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == text_bytes


def test_invalid_base64_static_key_is_ignored_not_fatal() -> None:
    decoder = _make_decoder(static_telemetry_keys={_NODE_ID: "not valid base64!!!"})
    position = mesh_pb2.Position(latitude_i=1, longitude_i=2)
    plaintext = position.SerializeToString()

    envelope = _build_envelope(decoder, plaintext, portnums_pb2.PortNum.POSITION_APP, 1, _NODE_ID)
    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == plaintext


@settings(max_examples=200)
@given(
    packet_id=_uint32,
    from_node_id=_uint32,
    latitude_i=st.integers(min_value=-(2**31), max_value=2**31 - 1),
    longitude_i=st.integers(min_value=-(2**31), max_value=2**31 - 1),
    altitude=st.integers(min_value=-1000, max_value=10000),
    sats_in_view=st.integers(min_value=0, max_value=30),
)
def test_static_key_round_trip_property(
    packet_id: int, from_node_id: int, latitude_i: int, longitude_i: int, altitude: int, sats_in_view: int
) -> None:
    """A real Position packet always carries several fields at once (at minimum
    lat+lon together, typically altitude/time/sats too - never just one field
    in isolation), which is what makes _is_plausible_static_payload's
    >=2-recognized-fields check a reliable discriminator (see its docstring
    for the measured false-positive rate). This uses a representative
    multi-field message rather than an artificially minimal one for that
    reason - the decryption itself (the thing actually under test here) works
    identically regardless of message size.
    """
    decoder = _make_decoder(static_telemetry_keys={from_node_id: _STATIC_KEY_B64})
    position = mesh_pb2.Position(
        latitude_i=latitude_i, longitude_i=longitude_i, altitude=altitude, time=1700000000, sats_in_view=sats_in_view
    )
    plaintext = position.SerializeToString()

    ciphertext = _static_key_encrypt(_STATIC_KEY, decoder, plaintext, packet_id, from_node_id)
    envelope = _build_envelope(decoder, ciphertext, portnums_pb2.PortNum.POSITION_APP, packet_id, from_node_id)

    result = decoder.decode_to_mesh_packet(_TOPIC, envelope)

    assert result is not None
    assert result.decoded.payload == plaintext
