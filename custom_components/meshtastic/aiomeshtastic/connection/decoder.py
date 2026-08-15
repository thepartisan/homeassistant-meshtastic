# SPDX-License-Identifier: MIT

"""MQTT packet decoder for Meshtastic ServiceEnvelope messages.

Handles ServiceEnvelope parsing, AES-CTR decryption, channel extraction
from MQTT topics, and JSON message handling.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2  # noqa: TID252

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

LOGGER = logging.getLogger(__name__)

# Default Meshtastic encryption key (base64: "1PG7OiApB1nwvP+rz05pAQ==")
_DEFAULT_KEY = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")

# Type indicators used in MQTT topic paths
_TYPE_INDICATORS = {"e", "c", "json"}

# A channel *name* is just a user-chosen label, not a unique namespace - anyone
# can configure a channel called "LongFast" with their own private key. Valid
# PortNum values, used to sanity-check which of several candidate keys for the
# same name actually decrypted a given packet (see decrypt_payload()).
_VALID_PORT_NUMS = frozenset(portnums_pb2.PortNum.values())

# Portnums the static telemetry key (see MqttPacketDecoder.__init__) applies to -
# must match the firmware's StaticTelemetryKey.h exactly.
_STATIC_TELEMETRY_KEY_PORT_NUMS = frozenset(
    {portnums_pb2.PortNum.POSITION_APP, portnums_pb2.PortNum.TELEMETRY_APP}
)

# Minimum number of schema-recognized fields a decrypt candidate must contain to
# be accepted as a genuine Position/Telemetry rather than random-bytes-that-
# happen-to-parse - see MqttPacketDecoder._is_plausible_static_payload().
_MIN_PLAUSIBLE_FIELDS = 2


class MqttPacketDecoder:
    """Decodes Meshtastic MQTT messages into MeshPacket protobuf objects.

    Supports ServiceEnvelope parsing with fallback to direct MeshPacket,
    AES-CTR decryption of encrypted payloads, and JSON message handling.
    """

    def __init__(
        self,
        channel_keys: Sequence[Mapping[str, str]],
        allowed_from_node_ids: set[int] | None = None,
        static_telemetry_key: str | None = None,
    ) -> None:
        """Initialize the decoder with channel encryption keys.

        Args:
            channel_keys: A list of {"name": channel_name, "key": base64_key} entries.
                A channel name is just a label, not a unique identifier - different
                private channels can share the same name with different keys - so
                the same name may appear more than once here, each with a different
                key. All of a name's keys are tried when decrypting (see
                decrypt_payload()).
            allowed_from_node_ids: If given, packets whose sender ("from") is not in
                this set are dropped immediately, before decryption is attempted. The
                sender ID is a cleartext MeshPacket field, so this filter is cheap and
                works even for packets this decoder holds no channel key for.
            static_telemetry_key: A base64-encoded AES key matching the firmware's
                channel-7 static telemetry key (see StaticTelemetryKey.h in the
                firmware fork). Position/Telemetry payloads are AES-CTR encrypted
                with this key as an extra layer *inside* the already channel-PSK
                decrypted Data.payload - see _maybe_decrypt_static_telemetry_payload().
        """
        self._channel_keys: dict[str, list[bytes]] = {}
        for entry in channel_keys:
            channel = entry.get("name", "")
            key_b64 = entry.get("key", "")
            try:
                raw = base64.b64decode(key_b64)
                self._channel_keys.setdefault(channel, []).append(self.prepare_key(raw))
            except Exception:
                LOGGER.warning("Invalid base64 key for channel %s, skipping", channel)

        self._allowed_from_node_ids = allowed_from_node_ids

        self._static_telemetry_key: bytes | None = None
        if static_telemetry_key:
            try:
                self._static_telemetry_key = self.prepare_key(base64.b64decode(static_telemetry_key))
            except Exception:
                LOGGER.warning("Invalid base64 static telemetry key, ignoring")

    def prepare_key(self, raw_key: bytes) -> bytes:
        """Prepare an AES key with padding/expansion rules.

        Rules:
            - 1 byte with value 0x01 → expand to default Meshtastic key
            - < 16 bytes → pad with 0x00 to 16 bytes
            - 16 bytes → use as-is (AES-128)
            - 17–31 bytes → pad with 0x00 to 32 bytes
            - 32 bytes → use as-is (AES-256)
            - > 32 bytes → truncate to 32 bytes

        Args:
            raw_key: The raw key bytes (decoded from base64).

        Returns:
            A 16-byte or 32-byte AES key.
        """
        if len(raw_key) == 1 and raw_key[0] == 0x01:
            return _DEFAULT_KEY

        length = len(raw_key)
        if length <= 16:
            return raw_key.ljust(16, b"\x00")
        if length <= 32:
            return raw_key.ljust(32, b"\x00")
        return raw_key[:32]

    def build_nonce(self, packet_id: int, from_node_id: int) -> bytes:
        """Build a 16-byte AES-CTR nonce from packet ID and sender node ID.

        The nonce is constructed as:
            packet_id (8 bytes, little-endian) + from_node_id (8 bytes, little-endian)

        Args:
            packet_id: The packet identifier.
            from_node_id: The sender's node identifier.

        Returns:
            A 16-byte nonce.
        """
        return packet_id.to_bytes(8, "little") + from_node_id.to_bytes(8, "little")

    def decrypt_payload(
        self,
        encrypted: bytes,
        channel: str,
        packet_id: int,
        from_node_id: int,
    ) -> bytes | None:
        """Decrypt an encrypted MeshPacket payload using AES-CTR.

        AES-CTR has no built-in authentication, so decrypting with the wrong
        key doesn't raise - it just produces garbage bytes. Since a channel
        name can have multiple registered keys (see __init__), every key for
        this name is tried in order, and the first one whose output actually
        parses as a valid Data protobuf with a recognized PortNum is used.
        That's a heuristic, not a cryptographic guarantee, but garbage bytes
        very rarely happen to form valid protobuf wire format by chance.

        Args:
            encrypted: The encrypted payload bytes.
            channel: The channel name used to look up the decryption key(s).
            packet_id: The packet ID (used for nonce construction).
            from_node_id: The sender node ID (used for nonce construction).

        Returns:
            The decrypted payload bytes, or None if no configured key for
            this channel produced a plausible result.
        """
        keys = self._channel_keys.get(channel)
        if not keys:
            LOGGER.debug("No key configured for channel '%s', skipping decryption", channel)
            return None

        nonce = self.build_nonce(packet_id, from_node_id)
        for key in keys:
            try:
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
                decryptor = cipher.decryptor()
                candidate = decryptor.update(encrypted) + decryptor.finalize()
            except Exception:
                LOGGER.debug("Decryption attempt failed for channel '%s'", channel, exc_info=True)
                continue

            if self._is_plausible_data(candidate):
                return candidate

        LOGGER.debug(
            "None of the %d configured key(s) for channel '%s' decrypted to a valid payload",
            len(keys),
            channel,
        )
        return None

    def _is_plausible_data(self, candidate: bytes) -> bool:
        """Check whether decrypted bytes look like a real Data protobuf.

        Used to pick the right key among several candidates for a shared
        channel name - see decrypt_payload().
        """
        try:
            data = mesh_pb2.Data()
            data.ParseFromString(candidate)
        except Exception:
            return False
        else:
            return data.portnum in _VALID_PORT_NUMS

    def _maybe_decrypt_static_telemetry_payload(self, packet: mesh_pb2.MeshPacket) -> None:
        """Try the static telemetry key on a Position/Telemetry Data.payload.

        This mirrors the firmware's StaticTelemetryKey.h: Position/Telemetry
        payloads may carry an *extra* AES-CTR encryption layer (applied by the
        sender before the normal channel-PSK layer, which this decoder has
        already peeled off by the time this runs). If the payload already
        parses as the expected message type, it's left untouched (handles
        stock senders, or the static key not being configured) - only on a
        parse failure is a decrypt attempt made, and only the decrypted result
        is kept if *that* parses.
        """
        if self._static_telemetry_key is None:
            return
        portnum = packet.decoded.portnum
        if portnum not in _STATIC_TELEMETRY_KEY_PORT_NUMS:
            return
        if self._is_plausible_static_payload(portnum, packet.decoded.payload):
            return

        from_node_id = getattr(packet, "from")
        nonce = self.build_nonce(packet.id, from_node_id)
        try:
            cipher = Cipher(algorithms.AES(self._static_telemetry_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            candidate = decryptor.update(packet.decoded.payload) + decryptor.finalize()
        except Exception:
            LOGGER.debug("Static telemetry key decryption attempt failed", exc_info=True)
            return

        if self._is_plausible_static_payload(portnum, candidate):
            packet.decoded.payload = candidate

    def _is_plausible_static_payload(self, portnum: int, payload: bytes) -> bool:
        """Check whether bytes are a genuine, canonically-encoded message of the
        type expected for portnum.

        Used to decide whether a Position/Telemetry payload is already
        plaintext or needs a static-key decrypt attempt - see
        _maybe_decrypt_static_telemetry_payload(). Position/Telemetry are almost
        entirely optional scalar fields, so unlike _is_plausible_data() (which
        additionally checks the parsed PortNum against a bounded enum),
        MergeFromString() succeeding alone isn't a strong enough signal here -
        protobuf silently accepts *any* well-formed tag/wire-type/length
        sequence as "unknown fields" rather than rejecting it, and - by design,
        for forward compatibility - faithfully reproduces those unknown fields
        byte-for-byte on re-serialization. So neither "it parsed" nor "it
        round-trips" alone proves anything. Requiring *both* that round-trip
        AND at least _MIN_PLAUSIBLE_FIELDS real (schema-recognized, not
        unknown-field) fields is empirically enough to make random ciphertext
        essentially never pass (measured 0/20000 false positives on
        realistically-sized encrypted Position messages; a single recognized
        field alone still occasionally collides by chance) while real
        Position/Telemetry packets - which always carry several fields at
        once - comfortably clear the bar.
        """
        try:
            if portnum == portnums_pb2.PortNum.POSITION_APP:
                candidate = mesh_pb2.Position()
            elif portnum == portnums_pb2.PortNum.TELEMETRY_APP:
                candidate = telemetry_pb2.Telemetry()
            else:
                return False
            candidate.MergeFromString(payload)
        except Exception:
            return False
        else:
            return len(candidate.ListFields()) >= _MIN_PLAUSIBLE_FIELDS and candidate.SerializeToString() == payload

    def extract_channel_from_topic(self, topic: str) -> str:
        """Extract the channel name from an MQTT topic string.

        Locates the protocol version ``2`` followed by a type indicator
        (``e``, ``c``, or ``json``) and returns the next segment as the
        channel name.

        Supports standard format: msh/{region}/2/e/{channel}
        Extended format: msh/{region}/{area}/{network}/2/e/{channel}
        JSON format: msh/{region}/2/json/{channel}

        Args:
            topic: The MQTT topic string.

        Returns:
            The extracted channel name, or "unknown" if not found.
        """
        parts = topic.split("/")
        for i, part in enumerate(parts):
            if (
                part in _TYPE_INDICATORS
                and i >= 1
                and parts[i - 1] == "2"
                and i + 1 < len(parts)
            ):
                return parts[i + 1]
        return "unknown"

    def decode_to_mesh_packet(
        self, topic: str, payload: bytes
    ) -> mesh_pb2.MeshPacket | None:
        """Decode an MQTT message into a MeshPacket.

        Parsing strategy:
            1. Try parsing as ServiceEnvelope, extract MeshPacket
            2. Fall back to parsing directly as MeshPacket
            3. Handle JSON-format topics
            4. Decrypt encrypted payloads if a channel key is available

        Args:
            topic: The MQTT topic the message was received on.
            payload: The raw message payload bytes.

        Returns:
            A decoded MeshPacket, or None if parsing/decryption fails.
        """
        if not payload:
            return None

        channel = self.extract_channel_from_topic(topic)

        # Check if this is a JSON-format topic
        if "/json/" in topic:
            return self._handle_json_message(payload, channel)

        # Try ServiceEnvelope first
        mesh_packet = self._try_parse_service_envelope(payload)

        # Fall back to direct MeshPacket parsing
        if mesh_packet is None:
            mesh_packet = self._try_parse_mesh_packet(payload)

        if mesh_packet is None:
            LOGGER.debug("Failed to parse payload from topic '%s'", topic)
            return None

        # "from" is a cleartext MeshPacket field even when the payload is encrypted,
        # so unwanted senders can be dropped before spending a decrypt attempt on them.
        if self._allowed_from_node_ids is not None and getattr(mesh_packet, "from") not in self._allowed_from_node_ids:
            return None

        # If the packet has an encrypted payload, attempt decryption
        if mesh_packet.HasField("encrypted") and mesh_packet.encrypted:
            decoded_packet = self._decrypt_mesh_packet(mesh_packet, channel)
        else:
            decoded_packet = mesh_packet

        if decoded_packet is not None:
            self._maybe_decrypt_static_telemetry_payload(decoded_packet)

        return decoded_packet

    def _try_parse_service_envelope(
        self, payload: bytes
    ) -> mesh_pb2.MeshPacket | None:
        """Try to parse payload as a ServiceEnvelope and extract MeshPacket."""
        try:
            envelope = mqtt_pb2.ServiceEnvelope()
            envelope.ParseFromString(payload)
            if envelope.HasField("packet"):
                return envelope.packet
        except Exception:
            LOGGER.debug("ServiceEnvelope parsing failed", exc_info=True)
        return None

    def _try_parse_mesh_packet(
        self, payload: bytes
    ) -> mesh_pb2.MeshPacket | None:
        """Try to parse payload directly as a MeshPacket."""
        try:
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(payload)
            # Verify we got something meaningful by checking for a non-zero id or from
            if packet.id != 0 or getattr(packet, "from") != 0:
                return packet
        except Exception:
            LOGGER.debug("Direct MeshPacket parsing failed", exc_info=True)
        return None

    def _handle_json_message(
        self, payload: bytes, channel: str
    ) -> mesh_pb2.MeshPacket | None:
        """Handle a JSON-format MQTT message.

        Extracts type, from, to, and payload fields from the JSON and
        constructs a MeshPacket with a decoded Data payload.

        Args:
            payload: The raw JSON payload bytes.
            channel: The channel name extracted from the topic.

        Returns:
            A MeshPacket with decoded data, or None on failure.
        """
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            LOGGER.debug("Invalid JSON payload")
            return None

        if not isinstance(data, dict):
            LOGGER.debug("JSON payload is not an object")
            return None

        try:
            packet = mesh_pb2.MeshPacket()

            if "from" in data:
                packet.__setattr__("from", int(data["from"]))
            if "to" in data:
                packet.to = int(data["to"])
            if "id" in data:
                packet.id = int(data["id"])
            if "channel" in data:
                packet.channel = int(data["channel"])

            # Build decoded Data from the JSON payload field
            if "type" in data or "payload" in data:
                decoded = packet.decoded
                if "type" in data:
                    # Try to map the type string to a PortNum value
                    type_str = str(data["type"]).upper()
                    try:
                        decoded.portnum = portnums_pb2.PortNum.Value(type_str)
                    except ValueError:
                        # If it's a numeric value, use it directly
                        try:
                            decoded.portnum = int(data["type"])
                        except (ValueError, TypeError):
                            pass
                if "payload" in data:
                    payload_val = data["payload"]
                    if isinstance(payload_val, str):
                        decoded.payload = payload_val.encode("utf-8")
                    elif isinstance(payload_val, dict):
                        decoded.payload = json.dumps(payload_val).encode("utf-8")
                    elif isinstance(payload_val, bytes):
                        decoded.payload = payload_val

            return packet
        except Exception:
            LOGGER.debug("Failed to construct MeshPacket from JSON", exc_info=True)
            return None

    def _decrypt_mesh_packet(
        self, packet: mesh_pb2.MeshPacket, channel: str
    ) -> mesh_pb2.MeshPacket | None:
        """Attempt to decrypt an encrypted MeshPacket.

        Args:
            packet: The MeshPacket with encrypted payload.
            channel: The channel name for key lookup.

        Returns:
            The MeshPacket with decrypted decoded data, or None on failure.
        """
        from_node_id = getattr(packet, "from")
        decrypted = self.decrypt_payload(
            packet.encrypted, channel, packet.id, from_node_id
        )
        if decrypted is None:
            return None

        try:
            data = mesh_pb2.Data()
            data.ParseFromString(decrypted)
            packet.decoded.CopyFrom(data)
            # Clear the encrypted field since we've decoded it
            packet.ClearField("encrypted")
            return packet
        except Exception:
            LOGGER.debug("Failed to parse decrypted payload as Data protobuf", exc_info=True)
            return None
