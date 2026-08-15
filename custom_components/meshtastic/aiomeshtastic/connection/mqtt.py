# SPDX-License-Identifier: MIT

"""MQTT connection for Meshtastic mesh network.

Implements ``ClientApiConnection`` over MQTT, subscribing to a Meshtastic
broker and yielding decoded ``FromRadio`` messages to the existing
``MeshInterface`` pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import AsyncIterable, Mapping, Sequence

import aiomqtt

from ..protobuf import mesh_pb2, mqtt_pb2  # noqa: TID252
from . import ClientApiConnection
from .decoder import MqttPacketDecoder
from .errors import (
    ClientApiConnectionInterruptedError,
    ClientApiNotConnectedError,
)

LOGGER = logging.getLogger(__name__)


class MqttConnection(ClientApiConnection):
    """MQTT-based connection to a Meshtastic mesh network.

    Subscribes to a Meshtastic MQTT broker, decodes ``ServiceEnvelope``
    messages via :class:`MqttPacketDecoder`, and yields ``FromRadio``
    messages through the standard ``ClientApiConnection`` interface.
    """

    def __init__(
        self,
        broker_host: str,
        broker_port: int = 1883,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = False,
        topic_pattern: str = "msh/US/2/e/#",
        channel_keys: Sequence[Mapping[str, str]] | None = None,
        region: str = "US",
        filter_node_nums: set[int] | None = None,
        static_telemetry_keys: Mapping[int, str] | None = None,
    ) -> None:
        super().__init__()
        self._broker_host = broker_host
        self._broker_port = broker_port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._topic_pattern = topic_pattern
        self._channel_keys = list(channel_keys or [])
        self._region = region

        self._decoder = MqttPacketDecoder(self._channel_keys, filter_node_nums, static_telemetry_keys)
        self._client: aiomqtt.Client | None = None
        self._connected = False
        self._gateway_node_num = self._generate_gateway_node_num()

    # ------------------------------------------------------------------
    # ClientApiConnection abstract method implementations
    # ------------------------------------------------------------------

    async def _connect(self) -> None:
        """Connect to the MQTT broker and subscribe to the topic pattern."""
        self._logger.debug(
            "Connecting to MQTT broker %s:%d", self._broker_host, self._broker_port
        )

        tls_context = None
        if self._use_tls:
            import ssl

            # ssl.create_default_context() reads system trust stores from disk and
            # is a blocking call; running it directly on the event loop trips
            # Home Assistant's blocking-call detector. Offload it to a worker
            # thread like any other blocking I/O.
            tls_context = await asyncio.get_running_loop().run_in_executor(None, ssl.create_default_context)

        # Some brokers (e.g. the public mqtt.meshtastic.org) reject connections with
        # CONNACK "identifier rejected" unless given an explicit, short client ID;
        # aiomqtt/paho otherwise auto-generate a long, hostname-suffixed one.
        self._client = aiomqtt.Client(
            hostname=self._broker_host,
            port=self._broker_port,
            username=self._username,
            password=self._password,
            tls_context=tls_context,
            identifier=f"hamesh{self._gateway_node_num:08x}",
        )
        await self._client.__aenter__()
        self._connected = True

        await self._client.subscribe(self._topic_pattern)
        self._logger.debug(
            "Subscribed to topic pattern: %s", self._topic_pattern
        )

    async def _disconnect(self) -> None:
        """Unsubscribe from topics and close the MQTT connection."""
        if self._client is not None:
            try:
                if self._connected:
                    await self._client.unsubscribe(self._topic_pattern)
            except Exception:  # noqa: BLE001
                self._logger.debug("Error unsubscribing", exc_info=True)
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                self._logger.debug("Error closing MQTT client", exc_info=True)
            finally:
                self._client = None
                self._connected = False

    @property
    def is_connected(self) -> bool:
        """Return whether the MQTT client is connected."""
        return self._connected and self._client is not None

    async def _packet_stream(self) -> AsyncIterable[mesh_pb2.FromRadio]:
        """Async generator yielding ``FromRadio`` from decoded MQTT messages.

        Receives MQTT messages, decodes them via :class:`MqttPacketDecoder`,
        wraps valid ``MeshPacket`` objects in ``FromRadio``, and yields them.
        """
        if not self.is_connected or self._client is None:
            raise ClientApiNotConnectedError

        try:
            async for message in self._client.messages:
                topic = str(message.topic)
                payload = message.payload
                if isinstance(payload, str):
                    payload = payload.encode("utf-8")
                if not payload:
                    continue

                mesh_packet = self._decoder.decode_to_mesh_packet(topic, payload)
                if mesh_packet is None:
                    continue

                # Mark packet as received via MQTT
                mesh_packet.via_mqtt = True

                from_radio = mesh_pb2.FromRadio()
                from_radio.packet.CopyFrom(mesh_packet)
                self._logger.debug(
                    "Decoded MQTT packet (id=0x%x from=0x%x to=0x%x)",
                    mesh_packet.id,
                    getattr(mesh_packet, "from"),
                    mesh_packet.to,
                )
                yield from_radio
        except aiomqtt.MqttError as exc:
            self._connected = False
            raise ClientApiConnectionInterruptedError(
                f"MQTT connection lost: {exc}"
            ) from exc

    async def _send_packet(self, packet: bytes) -> bool:
        """Construct a ``ServiceEnvelope`` and publish to the MQTT topic.

        Args:
            packet: Serialized ``ToRadio`` protobuf bytes.

        Returns:
            True if the message was published successfully.
        """
        if not self.is_connected or self._client is None:
            raise ClientApiNotConnectedError

        try:
            to_radio = mesh_pb2.ToRadio()
            to_radio.ParseFromString(packet)

            if not to_radio.HasField("packet"):
                # Non-packet messages (heartbeat, disconnect, etc.) are
                # not meaningful over MQTT — silently succeed.
                return True

            mesh_packet = to_radio.packet

            # Determine channel name for the topic
            channel_index = mesh_packet.channel
            channel_name = self._channel_name_for_index(channel_index)

            # Build the ServiceEnvelope
            envelope = mqtt_pb2.ServiceEnvelope()
            envelope.packet.CopyFrom(mesh_packet)
            envelope.channel_id = channel_name
            envelope.gateway_id = f"!{self._gateway_node_num:08x}"

            # Construct the publish topic
            topic = f"msh/{self._region}/2/e/{channel_name}/{envelope.gateway_id}"

            await self._client.publish(
                topic, payload=envelope.SerializeToString(), qos=1
            )
            self._logger.debug("Published packet to %s", topic)
            return True
        except aiomqtt.MqttError as exc:
            self._logger.warning("Failed to publish MQTT message: %s", exc)
            return False
        except Exception:
            self._logger.warning("Failed to send packet via MQTT", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # request_config override — synthesize virtual gateway node
    # ------------------------------------------------------------------

    async def request_config(self, minimal: bool = False) -> bool:  # noqa: FBT001, FBT002
        """Synthesize virtual gateway node config, waiting for delivery.

        In MQTT mode there is no physical device to query, so we fabricate a
        minimal config response. Rather than firing the synthesized messages
        and returning immediately, this uses the same listen()-based
        request/wait pattern the base ClientApiConnection.request_config()
        uses for real devices: it registers as a listener *before* sending
        anything, then waits to observe its own config_complete_id.

        This matters because MeshInterface's packet-processing loop (which
        turns these FromRadio messages into node-database entries) is a
        separately scheduled consumer of the same broadcast, not something
        this call can await directly. Returning immediately after just
        enqueueing the messages let callers see connected_node_ready()
        resolve before that loop had actually processed our own gateway
        node's info, so MeshInterface.connected_node() could return an
        incomplete/empty node. Waiting for our own listener to observe
        config_complete_id - sent last, after MyNodeInfo/NodeInfo - gives
        the processing loop's queue (registered earlier, when it started)
        the same delivery-ordering guarantee real devices already rely on.
        """
        config_id = self._CONFIG_ID_MINIMAL if minimal else 42

        async def send_synthetic_config() -> None:
            # Synthesize MyNodeInfo
            my_info = mesh_pb2.MyNodeInfo()
            my_info.my_node_num = self._gateway_node_num

            from_radio_info = mesh_pb2.FromRadio()
            from_radio_info.my_info.CopyFrom(my_info)
            await self._notify_packet_stream_listeners(from_radio_info, sequential=True)

            # Synthesize a NodeInfo for the virtual gateway
            node_info = mesh_pb2.NodeInfo()
            node_info.num = self._gateway_node_num
            node_info.user.id = f"!{self._gateway_node_num:08x}"
            node_info.user.long_name = f"MQTT Gateway ({self._broker_host})"
            node_info.user.short_name = "MQTT"
            node_info.user.hw_model = mesh_pb2.HardwareModel.PORTDUINO

            from_radio_node = mesh_pb2.FromRadio()
            from_radio_node.node_info.CopyFrom(node_info)
            await self._notify_packet_stream_listeners(from_radio_node, sequential=True)

            # Signal config complete
            from_radio_complete = mesh_pb2.FromRadio()
            from_radio_complete.config_complete_id = config_id
            await self._notify_packet_stream_listeners(from_radio_complete, sequential=True)

        async for packet in self.listen(on_start=send_synthetic_config()):
            if packet.HasField("config_complete_id") and packet.config_complete_id == config_id:
                return True

        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _generate_gateway_node_num(self) -> int:
        """Generate a deterministic node number from broker parameters.

        Uses a hash of the broker host and port to produce a stable
        uint32 node number for the virtual gateway.
        """
        key = f"{self._broker_host}:{self._broker_port}"
        digest = hashlib.sha256(key.encode()).digest()
        # Use first 4 bytes as a uint32, mask to ensure valid node num
        node_num = int.from_bytes(digest[:4], "big") & 0xFFFFFFFF
        # Avoid 0 and broadcast address
        if node_num == 0 or node_num == 0xFFFFFFFF:
            node_num = 0x004D5101  # fallback
        return node_num

    def _channel_name_for_index(self, channel_index: int) -> str:
        """Map a channel index to a channel name.

        Falls back to the first configured channel name, or ``"LongFast"``
        as the default. channel_keys may list the same name more than once
        (different keys for the same name), so duplicates are collapsed
        before indexing.
        """
        # Channel index 0 is typically the primary channel
        names = list(dict.fromkeys(entry.get("name", "") for entry in self._channel_keys))
        if names:
            if channel_index < len(names):
                return names[channel_index]
            return names[0]
        return "LongFast"
