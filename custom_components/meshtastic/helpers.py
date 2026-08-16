# SPDX-FileCopyrightText: 2024-2025 Pascal Brogle @broglep
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import typing
from collections import defaultdict

from homeassistant.helpers import entity_platform
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_CONNECTION_TYPE,
    CONF_OPTION_FILTER_NODES,
    LOGGER,
    ConnectionType,
)

if typing.TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from typing import Any

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity import Entity
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .data import MeshtasticConfigEntry, MeshtasticData


def resolve_mqtt_filter_node_nums(
    entry: MeshtasticConfigEntry, known_node_nums: typing.Iterable[int]
) -> set[int]:
    """Return the node IDs an MQTT connection should track.

    MQTT connections have no fixed node list to opt into up front, so an
    unconfigured filter (the default) tracks every node seen. Once the user
    has picked explicit node IDs via the options flow, only those are kept.
    """
    filter_nodes = entry.options.get(CONF_OPTION_FILTER_NODES, [])
    if not filter_nodes:
        return set(known_node_nums)
    return {el["id"] for el in filter_nodes}


def build_placeholder_node_info(node_id: int, name: str) -> dict[str, Any]:
    """Synthetic node-info dict for a manually configured MQTT node that hasn't
    sent any traffic yet.

    MQTT's node database is populated exclusively from received packets, so a
    node the user has explicitly added to the filter list but that hasn't
    transmitted this session would otherwise have no device/entities at all.
    This stands in until real data (via EVENT_MESHTASTIC_API_NODE_UPDATED)
    replaces it, using only fields the device/entity setup code already reads.
    """
    return {
        "num": node_id,
        "user": {
            "id": f"!{node_id:08x}",
            "longName": name,
            "shortName": name[:4] if name else f"{node_id:08x}"[-4:],
            "hwModel": "UNSET",
        },
    }


def get_nodes(entry: MeshtasticConfigEntry) -> typing.Mapping[int, typing.Mapping[str, Any]]:
    if not entry.runtime_data.coordinator.data:
        return {}

    connection_type = entry.data.get(CONF_CONNECTION_TYPE)
    if connection_type == ConnectionType.MQTT.value:
        filter_node_nums = resolve_mqtt_filter_node_nums(entry, entry.runtime_data.coordinator.data.keys())
        return {
            node_num: node_info
            for node_num, node_info in entry.runtime_data.coordinator.data.items()
            if node_num in filter_node_nums
        }

    filter_nodes = entry.options.get(CONF_OPTION_FILTER_NODES, [])
    filter_node_nums = [el["id"] for el in filter_nodes]

    return {
        node_num: node_info
        for node_num, node_info in entry.runtime_data.coordinator.data.items()
        if node_num in filter_node_nums
    }


_remove_listeners = defaultdict(lambda: defaultdict(list))


async def setup_platform_entry(
    hass: HomeAssistant,  # noqa: ARG001 function argument: `hass`
    entry: MeshtasticConfigEntry,
    async_add_entities: AddEntitiesCallback,
    entity_factory: Callable[[typing.Mapping[int, typing.Mapping[str, Any]], MeshtasticData], Iterable[Entity]],
) -> None:
    async_add_entities(entity_factory(get_nodes(entry), entry.runtime_data))
    platform = entity_platform.async_get_current_platform()

    def on_coordinator_data_update() -> None:
        entities = entity_factory(get_nodes(entry), entry.runtime_data)
        # Dedup by unique_id, not entity_id: entity_id bakes in the gateway node's
        # live shortName (see MeshtasticNodeEntity), which can be unknown on the
        # first call and resolve later - recomputing it would then look "new" here
        # even though unique_id (stable, and what the entity registry actually
        # keys on) hasn't changed, causing HA to reject it as a duplicate unique_id
        # on every subsequent coordinator update.
        existing_unique_ids = {e.unique_id for e in platform.entities.values()}
        new_entities = [s for s in entities if s.unique_id not in existing_unique_ids]
        if new_entities:
            async_add_entities(new_entities)

    remove_listener = entry.runtime_data.coordinator.async_add_listener(on_coordinator_data_update)
    _remove_listeners[platform.domain][entry.entry_id].append(remove_listener)


async def async_unload_entry(
    hass: HomeAssistant,  # noqa: ARG001
    entry: MeshtasticConfigEntry,
) -> bool:
    platform = entity_platform.async_get_current_platform()
    for remove_listener in _remove_listeners[platform.domain].pop(entry.entry_id, []):
        remove_listener()

    return True


async def fetch_meshtastic_hardware_names(hass: HomeAssistant) -> typing.Mapping[str, str]:
    try:
        session = async_get_clientsession(hass)
        async with session.get("https://api.meshtastic.org/resource/deviceHardware", raise_for_status=True) as response:
            response_json = await response.json()
            device_hardware_names = {h["hwModelSlug"]: h["displayName"] for h in response_json}
    except Exception:  # noqa: BLE001
        LOGGER.info("Failed to fetch meshtastic hardware infos", exc_info=True)
        device_hardware_names = {}
    return device_hardware_names
