# Feature: meshtastic-mqtt-integration, placeholder devices for silent MQTT nodes
"""Tests for the placeholder-node logic that gives manually-added-but-not-yet-seen
MQTT nodes a device/entities immediately, instead of only after their first
packet arrives. MQTT's node database is built purely from received traffic, so
without this a node the user explicitly added to the filter list stays
completely invisible in HA until it actually transmits.

helpers.py and coordinator.py can't be imported directly in this lightweight
test environment (they pull in homeassistant.* at import time - see
test_mqtt_config_flow.py for the same constraint), so the logic under test is
replicated here verbatim.
"""

from __future__ import annotations

from typing import Any


def build_placeholder_node_info(node_id: int, name: str) -> dict[str, Any]:
    """Replicates helpers.build_placeholder_node_info()."""
    return {
        "num": node_id,
        "user": {
            "id": f"!{node_id:08x}",
            "longName": name,
            "shortName": name[:4] if name else f"{node_id:08x}"[-4:],
            "hwModel": "UNSET",
        },
    }


def seed_placeholders(
    node_infos: dict[int, dict[str, Any]], mqtt_filter_node_nums: set[int], filter_nodes: list[dict[str, Any]]
) -> dict[int, dict[str, Any]]:
    """Replicates the MQTT branch of coordinator._async_update_data()."""
    result = {
        node_num: node_info for node_num, node_info in node_infos.items() if node_num in mqtt_filter_node_nums
    }
    filter_node_names = {el["id"]: el.get("name") for el in filter_nodes}
    for node_num in mqtt_filter_node_nums:
        if node_num not in result:
            name = filter_node_names.get(node_num) or f"Unknown (id: {node_num})"
            result[node_num] = build_placeholder_node_info(node_num, name)
    return result


def test_placeholder_has_the_fields_device_and_entity_setup_read_directly():
    placeholder = build_placeholder_node_info(0x11223344, "Tracker")
    assert placeholder["num"] == 0x11223344
    assert placeholder["user"]["longName"] == "Tracker"
    assert placeholder["user"]["id"] == "!11223344"
    assert placeholder["user"]["hwModel"] == "UNSET"
    assert "macaddr" not in placeholder["user"]


def test_placeholder_falls_back_to_a_short_name_when_no_name_given():
    placeholder = build_placeholder_node_info(0x11223344, "")
    assert placeholder["user"]["shortName"]


def test_unseen_filtered_node_gets_a_placeholder():
    result = seed_placeholders(
        node_infos={},
        mqtt_filter_node_nums={0x11223344},
        filter_nodes=[{"id": 0x11223344, "name": "Tracker"}],
    )
    assert 0x11223344 in result
    assert result[0x11223344]["user"]["longName"] == "Tracker"


def test_already_seen_node_keeps_its_real_data_not_a_placeholder():
    real_node_info = {"num": 0x11223344, "user": {"id": "!11223344", "longName": "Tracker", "hwModel": "TBEAM"}}
    result = seed_placeholders(
        node_infos={0x11223344: real_node_info},
        mqtt_filter_node_nums={0x11223344},
        filter_nodes=[{"id": 0x11223344, "name": "Tracker"}],
    )
    assert result[0x11223344] is real_node_info


def test_node_not_in_the_filter_list_gets_no_placeholder():
    result = seed_placeholders(node_infos={}, mqtt_filter_node_nums=set(), filter_nodes=[])
    assert result == {}


def test_placeholder_name_falls_back_to_unknown_when_filter_entry_has_no_name():
    result = seed_placeholders(
        node_infos={},
        mqtt_filter_node_nums={99},
        filter_nodes=[{"id": 99}],
    )
    assert result[99]["user"]["longName"] == "Unknown (id: 99)"
