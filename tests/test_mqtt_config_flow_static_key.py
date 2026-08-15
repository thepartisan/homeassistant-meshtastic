# Feature: meshtastic-static-telemetry-key, per-device static telemetry key field
# in the MQTT options flow
"""Tests for the per-device static-telemetry-key logic used by
OptionsFlowHandler._async_step_mqtt_options() in config_flow.py.

config_flow.py can't be imported directly in this lightweight test
environment (it pulls in homeassistant.components.* at import time - see
test_mqtt_config_flow.py for the same constraint), so the branch under test
is replicated here verbatim, matching the real implementation's use of a
per-node id->key mapping (CONF_OPTION_FILTER_NODE_STATIC_KEY, stored inside
each CONF_OPTION_FILTER_NODES entry) instead of one connection-wide key.
"""

from __future__ import annotations

import base64

CONF_OPTION_FILTER_NODES = "nodes"
CONF_OPTION_FILTER_NODE_STATIC_KEY = "static_key"


def _parse_manual_node_id(value: str) -> int:
    value = value.strip()
    if value.startswith("!"):
        return int(value[1:], 16)
    try:
        return int(value)
    except ValueError:
        return int(value, 16)


def _run_mqtt_options_step(
    current_filter_nodes: list[dict], user_input: dict[str, str]
) -> tuple[dict[str, str], list[dict] | None]:
    """Replicates the body of _async_step_mqtt_options() for a single submission.

    Returns (errors, new_filter_nodes). new_filter_nodes is None if errors
    prevented completion (mirrors the real method re-showing the form).
    """
    errors: dict[str, str] = {}

    node_options = {str(el["id"]): el.get("name") or f"Unknown (id: {el['id']})" for el in current_filter_nodes}
    node_static_keys = {el["id"]: el.get(CONF_OPTION_FILTER_NODE_STATIC_KEY, "") for el in current_filter_nodes}

    kept_ids = [int(node_id) for node_id in user_input.get(CONF_OPTION_FILTER_NODES, [])]

    manual_node_id = user_input.get("manual_node_id", "").strip()
    manual_node_name = user_input.get("manual_node_name", "").strip()
    manual_static_key = user_input.get("manual_static_key", "").strip()
    if manual_node_id:
        try:
            parsed_id = _parse_manual_node_id(manual_node_id)
        except ValueError:
            errors["manual_node_id"] = "invalid_node_id"
        else:
            if manual_static_key:
                try:
                    base64.b64decode(manual_static_key)
                except Exception:
                    errors["manual_static_key"] = "invalid_static_telemetry_key"

            if not errors:
                if parsed_id not in kept_ids:
                    kept_ids.append(parsed_id)
                node_options[str(parsed_id)] = manual_node_name or node_options.get(
                    str(parsed_id), f"Unknown (id: {parsed_id})"
                )
                if manual_static_key:
                    node_static_keys[parsed_id] = manual_static_key

    if errors:
        return errors, None

    new_filter_nodes = []
    for node_id in kept_ids:
        node_entry = {"id": node_id, "name": node_options.get(str(node_id), f"Unknown (id: {node_id})")}
        static_key = node_static_keys.get(node_id, "")
        if static_key:
            node_entry[CONF_OPTION_FILTER_NODE_STATIC_KEY] = static_key
        new_filter_nodes.append(node_entry)

    return errors, new_filter_nodes


def test_adding_a_device_without_a_key_has_no_static_key_field():
    errors, new_filter_nodes = _run_mqtt_options_step(
        [], {CONF_OPTION_FILTER_NODES: [], "manual_node_id": "!11223344", "manual_node_name": "Tracker"}
    )
    assert errors == {}
    assert new_filter_nodes == [{"id": 0x11223344, "name": "Tracker"}]


def test_adding_a_device_with_a_valid_key_stores_it_on_that_device_only():
    key_b64 = base64.b64encode(b"\x11" * 32).decode()
    errors, new_filter_nodes = _run_mqtt_options_step(
        [{"id": 42, "name": "Other"}],
        {
            CONF_OPTION_FILTER_NODES: ["42"],
            "manual_node_id": "!11223344",
            "manual_node_name": "Tracker",
            "manual_static_key": key_b64,
        },
    )
    assert errors == {}
    assert new_filter_nodes == [
        {"id": 42, "name": "Other"},
        {"id": 0x11223344, "name": "Tracker", CONF_OPTION_FILTER_NODE_STATIC_KEY: key_b64},
    ]


def test_invalid_base64_key_is_rejected_and_nothing_is_saved():
    errors, new_filter_nodes = _run_mqtt_options_step(
        [],
        {
            CONF_OPTION_FILTER_NODES: [],
            "manual_node_id": "!11223344",
            "manual_static_key": "not valid base64!!!",
        },
    )
    assert errors.get("manual_static_key") == "invalid_static_telemetry_key"
    assert new_filter_nodes is None


def test_existing_device_key_is_preserved_when_resubmitted_without_changes():
    key_b64 = base64.b64encode(b"\x22" * 32).decode()
    current = [{"id": 42, "name": "Tracker", CONF_OPTION_FILTER_NODE_STATIC_KEY: key_b64}]
    errors, new_filter_nodes = _run_mqtt_options_step(current, {CONF_OPTION_FILTER_NODES: ["42"]})
    assert errors == {}
    assert new_filter_nodes == [{"id": 42, "name": "Tracker", CONF_OPTION_FILTER_NODE_STATIC_KEY: key_b64}]


def test_resubmitting_existing_device_id_updates_its_key():
    old_key_b64 = base64.b64encode(b"\x22" * 32).decode()
    new_key_b64 = base64.b64encode(b"\x33" * 32).decode()
    current = [{"id": 42, "name": "Tracker", CONF_OPTION_FILTER_NODE_STATIC_KEY: old_key_b64}]
    errors, new_filter_nodes = _run_mqtt_options_step(
        current,
        {CONF_OPTION_FILTER_NODES: ["42"], "manual_node_id": "42", "manual_static_key": new_key_b64},
    )
    assert errors == {}
    assert new_filter_nodes == [{"id": 42, "name": "Tracker", CONF_OPTION_FILTER_NODE_STATIC_KEY: new_key_b64}]


def test_removing_a_device_from_the_multiselect_drops_its_key_too():
    key_b64 = base64.b64encode(b"\x11" * 32).decode()
    current = [
        {"id": 42, "name": "Kept"},
        {"id": 99, "name": "Removed", CONF_OPTION_FILTER_NODE_STATIC_KEY: key_b64},
    ]
    errors, new_filter_nodes = _run_mqtt_options_step(current, {CONF_OPTION_FILTER_NODES: ["42"]})
    assert errors == {}
    assert new_filter_nodes == [{"id": 42, "name": "Kept"}]
