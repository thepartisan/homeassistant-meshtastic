# Feature: meshtastic-mqtt-integration, gateway-first device creation ordering
"""Tests for the node-processing order in __init__._setup_meshtastic_devices().

Every non-gateway device is created with via_device pointing at the
gateway's own device entry, so that entry must already exist by the time
it's referenced - otherwise device_registry.async_get_or_create() gets a
dangling via_device (HA logs a "will stop working in 2025.12.0" deprecation
warning today). dict iteration order from async_get_all_nodes() doesn't
guarantee the gateway node comes first, so it must be moved to the front
explicitly before iterating.

__init__.py can't be imported directly in this lightweight test environment
(it pulls in homeassistant.* at import time - see test_mqtt_config_flow.py
for the same constraint), so the ordering logic is replicated here verbatim.
"""

from __future__ import annotations


def order_gateway_first(node_ids: list[int], gateway_node_id: int) -> list[int]:
    """Replicates the ordering line added to _setup_meshtastic_devices()."""
    return sorted(node_ids, key=lambda n: n != gateway_node_id)


def test_gateway_already_first_stays_first():
    assert order_gateway_first([1, 2, 3], gateway_node_id=1) == [1, 2, 3]


def test_gateway_in_middle_moves_to_front():
    assert order_gateway_first([5, 1, 2, 3], gateway_node_id=1) == [1, 5, 2, 3]


def test_gateway_last_moves_to_front():
    assert order_gateway_first([5, 2, 3, 1], gateway_node_id=1) == [1, 5, 2, 3]


def test_non_gateway_relative_order_is_preserved():
    # Stable sort: everything else keeps its original relative order.
    assert order_gateway_first([9, 7, 1, 8, 6], gateway_node_id=1) == [1, 9, 7, 8, 6]


def test_gateway_not_present_is_a_no_op():
    assert order_gateway_first([5, 2, 3], gateway_node_id=999) == [5, 2, 3]
