# Feature: meshtastic-mqtt-integration, entity dedup on coordinator refresh
"""Tests for the new-vs-already-added entity check in
helpers.setup_platform_entry()'s on_coordinator_data_update() callback.

Entities must be deduped by unique_id, not entity_id: MeshtasticNodeEntity's
entity_id bakes in the gateway node's live shortName, which can be unknown
on an early call and resolve to a real value later - recomputing entity_id
at that point produces a different string for the *same* unique_id, and
deduping by entity_id would then treat it as new and resubmit it, which the
entity registry correctly (and repeatedly) rejects as a duplicate unique_id.

helpers.py can't be imported directly in this lightweight test environment
(it pulls in homeassistant.* at import time - see test_mqtt_config_flow.py
for the same constraint), so the dedup logic is replicated here verbatim.
"""

from __future__ import annotations


class FakeEntity:
    def __init__(self, entity_id: str, unique_id: str) -> None:
        self.entity_id = entity_id
        self.unique_id = unique_id


def dedup_by_unique_id(candidates: list[FakeEntity], already_added: list[FakeEntity]) -> list[FakeEntity]:
    """Replicates the fixed body of on_coordinator_data_update()."""
    existing_unique_ids = {e.unique_id for e in already_added}
    return [s for s in candidates if s.unique_id not in existing_unique_ids]


def test_same_unique_id_is_not_resubmitted_even_if_entity_id_changed():
    already_added = [FakeEntity("binary_sensor.meshtastic_547212971_device_powered", "entry1_binary_sensor_547212971_device_powered")]
    # Gateway shortName resolved between calls, changing the computed entity_id -
    # unique_id (what the registry actually keys on) is unchanged.
    candidates = [
        FakeEntity("binary_sensor.meshtastic_mqtt_547212971_device_powered", "entry1_binary_sensor_547212971_device_powered")
    ]

    assert dedup_by_unique_id(candidates, already_added) == []


def test_genuinely_new_unique_id_is_still_submitted():
    already_added = [FakeEntity("binary_sensor.meshtastic_547212971_device_powered", "entry1_binary_sensor_547212971_device_powered")]
    candidates = [
        FakeEntity("binary_sensor.meshtastic_547212971_device_powered", "entry1_binary_sensor_547212971_device_powered"),
        FakeEntity("binary_sensor.meshtastic_999_device_powered", "entry1_binary_sensor_999_device_powered"),
    ]

    result = dedup_by_unique_id(candidates, already_added)

    assert [e.unique_id for e in result] == ["entry1_binary_sensor_999_device_powered"]


def test_no_already_added_entities_submits_everything():
    candidates = [FakeEntity("binary_sensor.meshtastic_1_device_powered", "entry1_binary_sensor_1_device_powered")]

    assert dedup_by_unique_id(candidates, []) == candidates
