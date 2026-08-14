# Feature: meshtastic-pki-decoder, PKI identity management in the MQTT options flow
"""Tests for the PKI-identity add/remove/replace decision logic used by
OptionsFlowHandler._async_step_mqtt_options() in config_flow.py.

config_flow.py can't be imported directly in this lightweight test
environment (it pulls in homeassistant.components.* at import time - see
the other test_mqtt_config_flow*.py files for the same constraint), so the
branching logic is replicated here verbatim. The actual X25519 key
generation/derivation calls into the real aiomeshtastic.pki module though,
since that module has no homeassistant dependency - this exercises the real
crypto, not a stub of it.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from aiomeshtastic import pki


def _parse_manual_node_id(value: str) -> int:
    """Replicated from config_flow.py (see TestParseManualNodeId in test_mqtt_config_flow.py)."""
    value = value.strip()
    if value.startswith("!"):
        return int(value[1:], 16)
    try:
        return int(value)
    except ValueError:
        return int(value, 16)


def _process_pki_identity_input(
    current_identities: list[dict[str, Any]],
    user_input: dict[str, Any],
) -> tuple[dict[str, str], list[dict[str, Any]], dict[str, Any] | None]:
    """Replicates the PKI-identity branch of _async_step_mqtt_options().

    Returns (errors, updated_identities, new_identity_or_none).
    """
    errors: dict[str, str] = {}
    kept_pki_ids = [
        int(node_id) for node_id in user_input.get("mqtt_pki_identities", [])
    ]
    updated_pki_identities = [
        entry for entry in current_identities if entry["node_id"] in kept_pki_ids
    ]

    new_pki_node_id_raw = user_input.get("pki_node_id", "").strip()
    new_pki_identity: dict[str, Any] | None = None

    if new_pki_node_id_raw:
        try:
            parsed_pki_node_id = _parse_manual_node_id(new_pki_node_id_raw)
        except ValueError:
            errors["pki_node_id"] = "invalid_node_id"
        else:
            pasted_key = user_input.get("pki_private_key", "").strip()
            if pasted_key:
                try:
                    private_key = base64.b64decode(pasted_key)
                    if len(private_key) != 32:
                        raise ValueError
                    public_key = pki.public_key_for_private_key(private_key)
                except Exception:
                    errors["pki_private_key"] = "invalid_pki_key"
            else:
                private_key, public_key = pki.generate_keypair()

            if not errors:
                new_pki_identity = {
                    "node_id": parsed_pki_node_id,
                    "name": user_input.get("pki_name", "").strip(),
                    "private_key": base64.b64encode(private_key).decode("ascii"),
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                }
                updated_pki_identities = [
                    entry
                    for entry in updated_pki_identities
                    if entry["node_id"] != parsed_pki_node_id
                ] + [new_pki_identity]

    return errors, updated_pki_identities, new_pki_identity


_SINK_A = {
    "node_id": 0x209DCEAB,
    "name": "Sink A",
    "private_key": "AAA=",
    "public_key": "BBB=",
}
_SINK_B = {
    "node_id": 0x11223344,
    "name": "Sink B",
    "private_key": "CCC=",
    "public_key": "DDD=",
}


class TestPkiIdentityRemoval:
    def test_unchecking_removes_identity(self):
        errors, updated, new = _process_pki_identity_input(
            [_SINK_A, _SINK_B], {"mqtt_pki_identities": [str(_SINK_A["node_id"])]}
        )
        assert errors == {}
        assert new is None
        assert updated == [_SINK_A]

    def test_all_kept_by_default(self):
        errors, updated, _new = _process_pki_identity_input(
            [_SINK_A, _SINK_B],
            {"mqtt_pki_identities": [str(_SINK_A["node_id"]), str(_SINK_B["node_id"])]},
        )
        assert errors == {}
        assert updated == [_SINK_A, _SINK_B]

    def test_unchecking_all_clears_list(self):
        errors, updated, _new = _process_pki_identity_input(
            [_SINK_A, _SINK_B], {"mqtt_pki_identities": []}
        )
        assert errors == {}
        assert updated == []


class TestPkiIdentityCreation:
    def test_no_node_id_creates_nothing(self):
        errors, updated, new = _process_pki_identity_input(
            [_SINK_A], {"mqtt_pki_identities": [str(_SINK_A["node_id"])]}
        )
        assert errors == {}
        assert new is None
        assert updated == [_SINK_A]

    def test_blank_private_key_generates_new_keypair(self):
        errors, updated, new = _process_pki_identity_input(
            [],
            {
                "mqtt_pki_identities": [],
                "pki_node_id": "!209dceab",
                "pki_name": "HA Sink",
            },
        )
        assert errors == {}
        assert new is not None
        assert new["node_id"] == 0x209DCEAB
        assert new["name"] == "HA Sink"

        private_key = base64.b64decode(new["private_key"])
        public_key = base64.b64decode(new["public_key"])
        assert len(private_key) == 32
        assert len(public_key) == 32
        # The stored public key must actually correspond to the stored private key.
        assert pki.public_key_for_private_key(private_key) == public_key
        assert updated == [new]

    def test_pasted_private_key_is_used_verbatim(self):
        private_key, expected_public_key = pki.generate_keypair()
        errors, _updated, new = _process_pki_identity_input(
            [],
            {
                "mqtt_pki_identities": [],
                "pki_node_id": "1234",
                "pki_private_key": base64.b64encode(private_key).decode(),
            },
        )
        assert errors == {}
        assert new is not None
        assert base64.b64decode(new["private_key"]) == private_key
        assert base64.b64decode(new["public_key"]) == expected_public_key

    def test_invalid_base64_private_key_rejected(self):
        errors, updated, new = _process_pki_identity_input(
            [],
            {
                "mqtt_pki_identities": [],
                "pki_node_id": "1234",
                "pki_private_key": "not valid base64!!!",
            },
        )
        assert errors.get("pki_private_key") == "invalid_pki_key"
        assert new is None
        assert updated == []

    def test_wrong_length_private_key_rejected(self):
        short_key = base64.b64encode(b"\x00" * 16).decode()
        errors, _updated, new = _process_pki_identity_input(
            [],
            {
                "mqtt_pki_identities": [],
                "pki_node_id": "1234",
                "pki_private_key": short_key,
            },
        )
        assert errors.get("pki_private_key") == "invalid_pki_key"
        assert new is None

    def test_invalid_node_id_rejected(self):
        errors, updated, new = _process_pki_identity_input(
            [], {"mqtt_pki_identities": [], "pki_node_id": "not-a-node-id"}
        )
        assert errors.get("pki_node_id") == "invalid_node_id"
        assert new is None
        assert updated == []

    def test_re_adding_same_node_id_replaces_old_identity(self):
        """Entering an existing identity's node ID again (with a blank/new
        key) is how a keypair gets regenerated/"changed" - it must fully
        replace the old entry, never leave two entries for one node.
        """
        errors, updated, new = _process_pki_identity_input(
            [_SINK_A],
            {
                "mqtt_pki_identities": [str(_SINK_A["node_id"])],
                "pki_node_id": f"!{_SINK_A['node_id']:08x}",
            },
        )
        assert errors == {}
        assert len(updated) == 1
        assert updated[0] is new
        assert updated[0]["private_key"] != _SINK_A["private_key"]

    def test_create_and_remove_combine_in_one_submission(self):
        errors, updated, new = _process_pki_identity_input(
            [_SINK_A, _SINK_B],
            {"mqtt_pki_identities": [str(_SINK_B["node_id"])], "pki_node_id": "999"},
        )
        assert errors == {}
        assert _SINK_A not in updated
        assert _SINK_B in updated
        assert new in updated
        assert len(updated) == 2


if __name__ == "__main__":
    pytest.main([__file__])
