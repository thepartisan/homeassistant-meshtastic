# Feature: meshtastic-static-telemetry-key, static telemetry key field in the MQTT options flow
"""Tests for the static-telemetry-key validation logic used by
OptionsFlowHandler._async_step_mqtt_options() in config_flow.py.

config_flow.py can't be imported directly in this lightweight test
environment (it pulls in homeassistant.components.* at import time - see
test_mqtt_config_flow.py for the same constraint), so the validation logic is
replicated here verbatim.
"""

from __future__ import annotations

import base64


def _validate_static_telemetry_key(user_input: dict[str, str]) -> tuple[dict[str, str], str]:
    """Replicates the static-telemetry-key branch of _async_step_mqtt_options().

    Returns (errors, static_telemetry_key).
    """
    errors: dict[str, str] = {}
    static_telemetry_key = user_input.get("static_telemetry_key", "").strip()
    if static_telemetry_key:
        try:
            base64.b64decode(static_telemetry_key)
        except Exception:
            errors["static_telemetry_key"] = "invalid_static_telemetry_key"
    return errors, static_telemetry_key


def test_blank_key_is_valid_and_disables_the_feature():
    errors, key = _validate_static_telemetry_key({"static_telemetry_key": ""})
    assert errors == {}
    assert key == ""


def test_valid_base64_key_is_accepted():
    key_b64 = base64.b64encode(b"\x11" * 32).decode()
    errors, key = _validate_static_telemetry_key({"static_telemetry_key": key_b64})
    assert errors == {}
    assert key == key_b64


def test_invalid_base64_key_is_rejected():
    errors, _key = _validate_static_telemetry_key({"static_telemetry_key": "not valid base64!!!"})
    assert errors.get("static_telemetry_key") == "invalid_static_telemetry_key"


def test_whitespace_is_stripped():
    key_b64 = base64.b64encode(b"\x11" * 32).decode()
    errors, key = _validate_static_telemetry_key({"static_telemetry_key": f"  {key_b64}  "})
    assert errors == {}
    assert key == key_b64
