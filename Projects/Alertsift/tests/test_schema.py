from datetime import datetime, timedelta, timezone

import pytest

from alertsift.detectors.base import Detector, available, get_detector, register
from alertsift.schema import Alert, AlertType, Incident


def make_alert(minutes=0, entity="10.0.0.5", target="root", tz=timezone.utc):
    base = datetime(2026, 10, 9, 10, 0, tzinfo=tz)
    return Alert(
        alert_type=AlertType.AUTH_ATTACK,
        timestamp=base + timedelta(minutes=minutes),
        source="test",
        entity=entity,
        target=target,
    )


def test_naive_timestamp_is_assumed_utc():
    a = Alert(AlertType.PORT_SCAN, datetime(2026, 10, 9, 10, 0), "test", "1.2.3.4")
    assert a.timestamp.tzinfo is not None
    assert a.timestamp.utcoffset() == timedelta(0)


def test_timestamp_with_offset_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    a = make_alert(tz=ist)  # 10:00 IST == 04:30 UTC
    assert a.timestamp.hour == 4 and a.timestamp.minute == 30


def test_incident_properties():
    inc = Incident(AlertType.AUTH_ATTACK, "10.0.0.5",
                   [make_alert(0, target="root"), make_alert(7, target="kali")])
    assert inc.count == 2
    assert inc.first_seen < inc.last_seen
    assert inc.targets == {"root", "kali"}


def test_incident_id_is_stable_and_entity_specific():
    a = Incident(AlertType.AUTH_ATTACK, "10.0.0.5", [make_alert(0)])
    b = Incident(AlertType.AUTH_ATTACK, "10.0.0.5", [make_alert(0)])
    c = Incident(AlertType.AUTH_ATTACK, "10.0.0.9", [make_alert(0, entity="10.0.0.9")])
    assert a.id == b.id
    assert a.id != c.id
    assert a.id.startswith("INC-")


def test_register_and_lookup_detector():
    @register
    class Dummy(Detector):
        name = "dummy_for_test"
        alert_type = AlertType.AUTH_ATTACK

        def detect(self, path):
            yield make_alert()

    assert "dummy_for_test" in available()
    alerts = list(get_detector("dummy_for_test").detect("ignored"))
    assert len(alerts) == 1


def test_duplicate_registration_rejected():
    with pytest.raises(ValueError):
        @register
        class Dup(Detector):
            name = "dummy_for_test"
            alert_type = AlertType.AUTH_ATTACK

            def detect(self, path):
                return iter(())


def test_unknown_detector_gives_helpful_error():
    with pytest.raises(KeyError):
        get_detector("does_not_exist")
