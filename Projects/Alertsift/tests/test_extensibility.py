"""The architecture's main claim: a new attack type is one small class."""
import json
from datetime import datetime, timedelta, timezone

from alertsift.cli import main
from alertsift.detectors import Detector, register
from alertsift.schema import Alert, AlertType


def test_new_detector_becomes_a_cli_flag_without_touching_the_core(tmp_path, capsys):
    @register
    class DemoDetector(Detector):
        name = "demo_ext"
        alert_type = AlertType.WEB_ATTACK
        description = "demo detector used by the test-suite"

        def detect(self, path):
            start = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)
            for i in range(6):
                yield Alert(self.alert_type, start + timedelta(seconds=i), "demo", "9.9.9.9",
                            "/x", raw=f"event {i}")

    sample = tmp_path / "anything.txt"
    sample.write_text("ignored")
    assert main(["--demo_ext", str(sample), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["incidents"][0]["type"] == "web_attack"
    assert data["incidents"][0]["alert_count"] == 6
