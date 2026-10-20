"""Add a brand-new detector in ~20 lines:  python examples/custom_detector.py

It watches for very long DNS names (a common sign of DNS tunnelling). The
moment the class is registered, `--longdns` exists on the command line and its
alerts flow through the same grouping, scoring and reporting as the built-ins.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alertsift.cli import main                                       # noqa: E402
from alertsift.detectors import Detector, register                   # noqa: E402
from alertsift.detectors.util import parse_timestamp, read_lines     # noqa: E402
from alertsift.schema import Alert, AlertType                        # noqa: E402


@register
class LongDnsNameDetector(Detector):
    name = "longdns"
    alert_type = AlertType.C2_BEACONING
    description = "Very long DNS names (possible tunnelling); CSV lines of: time,src,name"

    def detect(self, path):
        for line in read_lines(Path(path)):
            stamp, src, name = (part.strip() for part in line.split(",")[:3])
            when = parse_timestamp(stamp)
            if when and len(name) > 50:
                yield Alert(self.alert_type, when, "dns", src, name[:30],
                            description=f"{len(name)}-character DNS name", mitre="T1071.004", raw=line)


if __name__ == "__main__":
    demo = Path(tempfile.mkdtemp()) / "dns_names.csv"
    demo.write_text("\n".join(
        f"2026-10-09T10:00:{i:02d}+00:00,10.0.0.5,{'a1b2c3' * 12}{i}.tunnel.example" for i in range(6)))
    raise SystemExit(main(["--longdns", str(demo), "--max-details", "1"]))
