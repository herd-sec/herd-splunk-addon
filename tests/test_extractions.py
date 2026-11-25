#!/usr/bin/env python3
"""Check the REPORT field extractions in transforms.conf against Herd's real events.

The samples in tests/samples/*.raw.jsonl are the exact JSON Herd's outbound
builder produces (the `event` of each HEC envelope). Splunk applies these
transforms at search time; here the same regexes run through Python's `re`
(the patterns use only syntax PCRE and Python share) so a typo in a field name
or an escape is caught without a Splunk instance.

    python3 tests/test_extractions.py
"""

import configparser
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "TA-herd-security" / "default"
SAMPLES = ROOT / "tests" / "samples"


def read_conf(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    parser.optionxform = str  # keep key case
    parser.read(path)
    return parser


TRANSFORMS = read_conf(DEFAULT / "transforms.conf")
PROPS = read_conf(DEFAULT / "props.conf")


def extract(sourcetype: str, raw: str) -> dict[str, str]:
    """Apply the REPORT transforms of `sourcetype` the way Splunk does (FORMAT = $n::$m pairs)."""
    fields: dict[str, str] = {}
    reports = PROPS[sourcetype].get("REPORT-herd_security_fields", "")
    for name in [n.strip() for n in reports.split(",") if n.strip()]:
        regex = re.compile(TRANSFORMS[name]["REGEX"])
        fmt = TRANSFORMS[name]["FORMAT"].strip()
        for match in regex.finditer(raw):
            key, value = (part for part in fmt.split("::"))
            key = match.group(int(key[1:])) if key.startswith("$") else key
            value = match.group(int(value[1:])) if value.startswith("$") else value
            fields[key] = value
    return fields


def samples(name: str) -> list[str]:
    return [line for line in (SAMPLES / f"{name}.raw.jsonl").read_text().splitlines() if line]


class SecurityEventExtraction(unittest.TestCase):
    def test_every_field_of_every_sample_is_extracted(self) -> None:
        for raw in samples("herd_security_event"):
            body = json.loads(raw)
            fields = extract("herd:security:event", raw)
            self.assertEqual(fields["herd_type"], "security_event")
            self.assertEqual(fields["herd_source"], body["source"])
            for key in ("eventId", "eventType", "severity", "outcome", "occurredAt"):
                self.assertEqual(fields[key], body[key], key)

    def test_actor_fields_exist_only_when_the_event_has_an_actor(self) -> None:
        with_actor, _positive, without_actor = samples("herd_security_event")
        fields = extract("herd:security:event", with_actor)
        self.assertEqual(fields["actorUserId"], "cm3x9k2l40001abc")
        self.assertEqual(fields["actorEmail"], "jane.doe@example.com")
        fields = extract("herd:security:event", without_actor)
        self.assertNotIn("actorUserId", fields)
        self.assertNotIn("actorEmail", fields)

    def test_source_is_kept_off_splunks_own_source_field(self) -> None:
        fields = extract("herd:security:event", samples("herd_security_event")[0])
        self.assertNotIn("source", fields)
        self.assertEqual(fields["herd_source"], "phishing")

    def test_an_escaped_quote_inside_a_value_does_not_end_it(self) -> None:
        raw = r'{"type":"security_event","eventId":"a\"b","source":"x","eventType":"y"}'
        self.assertEqual(extract("herd:security:event", raw)["eventId"], r"a\"b")


class StanzaContract(unittest.TestCase):
    def test_every_sourcetype_herd_sends_has_a_props_stanza(self) -> None:
        sent = {
            json.loads(line)["sourcetype"]
            for path in SAMPLES.glob("*.hec.jsonl")
            for line in path.read_text().splitlines()
            if line
        }
        self.assertEqual(sent, set(PROPS.sections()))

    def test_every_report_names_a_transform(self) -> None:
        for section in PROPS.sections():
            for key, value in PROPS[section].items():
                if key.startswith("REPORT-"):
                    for name in [n.strip() for n in value.split(",")]:
                        self.assertIn(name, TRANSFORMS.sections(), f"{section} {key}")

    def test_the_alert_eventtype_is_tagged_alert(self) -> None:
        tags = read_conf(DEFAULT / "tags.conf")
        self.assertEqual(tags["eventtype=herd_security_alert"]["alert"], "enabled")
        eventtypes = read_conf(DEFAULT / "eventtypes.conf")
        self.assertIn("outcome=negative", eventtypes["herd_security_alert"]["search"])

    def test_samples_are_what_the_hec_envelope_carries(self) -> None:
        for path in SAMPLES.glob("*.hec.jsonl"):
            for line in path.read_text().splitlines():
                envelope = json.loads(line)
                self.assertEqual(
                    set(envelope) - {"index"}, {"time", "host", "source", "sourcetype", "event"}
                )
                self.assertEqual(envelope["source"], "herd")
                self.assertIsInstance(envelope["time"], (int, float))


if __name__ == "__main__":
    unittest.main()
