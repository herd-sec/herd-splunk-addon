# Herd Security Add-on for Splunk

A Splunk technology add-on for the events Herd Security sends to a Splunk HTTP Event Collector (HEC). It holds search-time knowledge only: field extractions, Common Information Model (CIM) mapping, event types and tags. It has no inputs, no scripts and no index definitions.

Herd pushes the events. Nothing in this add-on pulls from Herd.

## What it parses

| Sourcetype | Event | CIM |
| --- | --- | --- |
| `herd:security:event` | Security and risk events: phishing simulation results, training outcomes, compliance attestations, identity posture findings, SIEM alerts, AI findings | Alerts, for `outcome=negative` |
| `herd:points:earned` | One event per points ledger entry. Opt-in in Herd | none |
| `herd:ai:correction` | One event per rule decision on an AI tool or agent call. Opt-in in Herd. Never carries prompt text | none |
| `herd:test` | The test event from "Send test event" in Herd | none |

### Fields on `herd:security:event`

| Field | From the event | Notes |
| --- | --- | --- |
| `eventId` | `eventId` | Stable per event, for example `phishing:credential_submitted:<id>` |
| `herd_source` | `source` | `phishing`, `okta`, `training`, ... Kept off Splunk's own `source` field |
| `eventType` | `eventType` | |
| `severity` | `severity` | CIM values: lowercased (`critical`, `high`, `medium`, `low`) |
| `outcome` | `outcome` | `negative` (a risky action) or `positive` (a phish reported, a training done) |
| `occurredAt` | `occurredAt` | ISO 8601. HEC sets `_time` from it |
| `actorUserId`, `actorEmail` | `actorUserId`, `actorEmail` | Absent when the event has no person attached |
| `herd_type` | `type` | Always `security_event` |

CIM Alerts fields are added on top: `app`, `vendor_product`, `type=alert`, `severity`, `severity_id` (1 to 4), `id`, `signature`, `signature_id` (`<herd_source>:<eventType>`), `user` (the actor's email) and `user_id`.

The `herd_security_alert` event type (`outcome=negative`) carries `tag=alert`, so those events show up in the Alerts data model. Positive events are not alerts and stay out of it.

None of Herd's event types today is an authentication event, so there is no Authentication mapping.

## Install

1. Install the add-on on your search heads. If HEC runs on a heavy forwarder or an indexer, install it there too.
2. In Splunk, go to **Settings > Data inputs > HTTP Event Collector** and create a token. Pick the index the events should land in. Leave the sourcetype unset: Herd sets it on every event.
3. In Herd, go to **Settings > Integrations > SIEM / DLP Webhooks > Outbound Event Delivery**. Choose **Splunk HTTP Event Collector (HEC)**, enter the HEC URL (it ends in `/services/collector/event`), the token and, optionally, the index.
4. Select **Send test event**. Search `sourcetype=herd:test` in Splunk to see it.

Then search:

```
sourcetype="herd:security:event" outcome=negative
| stats count by herd_source eventType severity
```

or against the data model:

```
| tstats count from datamodel=Alerts where nodename=Alerts by Alerts.app Alerts.severity Alerts.signature
```

The Alerts data model's tag constraint may need `herd_security_alert`'s index added to its allowed indexes (`cim_Alerts_indexes` macro in the CIM add-on) if you put Herd events in a custom index.

## What Herd sends

Each HTTP request is one event in the HEC envelope:

```json
{
  "time": 1795615401.482,
  "host": "herdsecurity.io",
  "source": "herd",
  "sourcetype": "herd:security:event",
  "index": "herd",
  "event": {
    "type": "security_event",
    "eventId": "phishing:credential_submitted:int_8f3a1c",
    "source": "phishing",
    "eventType": "credential_submitted",
    "severity": "HIGH",
    "outcome": "negative",
    "occurredAt": "2026-11-24T14:03:21.482Z",
    "actorUserId": "cm3x9k2l40001abc",
    "actorEmail": "jane.doe@example.com"
  }
}
```

`index` is present only when you set one in Herd. Real samples are in `tests/samples/`.

Herd retries a failed delivery with backoff and gives up after five attempts. HEC has no deduplication, so a request that Splunk indexed but whose response was lost can arrive twice. `eventId` is stable, so `| dedup eventId` removes the repeat.

## Develop

```
python3 tests/test_extractions.py     # field extractions against the real samples
scripts/build.sh                      # dist/TA-herd-security-<version>.tgz
scripts/appinspect.sh                 # AppInspect, precert mode, cloud tag
```

AppInspect needs `pip install splunk-appinspect` in a Python 3.9 to 3.12 environment, plus `libmagic`.

`tests/samples/` holds the output of Herd's outbound builder, one `.hec.jsonl` file (the request body) and one `.raw.jsonl` file (the `_raw` Splunk stores) per sourcetype. Regenerate them from herd-core when the event bodies change.

### Status

- AppInspect `--mode precert --included-tags cloud`: 0 failures, 0 errors, 0 warnings (splunk-appinspect 4.4.0).
- The extractions are tested with Python's `re` against the real samples. They have not been run in a Splunk instance, and the CIM Alerts mapping has not been checked with the CIM validation dashboards.
- The icons are placeholders (`scripts/make_icons.py`).
- The contact address in `app.manifest` and the Apache-2.0 licence are placeholders for the owner to confirm before submission.
- Splunk's default (non-cloud) precert run warns that `check_for_updates = true` belongs to apps listed on Splunkbase. That is intended for the listing; set it to `false` for a private install.
