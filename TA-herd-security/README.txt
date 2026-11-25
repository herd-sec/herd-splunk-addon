Herd Security Add-on for Splunk (TA-herd-security) 1.0.0

This add-on parses the events Herd Security sends to a Splunk HTTP Event
Collector (HEC) input. It contains search-time knowledge only: no inputs, no
scripts and no index definitions.

Sourcetypes
  herd:security:event   Security and risk events (CIM: Alerts)
  herd:points:earned    Points earned (opt-in in Herd)
  herd:ai:correction    AI corrections (opt-in in Herd)
  herd:test             The test event from "Send test event" in Herd

Setup
  1. Install this add-on on your search heads (and on the heavy forwarders or
     indexers if HEC runs there).
  2. Create a HEC token (Settings > Data inputs > HTTP Event Collector) with an
     index of your choice. Leave the sourcetype unset: Herd sets it per event.
  3. In Herd, open Settings > Integrations > SIEM / DLP Webhooks > Outbound
     Event Delivery, choose "Splunk HTTP Event Collector (HEC)", and enter the
     HEC URL (ending /services/collector/event), the token and the index.

Release notes
  1.0.0  First release: field extractions, CIM Alerts mapping and eventtypes
         for the herd:security:event, herd:points:earned and herd:ai:correction
         sourcetypes.

Full documentation: https://herd-security.gitbook.io
