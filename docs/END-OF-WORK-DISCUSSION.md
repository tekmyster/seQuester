# End-of-work discussion list

## Wazuh integration — added October 9, 2026

User requested that this topic be discussed at the end of the main work.

- Preferred routing: server syslog for structured seQuester events; existing
  Wazuh agents for endpoint/server operational logs.
- Forward all seQuester records, including whitelisted activity, while keeping
  log-only events separate from alerts and automatic responses.
- Receiver source authorization, decoding, retention and search of non-alert
  records; avoid duplicate sensor/server forwarding.
- Whether Wazuh should coordinate blocking/process termination with seQuester,
  including original-host routing and revalidation of process-instance identity.
- Review deployment status and actual end-to-end acceptance before treating the
  integration as complete.

The optional log-only export is implemented and locally tested in source but
not deployed. Wazuh-triggered response is not enabled. Defer further Wazuh
deployment/response changes until this discussion; continue the main collection,
attribution, detection and reliability work.

Technical findings and test evidence: [Wazuh integration](WAZUH-INTEGRATION.md).
