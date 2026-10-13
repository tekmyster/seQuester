# seQuester documentation

seQuester detects activity around monitored honeypot files and canary tokens, records available actor evidence, and brings that activity into a central investigation workflow.

This documentation describes the development source published on October 13, 2026. Current behavior and pending work are distinguished in the [capability register](CAPABILITIES.md). Earlier engineering logs remain available as historical evidence.

## Start here

| You want to… | Read |
| --- | --- |
| Understand the product and investigate activity | [User guide](USER-GUIDE.md) |
| Enroll sensors, publish policies and configure delivery | [Administrator guide](ADMINISTRATOR-GUIDE.md) |
| Install, upgrade or recover the application | [Deployment and operations](DEPLOYMENT-AND-OPERATIONS.md) |
| Understand event capture, evidence and storage | [Architecture and evidence](ARCHITECTURE-AND-EVIDENCE.md) |
| Integrate with the server | [API guide](API-GUIDE.md) |
| Check what is implemented and what remains open | [Capability register](CAPABILITIES.md) |
| Review the interface | [Screenshot reference](SCREENSHOTS.md) |
| Contribute code or maintain documentation | [Development guide](DEVELOPMENT.md) |

## Product vocabulary

| Term | Meaning |
| --- | --- |
| Sensor | The endpoint component that monitors a host and reports activity. |
| Honeypot file | A locally monitored decoy file. Access is detected by a sensor. |
| Canary token | A unique marker or resource that records a callback when used by a compatible application or protocol. |
| Actor executable | The executable performing a monitored operation. This is the primary binary to hash and preserve. |
| Target file | The file being accessed or changed. It is not automatically preserved by the forensic pipeline. |
| Process instance | A process identified by its host, PID and creation identity; not PID alone. |
| Whitelist | A scoped exception that retains matching activity without an alert. |
| Incident | An analyst-created case linking activity, ownership and investigation notes. |
| Receipt | An acknowledgement for a particular delivery stage. Its meaning depends on that stage. |

Use **seQuester** for the product and **Sensors** for inventory. Source folders and project files use `seQuester`; existing assembly names, namespaces, routes and installed service paths remain unchanged for compatibility. See [Repository layout](REPOSITORY-LAYOUT.md).

## Detailed engineering references

The guides above provide the application overview. Use these references for platform implementation and acceptance history:

- [Forensic evidence contract](FORENSIC-EVIDENCE.md)
- [Windows kernel capture](WINDOWS-KERNEL-CAPTURE.md), [deferred token integration](WINDOWS-DEFERRED-TOKEN-INTEGRATION.md), and [syscall sensor reporting](WINDOWS-SYSCALL-SENSOR-REPORTING.md)
- [Linux kernel attribution](LINUX-KERNEL-ATTRIBUTION.md), [operation capture](LINUX-OPERATION-CAPTURE.md), and [native whitelist plan](LINUX-KERNEL-WHITELIST-PLAN.md)
- [Whitelist administration](WHITELIST-ADMINISTRATION.md)
- [Active response plan](ACTIVE-RESPONSE-PLAN.md) and [Wazuh integration](WAZUH-INTEGRATION.md)
- [Integration checkpoint](RESPONSE-POLICY-INTEGRATION-20261012.md) and [historical open work](CURRENT-OPEN-WORK.md)
- [Product UX Contract](PRODUCT-UX-CONTRACT.md)

Historical entries describe the state at their recorded time. They do not override newer capability or integration updates.
