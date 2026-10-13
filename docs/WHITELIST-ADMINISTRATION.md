## UI update — October 12

The editor now groups file operations and puts optional process restrictions and advanced scope settings behind expandable sections. Edit still selects only write, append and truncate. Use Sensor policy status and Linux hash-rule readiness for deployment details. All rule behavior and publication requirements below remain unchanged. The permanent design requirements are in [Product UX Contract](PRODUCT-UX-CONTRACT.md).

# Action-specific whitelists and alert rules

## Create a rule without an event

1. Open **Trust rules** on the management server.
2. Choose **Create whitelist** or **Create alert rule**. This prepares a disabled draft and retains existing rules.
3. Choose the scope: all sensors, a group, or one sensor. Add an optional exact target-file path.
4. Choose **User**, **Process**, or **User and process**. The last option requires both identities to match.
5. Select the operations. **Read only** selects read. **Edit** selects write, append and truncate. **Delete only** selects delete. Rename, move and permission changes require their own selections.
6. Set the start and expiry times. Review, enable and publish with administrator verification. Scoped exceptions may require broader-scope approval.
7. Check sensor policy receipts. Publishing a rule does not prove that each sensor has received or applied it.

No previous alert is required. Creating a draft does not enable a rule or change sensor behavior.

## Identity matching

- **Windows user:** supply the SID and its authority/domain, as recorded by the monitoring source. An account name alone is insufficient. Forensic details distinguish the process owner and available effective-thread identity; coverage depends on the source.
- **Linux user:** supply the UID and the target sensor ID as authority. The same UID on another sensor is not automatically trusted.
- **Windows process:** new drafts default to the exact executable path plus SHA-256. Obtain the digest from a trusted copy, for example:

  ```powershell
  (Get-FileHash -LiteralPath 'C:\Windows\System32\notepad.exe' -Algorithm SHA256).Hash
  ```

  A renamed or replaced binary with a different digest will not match. Missing verified executable evidence cannot satisfy a hash rule.
- **Path-only process matching:** this remains available as an explicit option labelled **no binary verification**. Existing path-only rules are preserved. It does not establish that the file contains the expected executable.
- **Linux kernel hash matching:** requires a qualified source and verified captured executable bytes. Its current trust mode matches observed open requests, with the restrictions shown in the readiness table. Do not infer write, append or other operation coverage from that mode.

An interpreter's executable hash identifies the interpreter, not a script passed to it. A whitelist grants the selected notification/response exception; it is not a declaration that the executable is safe.

## What happens to an event

| Result | Behavior |
|---|---|
| Approved log-only rule matches every observed operation | Retain the event and matched rule IDs; suppress seQuester alerts and automatic response for that event. |
| Always-alert rule also matches | Alert; retain both matching rule IDs. The always-alert rule takes precedence. |
| Identity, hash, path, scope, time or operation does not match | Continue alerting. |
| Required evidence is unavailable or policy assignment expires | Continue alerting; retain the available evidence and diagnostic state. |

For an OR policy, create separate user-only and process-only whitelists with the same resource and operation restrictions. Either approved match can permit log-only handling, unless an always-alert rule also matches. A single **User and process** rule is AND, not OR.

Remote canary callbacks do not establish a local user or process and are not covered by these local file-operation rules. A rule cannot provide detection for an operation the sensor did not capture. Current native attribution and executable-preservation gaps remain recorded in `CURRENT-OPEN-WORK.md`.

## Verification scope

The feature uses the existing versioned trust policy, sensor receipts, server validation and durable event history. Qualification includes real authenticated UI publication before any events exist, persistence after reload, user/process/AND predicates, operation presets, same-path wrong/missing-hash controls, always-alert precedence, history retention and desktop/tablet/mobile layouts. Test events in the UI acceptance fixture are explicitly synthetic; they do not establish universal native capture coverage.
