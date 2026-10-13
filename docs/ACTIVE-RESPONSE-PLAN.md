## Delivered policy workflow checkpoint — October 11 EDT

The server's whitelist/always-alert authoring UI is deployed as whitelist-20261011-r3 on unchanged 0.6.45 runtime. User-only, process-only and user-and-process rules can be created without events. Read/Edit/Delete presets, verified Windows path-plus-hash defaults, explicit path-only disclosure, required-field validation and always-alert precedence passed feature QA. Equivalent OR behavior uses separate rules; there is no new single-rule OR schema or PID-specific rule in this delivery. Exact-directory matching, principal-selection controls and the broader AR response chain are not closed by this UI work. No response policy, account restriction or process termination was enabled. See WHITELIST-ADMINISTRATION.md and the current feature register for receipts and platform limits.
# seQuester active response plan

Status: planned at the user's request on October 11, 2026. Add responses that stop access, terminate the responsible process, and disable the responsible account. This plan adds no live enforcement or implementation-completion claims.

## Existing foundation

The [remote response design](../src/RansomFree.Agent/REMOTE_RESPONSES.md) documents a Windows process-stop implementation with local permission gates, administrator reauthentication, recent local event matching, identity checks, exclusions, durable intent and receipts. Its acceptance status must be checked against current QA before reuse. Extend that implementation rather than creating a second unrestricted command channel.

The [open work register](CURRENT-OPEN-WORK.md) records unresolved live reporting and executable-preservation issues. Qualification must cover the actual event source used by each response; successful capture in a different fixture does not qualify an enforcement path.

## Response backlog

| Item | Capability | Required result |
| --- | --- | --- |
| AR-01 | Response policy and preview | Show exact endpoint, event, process instance, resource, account, reason, duration and expected impact. Support observation, operator action and separately enabled automatic policies. Default new actions to observation. |
| AR-02 | Stop access to a protected resource | Implement scoped denial for supported file/share operations, with explicit handling of already-open handles and sessions. Verify the affected access is denied and unrelated authorized access still succeeds. Preserve previous state and remove only the change owned by this response. |
| AR-03 | Terminate the responsible process | Bind to endpoint, boot identity, PID and process creation time, with available executable identity evidence. Revalidate at execution and hold a stable OS process reference where supported. Confirm that exact process exited. Reject stale events and PID reuse. Termination has no true undo. |
| AR-04 | Disable the responsible account | Resolve an immutable account identifier and authority: local account, AD or another supported directory. Distinguish process owner from effective impersonated user. Display and explicitly select the intended identity; never guess from a name or PID. Verify directory state and a controlled fresh authentication denial. |
| AR-05 | Revoke active access | Treat session/token revocation as separate from account disabling. Define and test coverage for existing sessions, open handles and supported authentication methods. Report residual access explicitly. |
| AR-06 | Optional host or network containment | Add narrowly scoped isolation or temporary EDL entries only after the endpoint/account actions pass. Preserve management, telemetry and recovery paths. Shared or NAT addresses require impact review before blocking. |
| AR-07 | Integrations and audit | Link seQuester events, operator decisions, Wazuh/CoPilot incidents and EDL changes through durable IDs. One authority owns each response; duplicate alerts must not produce repeated or conflicting actions. |
| AR-08 | User and process lists by file operation | Provide allowlists and blocklists scoped to resources and operations. Allowlisted activity generates a visible notice; blocklisted, unmatched or insufficiently attributed activity generates an alert. Support user-only, process-only, user AND process, and user OR process matching with explicit conflict precedence. |

## User and process access policies

User requirement: whitelisted access still gets a notice; everything else gets an alert. Keep every captured event, attempted operation, result, matched rule and policy revision available in history. An allowlist must not silently discard activity. Existing log-only trust handling is a foundation, but a retained database row alone does not satisfy the requested visible notice.

Each rule selects the endpoint or group, file or directory scope, identity conditions, operations, list disposition and optional expiry. Support read, write/edit, append, truncate/overwrite, rename/move, delete and permissions/ownership changes as independently selectable operations where the source can prove them. A UI Edit preset may select write, append and truncate explicitly; it must not silently include delete or permission changes. Saving via replacement or rename requires its own selected operations. Copying source content counts as reading only where that read is observed; do not claim that a read proves completed copying or exfiltration.

User identity uses an immutable SID or UID with its directory/host/namespace authority. Select process-owner versus effective accessing identity explicitly, and show impersonation when present. PID selection creates a temporary rule for one endpoint, boot and process start time, not a permanent numeric-PID exception. Provide separate persistent executable rules based on verified hash or another explicitly supported identity method. A missing required identity or unsupported operation cannot qualify an event for notice-only treatment.

Allow user-only and process-only rules, require both selectors for AND, and show clearly that OR permits either selector to match. A rule must also match the resource and operation. Apply this precedence within that scope:

| Matching result | Notification | Enforcement |
| --- | --- | --- |
| Any explicit blocklist rule, including a conflict with an allowlist | Alert with the conflicting rule IDs | Apply only the separately enabled and qualified block/response policy. |
| A verified allowlist match and no blocklist match | Visible informational notice | Suppress seQuester automatic response for this operation. Do not grant permissions the OS otherwise denies. |
| No matching allowlist, missing required identity or unsupported matching capability | Alert with the reason and actual operation outcome | Use the configured response policy; an alert alone does not authorize termination or account disablement. |

Enforcement exclusions for recovery accounts and critical services prevent harmful actions without hiding their alerts. Keep attempted versus successful activity distinct. Missing source coverage requires a visible health/coverage failure; the product cannot promise an alert for an operation it never captured. Delivery may aggregate repeated notices, but must preserve counts, original evidence and accessible notice history.

The policy editor must preview examples such as an approved backup process reading a folder (notice), the same process attempting an unapproved delete (alert), and an explicitly blocked user invoking an otherwise allowed process (alert). Show the matched identity, AND/OR grouping, operation and winning rule before publication. An allowlist change must not reclassify historical events silently.

AR-08 acceptance must cover every supported operation against user-only, process-only, AND and OR rules; conflicting rules; PID reuse and process restart; impersonation changes; account-name collisions; missing identity; path replacement and rename; file-scope/namespace ambiguity; stale policy and offline delivery. Verify both notice and alert paths through the actual UI and configured notification/SIEM destinations. Confirm that notices remain visible, unmatched activity remains alerting, and allowlisted activity is not automatically terminated. Test actual blocking separately from classification. These are pending acceptance requirements, not claims of implemented coverage.

## Evidence and execution controls

Preserve the event and attempt bounded executable acquisition before destructive action. Do not wait indefinitely for a snapshot or upload while damage continues. A policy must explicitly define whether containment may proceed without a preserved binary; show the missing evidence and reason. Hashing and upload stay outside critical file-I/O callbacks.

Use authenticated, authorized commands with endpoint scope, short expiry, policy version and unique execution ID. Grant each adapter only the privileges needed for its action. Separate authority to stop a process from authority to disable a domain account. Retain local permission gates and administrator authentication for disruptive operator actions.

Exclude recovery administrators, core services, domain-controller functions, security agents and the response service from default automation. Do not automatically disable root, SYSTEM, shared service accounts or privileged identities merely because they own a process. Allowlist decisions must use verified identity evidence. Add rate limits, a global stop control and a circuit breaker for widespread triggers or degraded telemetry. An LLM recommendation or remote canary callback alone must not authorize a destructive response.

Persist intent before execution and distinguish requested, dispatched, verified, failed, expired and indeterminate outcomes. An API success is not proof of containment; verify the effect. Do not retry an indeterminate destructive action blindly. For reversible restrictions, record previous state and ownership so recovery cannot overwrite a newer administrator change. Account re-enablement requires review; do not blindly re-enable a possibly compromised account when a timer expires.

Standing administrative-access requirement: keep the original privileged session open through ACL, management-firewall or credential changes. Verify a separate fresh session from the affected authorized source, its target-seen address and required privileges before closing the original. Test both intended denial and authorized recovery access. Roll back or correct failed access checks while retaining the original session; report untested paths.

## Delivery and acceptance

1. Inventory the existing response code and deployed capability versions; qualify exact identity binding, durable delivery and executable acquisition for each supported platform and source.
2. Build preview and operator-driven resource blocking/process termination in isolated test systems. Use owned actor processes and disposable files only.
3. Add account disabling and session revocation against disposable local and test-directory users with a separate verified recovery account.
4. Exercise false positives, impersonation, PID reuse, process exit/replacement, protected identities, expired/replayed commands, offline agents, lost receipts, restart recovery, concurrent administrator changes and rollback failures.
5. Complete the repository's functional, edge-case/regression and UI/runtime QA passes. Verify containment and unrelated application/administrative access independently. Record unsupported paths as pending.
6. Roll out observation first, then narrowly scoped operator responses. Enable each automatic policy only after representative false-positive and recovery tests; broader containment follows separately.

## Implementation references

Windows termination must wait for confirmed process exit; the call can return before termination completes. See [Microsoft TerminateProcess documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).

Wazuh supports custom one-time and time-limited responses. Match the adapter to the installed Wazuh version and test its actual command/receipt contract; do not infer rollback from a configured timeout alone. See [Wazuh custom active responses](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html).
