# Capability register

Updated October 13, 2026 from the published source, current integration checkpoint and recorded acceptance artifacts. This documentation review did not recheck live deployment or perform a new all-host forensic test.

**Implemented** means a source path exists. **Qualified** means a stated test passed within its recorded scope. **Deployed** refers to a recorded activation. These states are not interchangeable.

## Application features

| Area | Present in the application | Material boundary |
| --- | --- | --- |
| Sensor management | Enrollment, revocation, inventory, OS icons, status colors, contact/version and monitoring reports. | A heartbeat or enrollment does not qualify native capture. |
| Local honeypots | Generated/imported files, approved folder deployment and source-dependent operation monitoring. | Actor and operation coverage vary by platform and source. |
| Canary management | Database-tracked tokens, artifact downloads, metadata, revocation and callback history. | Consumer applications may block external resource use; all-type opening acceptance remains open. |
| Event investigation | Filters, columns, sorting, paging, user/process/PID and structured evidence disclosure. | Three present actor fields do not establish complete forensics. |
| Incidents | Linked events, analyst severity, status, assignment, notes and exports. | Analyst classification is not an automatic malware verdict. |
| Reports | Saved snapshots, text/PDF export and report schedules. | Scheduled storage does not imply email distribution. |
| Identity | Local roles, password policy, MFA/recovery and configured directory/SSO paths. | External provider configuration and enterprise deployment gates remain separate. |
| Policies | Group settings, deployments, revisions, assignments, receipts and history. | Published, received and successfully applied are different states. |
| Whitelists | No-event creation, user/process/AND rules, operation restrictions, path-plus-hash Windows matching and always-alert precedence. | New advanced controls are in an undeployed candidate. |
| Service decoys/jobs | Managed service decoys and Windows virtual-resource jobs with approval, receipt and history views. | Native job execution and resource coverage require platform-specific acceptance. |
| Evidence | Versioned metadata, actor hashing/preservation, upload protocol and source-linked retrieval. | Immediate first-use and rare execution-context preservation are not universally reliable. |
| Responses | Legacy process-stop paths; new policy, preview, journaling and capability controls. | Full native response chain and broader enforcement adapters remain unfinished. |
| Notifications | Canary SMTP, server syslog categories, delivery diagnostics and candidate TLS receipt controls. | Cross-host production Wazuh delivery is not working reliably. |
| Operational visibility | Service/source and delivery status views. | Full operational-log export to Wazuh remains open. |

## Version and deployment reference

| Component | Source version | Last recorded deployment reference |
| --- | --- | --- |
| Management server | `0.6.45-dev` | Runtime 0.6.45; UI `decoy-history-20261012-r2`. |
| Windows sensor | `0.6.26-dev` | Four Windows sensors on 0.6.26 in the recorded checkpoint. |
| Linux sensor | `0.9.43-linux-dev` | Twenty-six Linux sensors on 0.9.43 in the recorded checkpoint. |

Inventory also contains historical identities. Do not count every inventory row as a deployed sensor. These figures are historical checkpoint references, not live measurements made for this documentation update.

## Windows forensic boundary

The implemented pipeline can retain process-instance, executable, target, security-context and preservation evidence. Native minifilter and other source-specific records improve attribution beyond audit-only collection.

Open items include consistent accessing-thread identity in unsupported/missing callback contexts, complete failed-operation coverage, live sensor reporting for the private syscall source and immediate actor acquisition/preservation under every required race condition. Successful private native tests, managed replay and owned-child response tests do not close these items across deployed hosts.

In particular, rejection of an initial open does not prove capture of a later failed read, write, rename or delete on an already-open handle. Each operation/result combination requires its own independent actor truth and server receipt.

## Linux forensic boundary

Audit and native capture, held-executable acquisition, immutable actor/target contracts and exact-operation paths are represented in source and historical acceptance work. Kernel support and operation coverage remain source/version-specific.

The new read/write/append SHA-256 whitelist binding has 130 fixture checks using synthetic frames and actual held descriptors. Live native pairing qualification and deployment remain open. Permission-hook result evidence must not be described as final syscall success or failure without a completed-operation source.

## Open integration work

Commercial licensing is also open: the [third-party notices](../THIRD-PARTY-NOTICES.md) identify GPL-marked Linux capture source, libbpf/libauparse imports, custom Microsoft native licenses and other bundled native materials outside the new MIT/Apache-2.0-only policy. The automated license audit rejects these conflicts. Ownership headers and a proprietary license do not resolve or relicense them.

| Work | Current state | What closes it |
| --- | --- | --- |
| Native active response | Policy/preview, exact target binding, durable journal and capability gates implemented. Owned-child legacy Windows termination tested. | Live native event-to-preservation-to-command execution with exact process exit and recovery checks. |
| Additional whitelist controls | Single-rule OR, principal selection, directory scope and temporary process-instance rules implemented in the candidate. | Fresh parser/readiness gates, acceptance on installed sources, release activation and sensor receipts. |
| Linux operation hash whitelisting | Source-bound hash-only read/write/append mode and original-entry pairing implemented. | Native kernel/source qualification, missing/wrong hash controls and controlled deployment. |
| Wazuh transport | Manager-local storage, alert suppression/detection and indexing tested. | Reliable cross-host durable receipt from the production service account, indexing, interruption/replay and log coverage. |
| Resource/account/session/host response | Planned adapters and explicit unsupported gates. | Implemented scoped action, independent outcome validation, recovery and authorization tests. |
| Responsive filtering | Requested follow-up after the four integrations. | 400 ms text debounce, cancellation/stale-response guards, background results, appropriate loading/action disabling, caching and retry acceptance. |

The Wazuh sender still stalls after TLS negotiation. Temporary source grants were rolled back; production forwarding remains disabled. The cause is unconfirmed. A larger VM or a successful handshake does not establish delivery.

## Local file templates

`CanaryTemplates.Types` defines **11 local file formats**:

DOCX, XLSX, PDF, TXT, CSV, RTF, HTML, SVG, JSON, XML and Markdown.

Imported templates are limited to DOCX, XLSX and PDF with their original type. Embedded callback configuration is supported for DOCX, XLSX, PDF, HTML and SVG. The other formats use local monitoring unless another explicit mechanism supplies a trigger.

Historical references to “14 file types” describe a requested test scope. They are not the current local template enumeration and do not demonstrate completed consumer-opening tests.

## Callback catalog

The source catalog contains **32 mechanisms**: 19 labelled **Implemented; untested**, 7 **Provider required**, and 6 **Pending**. These are the catalog's literal qualification states, not a claim that all 19 work in every application. Receiver/protocol tests and application-opening tests are distinct.

| State | Mechanisms |
| --- | --- |
| Implemented; untested | Word, Excel, Acrobat PDF, SVG, web image, web bug, DNS, QR code, fast redirect, slow redirect, Windows folder, network folder, JavaScript clone, CSS clone, kubeconfig, MCP configuration, MySQL, unique email address, Log4shell. |
| Provider required | Entra login, SAML application, fake application, AWS keys, AWS infrastructure, Azure login certificate, credit card. |
| Pending | Windows fake filesystem, sensitive command, custom executable/binary, WireGuard, Microsoft SQL Server, SVN. |

Source: `src/seQuester.Server/CallbackManagement.cs`. Exact trigger descriptions are shown by the application catalog. Provider-required entries need a configured external service; they do not become operational through local artifact generation.

## Verification reference

The recorded integration candidate passed 28 release groups after the latest transport change, as listed in the local `regression-r2/REGRESSION.json` acceptance artifact. Component checks include 66 advanced trust/policy, 218 whitelist, 130 Linux evidence, 16 response-journal/process, 19 Linux receiver, 18 loopback transport and 22 browser checks.

Those counts describe their individual scopes. They are not an all-host native forensic or production Wazuh pass. This documentation update adds isolated screenshot checks, not new endpoint qualification.

## Known UI issue found during documentation review

Revisiting Overview can show a request error even though the summary request succeeds. `incidents.js` replaces the second insight card, removing `overview-informational`; `console.js` still writes to that field on subsequent overview loads. The error was reproduced in the isolated build and remains unresolved by this documentation-only change.

The Overview screenshot shows the successful initial view. It does not imply that refresh is fixed. Existing sensor-table horizontal scrolling and long advanced-settings pages are represented as they render; no UI redesign is included in this update.

## Acceptance required before “complete”

For each supported host/source, match independent actor identity and actual operation results against server events. Check owner/effective identity separately, reject PID reuse and wrong executable bindings, preserve and retrieve matching actor bytes, and exercise short-lived/replaced/deleted actors, denied opens and later failed operations.

Verify permitted whitelist operations remain logged without alerts and adjacent operations still alert. Verify response completion rather than queue admission. Verify SIEM storage, indexing and alerting independently. Record unavailable contexts and failures explicitly.
