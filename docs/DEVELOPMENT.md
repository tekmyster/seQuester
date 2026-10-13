# Development guide

## Repository conventions

Source folders and project files use `seQuester`. Keep existing assembly names, namespaces, service names, API identifiers and database keys stable unless a scoped compatibility change is required. User-facing documentation uses **seQuester**, **Sensors**, **actor executable** and **target file** consistently.

Read [AGENTS.md](../AGENTS.md) and the [Product UX Contract](PRODUCT-UX-CONTRACT.md) before changing UI. Preserve existing business logic, security requirements, accessibility and diagnostic access while improving presentation.

The GitHub repository began as a clean development snapshot. Historical local commits were not imported because they contained generated artifacts, including a test certificate archive. Credentials, evidence binaries and deployment captures stay outside Git.

## Build and test boundaries

Use .NET 10 for managed projects and the required native toolchain for the platform component. Keep generated output in a separate artifact directory.

The release runner is `tools/test-release.ps1`; it accepts a published server and results directory and runs the listed fixtures plus UX checks. Review its configured executable paths before using it on a different machine. Individual fixture projects can be built and executed separately.

| Test area | Representative fixtures |
| --- | --- |
| Server, authentication and persistence | `tests/seQuester.Server.Tests` |
| Canary generation/receiver behavior | `tests/seQuester.Canary.Tests`, `tools/CanaryDocumentFixture` |
| Trust and whitelist matching | `tools/WhitelistFixture`, `tools/AdvancedTrustFixture`, `tools/TrustGovernanceFixture` |
| Event history and presentation | `tools/EventHistoryFixture`, `tools/ActivityContractFixture` |
| Forensic acquisition and transfer | `tools/ForensicFixture`, `tools/EvidenceTransferFixture` and platform acquisition fixtures |
| Linux native I/O bindings | `tools/LinuxIoFixture` |
| Response identity, policy and journal | `tools/NativeResponseFixture` |
| Syslog storage receipts | `tools/SyslogReceiptFixture` |
| Wazuh collector | `packaging/wazuh/test_receiver.py` |

Run tests relevant to a change and required release gates. Separate compile, fixture, native-host, browser, deployment and end-to-end results. A synthetic frame or mocked response is useful contract evidence but not an OS capture result.

## UX checks

```powershell
node tools/check-product-ux.mjs --self-test
node tools/check-product-ux.mjs src/seQuester.Server/wwwroot/index.html
```

The mechanical checker flags deterministic issues such as obvious raw-object presentation or prohibited placeholder copy. It does not replace editorial review, actual browser inspection, keyboard testing or mobile/state coverage.

Keep technical detail in labelled evidence, explicit diagnostics, logs and developer documentation. Do not move internal values into normal labels or change API keys to improve copy.

## Capture documentation screenshots

`tools/capture-documentation.mjs` starts an isolated localhost server, creates synthetic documentation data, signs in, captures the interface and stops its owned process. It never connects to the deployment host.

Prerequisites: a published development server, Node.js, Playwright and Chromium. Set `SEQUESTER_DOC_SERVER_DLL` to the absolute DLL path. Optional variables select the .NET executable, Playwright module and Chromium executable. The capture tool removes inherited database, certificate and callback deployment settings from the child process.

```powershell
$env:SEQUESTER_DOC_SERVER_DLL='C:\Builds\sequester\RansomFree.Server.dll'
node tools/capture-documentation.mjs docs/screenshots
```

The script generates its own bootstrap key and administrator password in memory. It stores isolated runtime state in the OS temporary directory outside Git for review. Screenshots must not show real credentials, enrollment codes, recovery codes, token URLs or customer evidence.

Review every image before committing it. `capture.json` records the actual reported server version, capture time, sample-data scope and browser checks. It is not a native forensic qualification report.

## Maintain documentation

1. Confirm current behavior against the route, contract or implementation.
2. Use workflow names that match the interface.
3. Keep current product guides separate from chronological engineering logs.
4. Update [Capabilities](CAPABILITIES.md) when implementation, qualification or deployment changes.
5. Refresh affected screenshots from the same source/build and label synthetic data.
6. Check links, image references, examples and required security information.
7. Report unresolved defects without turning the guide into a warning-filled status log.

Do not assign an arbitrary completion percentage. Use specific implemented, tested, deployed and pending states with evidence instead.

## Evidence-preserving engineering

Capture ephemeral identities early. Perform expensive hashing, signature validation and upload asynchronously where safe. Bind enrichment to the original process/file instance and keep owner and effective identity distinct.

Hash and preserve the actor executable. Do not enable indiscriminate target-file hashing or copying. Preserve raw source/error status where useful, explicit collection failures and stable reason codes.

New native code needs reproducible build inputs, versioned protocols and tests for PID reuse, short-lived processes, rename/replacement races, signature states, impersonation, preservation integrity/failure, operation outcomes and high-volume caching.

Administrative ACL, credential or management-firewall changes must follow the fresh-session rule in [Deployment and operations](DEPLOYMENT-AND-OPERATIONS.md).
