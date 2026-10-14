# seQuester

Endpoint honeypot monitoring, canary callbacks, process attribution and forensic evidence collection, with a central management server and web interface.

## License

Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.

seQuester uses a [proprietary commercial license](PRIVATE-LICENSE.md). Public source access does not grant an open-source license. Core library policy permits MIT and Apache-2.0; the [third-party notices](THIRD-PARTY-NOTICES.md) record exact dependencies and existing conflicts that still prevent a compliant release.

## Documentation

Start with the [documentation index](docs/README.md).

- [User guide](docs/USER-GUIDE.md): monitoring, investigation, canaries and reports.
- [Administrator guide](docs/ADMINISTRATOR-GUIDE.md): enrollment, policies, whitelists and delivery.
- [Deployment and operations](docs/DEPLOYMENT-AND-OPERATIONS.md): installation, upgrades and recovery.
- [Architecture and evidence](docs/ARCHITECTURE-AND-EVIDENCE.md) and [API guide](docs/API-GUIDE.md).
- [Capability register](docs/CAPABILITIES.md): implemented features, acceptance boundaries and open work.
- [Screenshot reference](docs/SCREENSHOTS.md) and [Development guide](docs/DEVELOPMENT.md).

![Sensors with synthetic Windows and Linux documentation data](docs/screenshots/sensors-desktop.png)

The screenshot shows an isolated development build, not production telemetry.

## Project layout

| Directory | Contents |
| --- | --- |
| `src/seQuester.Server` | Management server, persistence and web UI |
| `src/seQuester.Receiver` | Canary callback receiver |
| `src/seQuester.Agent` | Windows sensor service |
| `src/seQuester.LinuxAgent` | Linux sensor |
| `src/seQuester.Contracts` | Shared event and policy contracts |
| `src/seQuester.WindowsKernel` | Windows native capture source |
| `src/seQuester.LinuxKernel` | Linux native capture source |
| `packaging` | Platform packaging and configuration templates |
| `tests`, `tools` | Tests, fixtures and build tools |
| `docs` | Architecture, feature plans, operational guidance and UX contract |

Folders and project files use the `seQuester` prefix. Assembly names, namespaces and installed service paths retain their existing identifiers for compatibility. See the [layout migration](docs/REPOSITORY-LAYOUT.md).

## Build

Managed projects require the .NET 10 SDK. Windows projects require Windows build support. Native components have separate platform toolchain requirements described in their documentation.

```powershell
dotnet build src/seQuester.Server/seQuester.Server.csproj -c Release
dotnet build src/seQuester.Agent/seQuester.Agent.csproj -c Release
dotnet build src/seQuester.LinuxAgent/seQuester.LinuxAgent.csproj -c Release
```

Build and packaging scripts are in `tools`. Some scripts use local Windows tool paths and must be configured for the build machine. Configuration templates are provided under `packaging`; supply deployment credentials separately.

## Implementation status

This repository contains the current development source snapshot, including work in progress. Publishing it does not deploy or qualify a release.

See the [capability register](docs/CAPABILITIES.md) for current status. [FEATURES.md](FEATURES.md), [current open work](docs/CURRENT-OPEN-WORK.md) and the [integration checkpoint](docs/RESPONSE-POLICY-INTEGRATION-20261012.md) retain detailed engineering history. Active response, additional whitelist controls, Linux native hash-based whitelisting and Wazuh integration still have outstanding acceptance or integration work. Responsive filtering improvements remain queued.

## Publication contents

The initial commit is a clean snapshot rather than an import of historical local commits. It includes source, required assets, configuration templates, tests and project documentation. Credentials, private certificates, executable evidence, generated test captures and build output are excluded. Existing deployment data stays outside this repository.

UI changes must follow [AGENTS.md](AGENTS.md) and the [Product UX Contract](docs/PRODUCT-UX-CONTRACT.md).
