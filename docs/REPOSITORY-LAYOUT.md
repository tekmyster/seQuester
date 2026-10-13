# Repository layout

The October 13, 2026 layout change replaces the `RansomFree` prefix with `seQuester` in source/test folders and project filenames. It applies to the GitHub repository and the current local development checkout.

## Structure

```text
seQuester.csproj
src/
  seQuester.Agent/
  seQuester.AuditRelay/
  seQuester.Client/
  seQuester.Contracts/
  seQuester.DecoyHost/
  seQuester.LinuxAgent/
  seQuester.LinuxKernel/
  seQuester.MacAgent/
  seQuester.Receiver/
  seQuester.Server/
  seQuester.Tray/
  seQuester.UnixDesktop/
  seQuester.WindowsDecoys/
  seQuester.WindowsKernel/
tests/
  seQuester.Canary.Tests/
  seQuester.Server.Tests/
  seQuester.WindowsSyscall.Tests/
tools/
packaging/
docs/
Assets/
```

Managed project filenames match their new folder names, for example `src/seQuester.Server/seQuester.Server.csproj`. The desktop project is `seQuester.csproj`. Native source folders use the same prefix but retain their existing native build inputs.

## Build examples

```powershell
dotnet build seQuester.csproj -c Release
dotnet build src/seQuester.Server/seQuester.Server.csproj -c Release
dotnet build src/seQuester.Agent/seQuester.Agent.csproj -c Release
dotnet build src/seQuester.LinuxAgent/seQuester.LinuxAgent.csproj -c Release
```

Update local scripts, IDE shortcuts and explicit project paths to these locations. Existing generated output may refer to the former paths; rebuild from the renamed projects.

## Compatibility

Each renamed managed project explicitly preserves its original assembly name and root namespace. Build output therefore retains identifiers such as `RansomFree.Server.dll` and `RansomFree.Agent.exe` used by installers, services and integrations.

Project references, packaging/build scripts, QA tools, source links and the UX checker's file selection use the new source paths. The release runner distinguishes the project filename from the preserved assembly filename.

This is a source-layout change. Installed service names and paths, API routes, event schemas, credentials, databases, evidence stores and native driver identities are not migrated by it. Existing deployments continue to use their accepted packages.

Historical worktrees and build/acceptance archives retain their recorded layout. The current working checkout and published repository use the layout above.
