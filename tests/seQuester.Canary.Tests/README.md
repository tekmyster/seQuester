# Canary local integration harness

Run only on an authorized development host. This executable starts a synthetic-admin management host and the actual receiver, all on random loopback ports, using isolated SQLite databases and synthetic credentials. It never follows redirects or resolves token hostnames through the system resolver. SMTP uses an exact generated-certificate pin, not a global trust bypass. No production authentication is tested.

From the repository root in PowerShell:

```powershell
New-Item -ItemType Directory -Path 'D:\Codex\RansomFree\temp' -Force | Out-Null
$env:TEMP='D:\Codex\RansomFree\temp'
$env:TMP=$env:TEMP
$qaDotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe'
& $qaDotnet build tests/seQuester.Canary.Tests/seQuester.Canary.Tests.csproj -c Release --artifacts-path 'D:\Codex\RansomFree\artifacts'
if ($LASTEXITCODE -ne 0) { throw 'Harness build failed' }
& $qaDotnet build src/seQuester.Receiver/seQuester.Receiver.csproj -c Release --artifacts-path 'D:\Codex\RansomFree\artifacts'
if ($LASTEXITCODE -ne 0) { throw 'Receiver build failed' }
& $qaDotnet 'D:\Codex\RansomFree\artifacts\bin\seQuester.Canary.Tests\release\RansomFree.Canary.Tests.dll' $qaDotnet 'D:\Codex\RansomFree\artifacts\bin\seQuester.Receiver\release\RansomFree.Receiver.dll'
```

Prefer direct DLL execution with absolute paths; `dotnet run` changes the working directory. Results default to `D:\Codex\RansomFree\test-results\canaries\<unique-id>` when D: exists. Set RF_QA_RESULTS to override. Each run preserves its own artifacts/logs/databases and stops only its own receiver. Random port reservation has a small bind race; a bind failure is a failed setup, not a product pass. Windows SMTP may create OS-managed temporary crypto key material outside this directory; no trust-store installation is performed.

Latest run: 260 passing assertions, zero failures. This is not 260 independent feature acceptance tests. Consult QA.md for all 19 mechanism rows and pending native reader, external delivery, UI, SQL Server, Linux, service identity and packaged-app checks. QR is signature-checked, not decoded; web/document callbacks are manually invoked, not proof of reader activation. Do not use generated specimens in live folders.
