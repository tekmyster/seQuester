# Windows actor-capture driver packaging

The driver supplements Windows Security auditing with operation-time request-thread
and CREATE authorization evidence. Audit events cannot be retroactively enriched
with an accessing thread token that the event source never recorded.

## Components

- `SeQuesterActor.legacy.inf.in`: Server 2012 R2 / Server 2019 x64, downlevel service installation.
- `SeQuesterActor.modern.inf.in`: Windows 10 22H2 x64 primitive package, using the Driver Store.
- `../../tools/build-windows-kernel-package.ps1`: preserves the supplied driver bytes,
  verifies their expected SHA-256, renders both INFs, runs WDK InfVerif and Inf2Cat,
  and writes a file-hash manifest in a new directory.
- `../../tools/test-windows-kernel-package.ps1`: checks package integrity and refusal
  paths, including hash mismatches, unsafe INF input, missing assignment evidence,
  and attempts to overwrite existing output.

The builder does not install, load, sign, enable, or certify a driver. Its output
always records `ProductionReady: false`. InfVerif and Inf2Cat success do not establish
HLK certification or permission to use a test altitude in production.

## Altitude and signing

The October 1, 2026 request for Tekmyster Industries, LLC was submitted from
daniel@tekmyster.com to fsfcomm@microsoft.com. The outbound relay accepted it and
the sent copy was verified. Microsoft assignment is pending. `385200.923` remains
an isolated test value only. Never label it as an assigned production altitude.

For a Microsoft-assigned value, the builder requires the reviewed correspondence
and its expected SHA-256. This records the operator's reviewed evidence; the
builder does not authenticate email or issue an allocation. Archive the original
assignment independently. A changed altitude requires a new INF/catalog and renewed
installation/coexistence checks. Microsoft signing follows the supported
HLK/dashboard route for the servers. An attestation signature for Windows desktop
is not the Server 2019 signing route.

## Installation qualification

Use only UUID-bound, disconnected VMware guests for the current self-signed test
package. Production boot policy and installed audit monitoring remain unchanged.

On Windows 10, use `DiInstallDriverW` and inspect its return value, native error,
and reboot-required flag. The first qualification attempt using a legacy rundll32
entry point returned without establishing the required instance registration;
process exit alone was correctly rejected as insufficient evidence of installation.

For the downlevel server qualification harness, the exact verified driver bytes are
copied to the driver directory and `SetupInstallServicesFromInfSectionW` processes
the legacy INF service section. Its native error and restart-required result are
checked. The earlier legacy launcher also returned without registering the required
instance on Server 2012 R2; that attempt remains failed. These are isolated
installation checks starting from the existing test-driver setup, not a claim of
clean-machine production installation or Microsoft catalog trust. Independently
verify service type, demand start, Filter Manager dependency, actual image path/hash,
default instance, altitude, driver load/unload, and fresh operation/token observations.

Do not enable `windows-kernel.enabled` on a live sensor until the signed driver,
assigned altitude, supported OS/I/O scope, service integration, and server receipt
have been accepted together. Retain auditing as an independent source, with missing
thread-token evidence explicitly unavailable.

## Qualified scope

Current operation/token qualification is for local NTFS exact paths on x64 builds
6.3.9600.18734, 10.0.17763.9020, and 10.0.19045.6456. It is not a claim about every
Windows version, every filesystem, every I/O path, or HLK certification. Null-thread,
higher-IRQL, paging/cache-worker, remote origin, full memory-map, and sustained-load
coverage retain the limitations in `../../docs/WINDOWS-KERNEL-CAPTURE.md`.

## Primary references

- [Microsoft altitude request process](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request)
- [Minifilter INF requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver)
- [Primitive drivers and downlevel compatibility](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-primitive-driver)
- [InstallHinfSection restart modes](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-installhinfsectionw)
- [INF service installation and native status](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupinstallservicesfrominfsectionw)
- [Microsoft driver signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)
- [File-system/minifilter tests under Filter.Driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs)
