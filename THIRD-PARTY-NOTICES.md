<!--
// Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.
// seQuester — Proprietary Commercial License.
-->

# Third-party notices

## Policy

seQuester first-party source uses the [proprietary commercial license](PRIVATE-LICENSE.md). Approved core library licenses are **MIT** and **Apache-2.0**. Upstream copyrights and license terms remain intact. A package's permissive wrapper license does not automatically approve every embedded native component.

This inventory was assembled on October 13, 2026 from the eight application package lockfiles and exact-version NuGet metadata in the restored package cache. It covers 107 locked package/version pairs, including desktop runtime variants. Tests, tools, SDK/runtime internals and all nested native materials are not represented as fully audited by this table.

**Current source does not yet satisfy the strict policy.** The conflicts below are release blockers, not approved exceptions. Adding notices does not authorize redistribution under an incompatible license.

## Confirmed conflicts and required review

| Component | Evidence | Policy result |
| --- | --- | --- |
| Microsoft.Data.SqlClient.SNI.runtime 6.0.2 | Package LICENSE.txt contains Microsoft Software License Terms. | Not MIT/Apache-2.0; replace or obtain an explicit policy decision. |
| Microsoft.Identity.Client.NativeInterop 0.20.6 | Package LICENSE contains Microsoft Software License Terms. | Not MIT/Apache-2.0; replace or obtain an explicit policy decision. |
| Avalonia.Angle.Windows.Natives 2.1.27548.20260419 | Packaged LICENSE uses BSD-style redistribution terms. | Outside the allowlist. |
| Linux actor-lease modules, BPF programs and supporting source | GPL-2.0-only SPDX declarations and GPL module/program declarations in src/seQuester.LinuxKernel. | Conflicts with proprietary-only core source policy; preserve declarations until a valid architectural/licensing resolution. |
| libbpf | Direct imports in seQuester.Client and native loaders; upstream LGPL-2.1-only OR BSD-2-Clause. | Neither license is MIT/Apache-2.0; not approved. |
| libauparse | Direct imports in seQuester.LinuxAgent/AuditParser.cs; upstream LGPL-2.1-or-later. | Not approved. |
| SQLite native engine | Included through SQLitePCLRaw native packages; upstream public-domain dedication. | Not one of the two specified licenses; requires a policy decision or replacement. |
| Skia native engine and embedded graphics materials | SkiaSharp package metadata is MIT; upstream Skia uses BSD terms and includes third-party materials. | Wrapper approval is insufficient; native material review remains open. |

Linux BPF LSM programs require GPL-compatible licensing according to the [kernel documentation](https://docs.kernel.org/bpf/bpf_licensing.html). Removing a GPL declaration without resolving that requirement is not a valid repair. [libbpf's upstream license](https://github.com/libbpf/libbpf/blob/master/LICENSE) and [libauparse's source notice](https://github.com/linux-audit/audit-userspace/blob/v3.0.7/auparse/auparse.c) identify the library terms. [SQLite's copyright page](https://www.sqlite.org/copyright.html) and [Skia's license](https://skia.googlesource.com/skia/+/refs/heads/main/LICENSE) describe those native materials.

Operating-system APIs and separately installed host tools are distinct from first-party source and bundled libraries. That distinction does not automatically approve direct third-party library imports or remove their license obligations.

## Application package inventory

The License column records the package's declared expression or reviewed file-based terms. It is not a blanket approval of embedded material. Upstream package downloads contain the authoritative license and notices; retain them with distributed artifacts.

| Package | Version | Declared license | Upstream package |
| --- | --- | --- | --- |
| Avalonia | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia/12.1.2) |
| Avalonia.Angle.Windows.Natives | 2.1.27548.20260419 | BSD-style (LICENSE) | [NuGet](https://www.nuget.org/packages/Avalonia.Angle.Windows.Natives/2.1.27548.20260419) |
| Avalonia.BuildServices | 11.3.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.BuildServices/11.3.2) |
| Avalonia.Desktop | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Desktop/12.1.2) |
| Avalonia.FreeDesktop | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.FreeDesktop/12.1.2) |
| Avalonia.FreeDesktop.AtSpi | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.FreeDesktop.AtSpi/12.1.2) |
| Avalonia.HarfBuzz | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.HarfBuzz/12.1.2) |
| Avalonia.Native | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Native/12.1.2) |
| Avalonia.Remote.Protocol | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Remote.Protocol/12.1.2) |
| Avalonia.Skia | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Skia/12.1.2) |
| Avalonia.Themes.Fluent | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Themes.Fluent/12.1.2) |
| Avalonia.Win32 | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.Win32/12.1.2) |
| Avalonia.X11 | 12.1.2 | MIT | [NuGet](https://www.nuget.org/packages/Avalonia.X11/12.1.2) |
| Azure.Core | 1.50.0 | MIT | [NuGet](https://www.nuget.org/packages/Azure.Core/1.50.0) |
| Azure.Identity | 1.17.1 | MIT | [NuGet](https://www.nuget.org/packages/Azure.Identity/1.17.1) |
| HarfBuzzSharp | 8.3.1.3 | MIT | [NuGet](https://www.nuget.org/packages/HarfBuzzSharp/8.3.1.3) |
| HarfBuzzSharp.NativeAssets.Linux | 8.3.1.3 | MIT | [NuGet](https://www.nuget.org/packages/HarfBuzzSharp.NativeAssets.Linux/8.3.1.3) |
| HarfBuzzSharp.NativeAssets.macOS | 8.3.1.3 | MIT | [NuGet](https://www.nuget.org/packages/HarfBuzzSharp.NativeAssets.macOS/8.3.1.3) |
| HarfBuzzSharp.NativeAssets.WebAssembly | 8.3.1.3 | MIT | [NuGet](https://www.nuget.org/packages/HarfBuzzSharp.NativeAssets.WebAssembly/8.3.1.3) |
| HarfBuzzSharp.NativeAssets.Win32 | 8.3.1.3 | MIT | [NuGet](https://www.nuget.org/packages/HarfBuzzSharp.NativeAssets.Win32/8.3.1.3) |
| MicroCom.Runtime | 0.11.6 | MIT | [NuGet](https://www.nuget.org/packages/MicroCom.Runtime/0.11.6) |
| Microsoft.AspNetCore.Authentication.OpenIdConnect | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.OpenIdConnect/10.0.12) |
| Microsoft.AspNetCore.Identity.EntityFrameworkCore | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.AspNetCore.Identity.EntityFrameworkCore/10.0.12) |
| Microsoft.Bcl.AsyncInterfaces | 8.0.0 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Bcl.AsyncInterfaces/8.0.0) |
| Microsoft.Bcl.Cryptography | 10.0.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Bcl.Cryptography/10.0.2) |
| Microsoft.Data.SqlClient | 6.1.6 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Data.SqlClient/6.1.6) |
| Microsoft.Data.SqlClient.SNI.runtime | 6.0.2 | Microsoft Software License Terms | [NuGet](https://www.nuget.org/packages/Microsoft.Data.SqlClient.SNI.runtime/6.0.2) |
| Microsoft.Data.Sqlite | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Data.Sqlite/10.0.12) |
| Microsoft.Data.Sqlite.Core | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Data.Sqlite.Core/10.0.12) |
| Microsoft.EntityFrameworkCore | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore/10.0.12) |
| Microsoft.EntityFrameworkCore.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Abstractions/10.0.12) |
| Microsoft.EntityFrameworkCore.Analyzers | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Analyzers/10.0.12) |
| Microsoft.EntityFrameworkCore.Relational | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Relational/10.0.12) |
| Microsoft.EntityFrameworkCore.Sqlite | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Sqlite/10.0.12) |
| Microsoft.EntityFrameworkCore.Sqlite.Core | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Sqlite.Core/10.0.12) |
| Microsoft.EntityFrameworkCore.SqlServer | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.SqlServer/10.0.12) |
| Microsoft.Extensions.Configuration | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration/10.0.12) |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.Abstractions/10.0.12) |
| Microsoft.Extensions.Configuration.Binder | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.Binder/10.0.12) |
| Microsoft.Extensions.Configuration.CommandLine | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.CommandLine/10.0.12) |
| Microsoft.Extensions.Configuration.EnvironmentVariables | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.EnvironmentVariables/10.0.12) |
| Microsoft.Extensions.Configuration.FileExtensions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.FileExtensions/10.0.12) |
| Microsoft.Extensions.Configuration.Json | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.Json/10.0.12) |
| Microsoft.Extensions.Configuration.UserSecrets | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Configuration.UserSecrets/10.0.12) |
| Microsoft.Extensions.DependencyInjection | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.DependencyInjection/10.0.12) |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.DependencyInjection.Abstractions/10.0.12) |
| Microsoft.Extensions.DependencyModel | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.DependencyModel/10.0.12) |
| Microsoft.Extensions.Diagnostics | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Diagnostics/10.0.12) |
| Microsoft.Extensions.Diagnostics.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Diagnostics.Abstractions/10.0.12) |
| Microsoft.Extensions.FileProviders.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.FileProviders.Abstractions/10.0.12) |
| Microsoft.Extensions.FileProviders.Physical | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.FileProviders.Physical/10.0.12) |
| Microsoft.Extensions.FileSystemGlobbing | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.FileSystemGlobbing/10.0.12) |
| Microsoft.Extensions.Hosting | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Hosting/10.0.12) |
| Microsoft.Extensions.Hosting.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Hosting.Abstractions/10.0.12) |
| Microsoft.Extensions.Hosting.WindowsServices | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Hosting.WindowsServices/10.0.12) |
| Microsoft.Extensions.Logging | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging/10.0.12) |
| Microsoft.Extensions.Logging.Abstractions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.Abstractions/10.0.12) |
| Microsoft.Extensions.Logging.Configuration | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.Configuration/10.0.12) |
| Microsoft.Extensions.Logging.Console | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.Console/10.0.12) |
| Microsoft.Extensions.Logging.Debug | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.Debug/10.0.12) |
| Microsoft.Extensions.Logging.EventLog | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.EventLog/10.0.12) |
| Microsoft.Extensions.Logging.EventSource | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Logging.EventSource/10.0.12) |
| Microsoft.Extensions.Options | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Options/10.0.12) |
| Microsoft.Extensions.Options.ConfigurationExtensions | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Options.ConfigurationExtensions/10.0.12) |
| Microsoft.Extensions.Primitives | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Extensions.Primitives/10.0.12) |
| Microsoft.Identity.Client | 4.84.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Identity.Client/4.84.2) |
| Microsoft.Identity.Client.Broker | 4.84.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Identity.Client.Broker/4.84.2) |
| Microsoft.Identity.Client.Extensions.Msal | 4.78.0 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Identity.Client.Extensions.Msal/4.78.0) |
| Microsoft.Identity.Client.NativeInterop | 0.20.6 | Microsoft Software License Terms | [NuGet](https://www.nuget.org/packages/Microsoft.Identity.Client.NativeInterop/0.20.6) |
| Microsoft.IdentityModel.Abstractions | 8.14.0 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Abstractions/8.14.0) |
| Microsoft.IdentityModel.Abstractions | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Abstractions/8.19.2) |
| Microsoft.IdentityModel.JsonWebTokens | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens/7.7.1) |
| Microsoft.IdentityModel.JsonWebTokens | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens/8.19.2) |
| Microsoft.IdentityModel.Logging | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Logging/7.7.1) |
| Microsoft.IdentityModel.Logging | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Logging/8.19.2) |
| Microsoft.IdentityModel.Protocols | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols/7.7.1) |
| Microsoft.IdentityModel.Protocols | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols/8.19.2) |
| Microsoft.IdentityModel.Protocols.OpenIdConnect | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols.OpenIdConnect/7.7.1) |
| Microsoft.IdentityModel.Protocols.OpenIdConnect | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Protocols.OpenIdConnect/8.19.2) |
| Microsoft.IdentityModel.Tokens | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/7.7.1) |
| Microsoft.IdentityModel.Tokens | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/8.19.2) |
| Microsoft.SqlServer.Server | 1.0.0 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.SqlServer.Server/1.0.0) |
| Microsoft.Win32.SystemEvents | 6.0.0 | MIT | [NuGet](https://www.nuget.org/packages/Microsoft.Win32.SystemEvents/6.0.0) |
| PDFsharp | 6.2.4 | MIT | [NuGet](https://www.nuget.org/packages/PDFsharp/6.2.4) |
| QRCoder | 1.8.0 | MIT | [NuGet](https://www.nuget.org/packages/QRCoder/1.8.0) |
| SkiaSharp | 3.119.4 | MIT | [NuGet](https://www.nuget.org/packages/SkiaSharp/3.119.4) |
| SkiaSharp.NativeAssets.Linux | 3.119.4 | MIT | [NuGet](https://www.nuget.org/packages/SkiaSharp.NativeAssets.Linux/3.119.4) |
| SkiaSharp.NativeAssets.macOS | 3.119.4 | MIT | [NuGet](https://www.nuget.org/packages/SkiaSharp.NativeAssets.macOS/3.119.4) |
| SkiaSharp.NativeAssets.WebAssembly | 3.119.4 | MIT | [NuGet](https://www.nuget.org/packages/SkiaSharp.NativeAssets.WebAssembly/3.119.4) |
| SkiaSharp.NativeAssets.Win32 | 3.119.4 | MIT | [NuGet](https://www.nuget.org/packages/SkiaSharp.NativeAssets.Win32/3.119.4) |
| SQLitePCLRaw.bundle_e_sqlite3 | 2.1.12 | Apache-2.0 | [NuGet](https://www.nuget.org/packages/SQLitePCLRaw.bundle_e_sqlite3/2.1.12) |
| SQLitePCLRaw.core | 2.1.12 | Apache-2.0 | [NuGet](https://www.nuget.org/packages/SQLitePCLRaw.core/2.1.12) |
| SQLitePCLRaw.lib.e_sqlite3 | 2.1.12 | Apache-2.0 | [NuGet](https://www.nuget.org/packages/SQLitePCLRaw.lib.e_sqlite3/2.1.12) |
| SQLitePCLRaw.provider.e_sqlite3 | 2.1.12 | Apache-2.0 | [NuGet](https://www.nuget.org/packages/SQLitePCLRaw.provider.e_sqlite3/2.1.12) |
| System.ClientModel | 1.8.0 | MIT | [NuGet](https://www.nuget.org/packages/System.ClientModel/1.8.0) |
| System.Configuration.ConfigurationManager | 9.0.11 | MIT | [NuGet](https://www.nuget.org/packages/System.Configuration.ConfigurationManager/9.0.11) |
| System.Diagnostics.EventLog | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/System.Diagnostics.EventLog/10.0.12) |
| System.DirectoryServices.Protocols | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/System.DirectoryServices.Protocols/10.0.12) |
| System.Drawing.Common | 6.0.0 | MIT | [NuGet](https://www.nuget.org/packages/System.Drawing.Common/6.0.0) |
| System.IdentityModel.Tokens.Jwt | 7.7.1 | MIT | [NuGet](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/7.7.1) |
| System.IdentityModel.Tokens.Jwt | 8.19.2 | MIT | [NuGet](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/8.19.2) |
| System.Memory.Data | 8.0.1 | MIT | [NuGet](https://www.nuget.org/packages/System.Memory.Data/8.0.1) |
| System.Security.Cryptography.Pkcs | 9.0.11 | MIT | [NuGet](https://www.nuget.org/packages/System.Security.Cryptography.Pkcs/9.0.11) |
| System.Security.Cryptography.ProtectedData | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/System.Security.Cryptography.ProtectedData/10.0.12) |
| System.Security.Cryptography.ProtectedData | 9.0.11 | MIT | [NuGet](https://www.nuget.org/packages/System.Security.Cryptography.ProtectedData/9.0.11) |
| System.ServiceProcess.ServiceController | 10.0.12 | MIT | [NuGet](https://www.nuget.org/packages/System.ServiceProcess.ServiceController/10.0.12) |
| Tmds.DBus.Protocol | 0.94.1 | MIT | [NuGet](https://www.nuget.org/packages/Tmds.DBus.Protocol/0.94.1) |

## Existing assets

| Asset | Upstream terms and retained notice |
| --- | --- |
| Font Awesome OS icons, Free 6.7.2 | CC BY 4.0. See [provenance](src/seQuester.Server/wwwroot/icons/os/PROVENANCE.md) and [license](src/seQuester.Server/wwwroot/icons/os/LICENSE.txt). |
| Bitstream Vera fonts | Bitstream Vera license. See [font license](src/seQuester.Server/Fonts/bitstream-vera-license.txt). |
| seQuester original brand assets | First-party asset inventory is in Assets/Branding/brand-assets.json; do not infer ownership of upstream artwork from this notice. |

Fonts and icons are assets, not approved core library dependencies. Preserve their existing terms and obtain an owner decision before treating additional asset-license families as approved. Do not replace their attribution with Tekmyster copyright headers.

## Enforcement and release status

Run `python tools/check-license-policy.py`. It rejects package license expressions outside MIT/Apache-2.0, file-based/unverified metadata, missing locked-package entries, GPL-marked source, the known libbpf/libauparse imports and SQLite/Skia native package conflicts. A nonzero result currently reflects the conflicts above; it must not be reported as a pass.

The automated check does not establish complete native/embedded dependency compliance. Before distribution, resolve the listed conflicts, inventory all shipped runtime/native materials, include required upstream license/copyright/NOTICE texts, and verify the actual release payload. No existing source declaration or operating sensor has been changed merely to conceal a license conflict.

New first-party file headers are checked on pull requests. Formats without comments use a `.license` sidecar. Imported third-party material requires retained upstream attribution and an explicit owner-reviewed policy exception; do not satisfy the header check by falsely claiming ownership.
