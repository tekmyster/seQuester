[CmdletBinding()]
param(
    [ValidateSet('linux-x64','linux-arm64')][string]$Runtime='linux-x64',
    [ValidateSet('Management','Receiver')][string]$Role='Management',
    [string]$Dotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe',
    [string]$WorkRoot='D:\Codex\RansomFree',
    [string]$Bash='C:\Program Files\Git\bin\bash.exe'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$roleId=$Role.ToLowerInvariant()
$assembly=if ($Role -eq 'Management') { 'RansomFree.Server' } else { 'RansomFree.Receiver' }
$project=if ($Role -eq 'Management') { 'seQuester.Server' } else { 'seQuester.Receiver' }
$product=if ($Role -eq 'Management') { 'Ransom Free Management Server' } else { 'Ransom Free Callback Receiver' }
$machine=if ($Runtime -eq 'linux-arm64') { 183 } else { 62 }
$env:TEMP=Join-Path $WorkRoot 'temp'; $env:TMP=$env:TEMP
$env:NUGET_PACKAGES=Join-Path $WorkRoot 'nuget\packages'
$env:NUGET_HTTP_CACHE_PATH=Join-Path $WorkRoot 'nuget\http-cache'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; $env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
[void][IO.Directory]::CreateDirectory($env:TEMP)
$release="ransomfree-$roleId-0.6.4-dev."+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)+"-$Runtime"
$output=Join-Path $WorkRoot ("packages\linux-$roleId\"+$release)
if (Test-Path -LiteralPath $output) { throw 'Immutable release destination already exists.' }
$payload=Join-Path $output 'payload'
[void][IO.Directory]::CreateDirectory($payload)
& $Dotnet publish (Join-Path $repo "src\$project\$project.csproj") --configuration Release --runtime $Runtime --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') --output (Join-Path $payload 'app') -p:RestoreLockedMode=true -p:Version=0.6.4 -p:DebugType=None -p:DebugSymbols=false
if ($LASTEXITCODE -ne 0) { throw "Linux $Role publish failed; partial build retained." }
Copy-Item -Path (Join-Path $repo "packaging\linux-$roleId\*") -Destination $payload
$docs=Join-Path $payload 'docs'; [void][IO.Directory]::CreateDirectory($docs)
$docNames=if ($Role -eq 'Management') { @('SQL_SERVER_SETUP.md','SSO_SETUP.md','DIRECTORY_SETUP.md','CALLBACK_SETUP.md') } else { @('SQL_SERVER_SETUP.md','CALLBACK_SETUP.md') }
foreach ($name in $docNames) { Copy-Item -LiteralPath (Join-Path $repo "src\seQuester.Server\$name") -Destination $docs }
Copy-Item -LiteralPath (Join-Path $repo 'src\seQuester.Server\Database\RuntimeRoles.sql') -Destination $docs
if ($Role -eq 'Management') {
    Copy-Item -LiteralPath (Join-Path $repo 'packaging\linux-client\AUDIT.md') -Destination (Join-Path $docs 'LINUX_ATTRIBUTION.md')
    Copy-Item -LiteralPath (Join-Path $repo 'integrations\notifications\README.md') -Destination (Join-Path $docs 'NOTIFICATIONS.md')
} else {
    Copy-Item -LiteralPath (Join-Path $repo 'src\seQuester.Receiver\SERVICE_TOKENS.md') -Destination $docs
}
$utf8=New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $payload 'RELEASE_ID'),$release+"`n",$utf8)
[IO.File]::WriteAllText((Join-Path $payload 'RUNTIME_ID'),$Runtime+"`n",$utf8)
# Linux configuration/scripts must be LF-only with no UTF-8 BOM.
foreach ($file in Get-ChildItem -LiteralPath $payload -File) {
    if ($file.Extension -in @('.sh','.service','.example','.md')) {
        $content=[IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n")
        [IO.File]::WriteAllText($file.FullName,$content,$utf8)
    }
}
$shellStatus='NOT RUN: Bash parser unavailable on build host.'
if (Test-Path -LiteralPath $Bash) {
    foreach ($script in Get-ChildItem -LiteralPath $payload -Filter *.sh) {
        & $Bash -n $script.FullName
        if ($LASTEXITCODE -ne 0) { throw 'Shell syntax check failed.' }
    }
    $shellCount=@(Get-ChildItem -LiteralPath $payload -Filter *.sh).Count
    $shellStatus=if ($shellCount -gt 0) { "PASS: bash -n parsed $shellCount shell scripts (Windows Git Bash; not Linux execution)." } else { 'NOT APPLICABLE: publish-only role bundle has no shell scripts.' }
}
foreach ($name in @($assembly,'libcoreclr.so','libhostfxr.so','libe_sqlite3.so')) {
    $file=Join-Path $payload "app\$name"
    if (!(Test-Path -LiteralPath $file)) { throw "Required native file missing: $name" }
    $stream=[IO.File]::OpenRead($file)
    try { $head=New-Object byte[] 20; if ($stream.Read($head,0,20) -ne 20 -or $head[0] -ne 127 -or [Text.Encoding]::ASCII.GetString($head,1,3) -ne 'ELF' -or $head[4] -ne 2 -or $head[5] -ne 1 -or $head[18] -ne $machine -or $head[19] -ne 0) { throw "Not an ELF64 $Runtime payload: $name" } }
    finally { $stream.Dispose() }
}
$required=@("$assembly.dll","$assembly.runtimeconfig.json","$assembly.deps.json")
if ($Role -eq 'Management') { $required+=@('wwwroot\index.html','wwwroot\notifications.js','wwwroot\policies.js') }
foreach ($name in $required) {
    if (!(Test-Path -LiteralPath (Join-Path $payload "app\$name"))) { throw "Required $Role payload missing: $name" }
}
$sourceFiles=@(Get-ChildItem -LiteralPath (Join-Path $repo "src\$project"),(Join-Path $repo "packaging\linux-$roleId") -Recurse -File | Where-Object FullName -notmatch '\\(bin|obj)\\')
if ($Role -eq 'Management') {
    $sourceFiles+=@(Get-ChildItem -LiteralPath (Join-Path $repo 'src\seQuester.Contracts'),(Join-Path $repo 'Assets') -Recurse -File | Where-Object FullName -notmatch '\\(bin|obj)\\')
    $sourceFiles+=@(Get-Item -LiteralPath (Join-Path $repo 'CanaryTemplates.cs'),(Join-Path $repo 'CallbackDocuments.cs'),(Join-Path $repo 'ImportedCanaries.cs'),(Join-Path $repo 'Syslog.cs'))
} else {
    foreach ($name in @('CallbackStorage.cs','DatabaseSettings.cs','SqlServerSchema.cs')) { $sourceFiles+=Get-Item -LiteralPath (Join-Path $repo "src\seQuester.Server\$name") }
}
$sourceFiles+=@(Get-Item -LiteralPath $PSCommandPath,(Join-Path $PSScriptRoot 'verify-linux-management-package.ps1'))
$sources=@($sourceFiles | Sort-Object FullName -Unique | ForEach-Object { [ordered]@{Path=$_.FullName.Substring($repo.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash} })
[IO.File]::WriteAllText((Join-Path $payload 'source-inventory.json'),(ConvertTo-Json -InputObject $sources -Depth 5)+"`n",$utf8)
$report=@"
# Package verification and smoke-test report

Release: $release
Target: $Runtime/glibc $Role. No deployment target contacted.

- PASS: .NET 10 Release self-contained $Runtime publish with locked dependency restore.
- PASS: required role-specific DLL, runtime configuration, assets and native runtime files present.
- PASS: role apphost, CoreCLR, hostfxr and SQLite native library have ELF64/little-endian/$Runtime headers.
- $shellStatus
- NOT RUN: native Linux execution, ldd/dynamic loader, systemd-analyze verify, service install/uninstall, UID/sandbox behavior, loopback TLS startup or smoke-test.sh. Build host has no identified WSL distribution/container runtime. Windows Bash syntax is not a Linux smoke pass.
- NOT RUN: cptnycdc01 OS/architecture/prerequisites, database migration/writes, LDAP/Entra/MFA, TLS/key recovery, callback receiver, email/Wazuh, report rendering, upgrade/rollback/backup restore or load testing.
- NOT SIGNED: artifact is development-only; SHA-256 detects changes but does not authenticate the publisher.
- BLOCKED FOR PRODUCTION: application explicitly rejects non-Development hosting. This gate has not been bypassed. See README for all remaining release and environment gates.

Archive inventory/hash verification is performed separately by tools/verify-linux-management-package.ps1 against the final tar.gz and its payload manifest. Its result is written beside the immutable archive, avoiding a circular self-hash.
No live service, firewall, database, certificate store, account or remote host was changed by packaging. No real credential or callback URL was included.
"@
[IO.File]::WriteAllText((Join-Path $payload 'VERIFICATION-REPORT.md'),$report.Replace("`r`n","`n")+"`n",$utf8)
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object { [ordered]@{Path=$_.FullName.Substring($payload.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash} })
$manifest=[ordered]@{Release=$release;Product=$product;ProductLine='Quiver';ProductName='seQuester';Role=$Role;PackageSchema=2;Runtime=$Runtime;Version='0.6.4';Signed=$false;NativeLinuxSmokeTest='NOT RUN';BuiltUtc=[DateTime]::UtcNow.ToString('o');Files=$files}
[IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),($manifest | ConvertTo-Json -Depth 7)+"`n",$utf8)
$hashes=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.FullName.Substring($payload.Length+1).Replace('\','/') })
[IO.File]::WriteAllText((Join-Path $payload 'SHA256SUMS'),($hashes -join "`n")+"`n",$utf8)
$archive=Join-Path $output ($release+'.tar.gz')
& tar --format=ustar -czf $archive -C $payload .
if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
$archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive+'.sha256'),$archiveHash+'  '+[IO.Path]::GetFileName($archive)+"`n",$utf8)
& (Join-Path $PSScriptRoot 'verify-linux-management-package.ps1') -PackageDirectory $output
Write-Output "Built, not deployed: $archive"
