# Static integrity verification only: never executes/extracts Linux binaries.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($PackageDirectory)
$payload=Join-Path $root 'payload'
$manifest=Get-Content -LiteralPath (Join-Path $payload 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.Product -notin @('Ransom Free Management Server','Ransom Free Callback Receiver') -or $manifest.Runtime -notin @('linux-x64','linux-arm64') -or $manifest.Signed -ne $false) { throw 'Incorrect package identity.' }
$role=if ($manifest.Product -eq 'Ransom Free Management Server') { 'Management' } else { 'Receiver' }
$assembly=if ($role -eq 'Management') { 'RansomFree.Server' } else { 'RansomFree.Receiver' }
$releasePattern='^ransomfree-'+$role.ToLowerInvariant()+'-[A-Za-z0-9._-]+-'+[Regex]::Escape($manifest.Runtime)+'$'
if ($manifest.Release -cnotmatch $releasePattern) { throw 'Invalid release/role/runtime binding.' }
if ([IO.File]::ReadAllText((Join-Path $payload 'RELEASE_ID')).Trim() -cne $manifest.Release) { throw 'Release marker mismatch.' }
# Preserve read-only verification of historical schema-1 x64 management archives.
$schema2=$null -ne $manifest.PSObject.Properties['PackageSchema']
if ($schema2) {
    if ($manifest.PackageSchema -ne 2 -or $manifest.Role -cne $role -or [IO.File]::ReadAllText((Join-Path $payload 'RUNTIME_ID')).Trim() -cne $manifest.Runtime) { throw 'Package schema/role/runtime marker mismatch.' }
} elseif ($role -ne 'Management' -or $manifest.Runtime -ne 'linux-x64') { throw 'This role/runtime requires package schema 2.' }
$machine=if ($manifest.Runtime -eq 'linux-arm64') { 183 } else { 62 }
foreach ($name in @($assembly,'libcoreclr.so','libhostfxr.so','libe_sqlite3.so')) {
    $native=[IO.File]::OpenRead((Join-Path $payload "app/$name"))
    try {
        $head=New-Object byte[] 20
        if ($native.Read($head,0,20) -ne 20 -or $head[0] -ne 127 -or [Text.Encoding]::ASCII.GetString($head,1,3) -ne 'ELF' -or $head[4] -ne 2 -or $head[5] -ne 1 -or $head[18] -ne $machine -or $head[19] -ne 0) { throw "Native architecture does not match $($manifest.Runtime): $name" }
    } finally { $native.Dispose() }
}
if ($role -eq 'Receiver' -and ((Test-Path -LiteralPath (Join-Path $payload 'app/RansomFree.Server.dll')) -or (Test-Path -LiteralPath (Join-Path $payload 'app/wwwroot')))) { throw 'Management application leaked into receiver bundle.' }
$expected=@{}
foreach ($file in $manifest.Files) {
    if ($file.Path.StartsWith('/') -or $file.Path.Contains('\') -or '..' -in $file.Path.Split('/') -or $expected.ContainsKey($file.Path)) { throw 'Invalid manifest path.' }
    $path=Join-Path $payload $file.Path
    if ((Get-Item -LiteralPath $path).Length -ne $file.Bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.Sha256) { throw 'Payload manifest mismatch.' }
    $expected[$file.Path]=$file.Sha256
}
foreach ($name in @('manifest.json','SHA256SUMS')) { $expected[$name]=(Get-FileHash -LiteralPath (Join-Path $payload $name) -Algorithm SHA256).Hash }
if (@(Get-ChildItem -LiteralPath $payload -Recurse -File).Count -ne $expected.Count) { throw 'Untracked payload file.' }
$hashLines=[IO.File]::ReadAllLines((Join-Path $payload 'SHA256SUMS'))
if ($hashLines.Count -ne $expected.Count-1) { throw 'SHA256SUMS inventory count mismatch.' }
$seenSums=@{}
foreach ($line in $hashLines) {
    if ($line -cnotmatch '^([0-9a-f]{64})  (.+)$') { throw 'Invalid checksum line.' }
    $name=$Matches[2]; $hash=$Matches[1].ToUpperInvariant()
    if ($name -eq 'SHA256SUMS' -or $seenSums.ContainsKey($name) -or !$expected.ContainsKey($name) -or $expected[$name] -cne $hash) { throw 'Checksum inventory mismatch.' }
    $seenSums[$name]=$true
}
$archive=Join-Path $root ($manifest.Release+'.tar.gz')
$sidecar=[IO.File]::ReadAllText($archive+'.sha256').Trim()
$archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sidecar -cne ($archiveHash+'  '+[IO.Path]::GetFileName($archive))) { throw 'Archive hash mismatch.' }
Add-Type -AssemblyName System.Formats.Tar
$stream=[IO.File]::OpenRead($archive)
$gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Decompress)
$reader=[System.Formats.Tar.TarReader]::new($gzip)
$seen=@{}
try {
    while ($entry=$reader.GetNextEntry()) {
        $name=$entry.Name
        if ($name.StartsWith('./')) { $name=$name.Substring(2) }
        if ($name.StartsWith('/') -or $name.Contains('\') -or '..' -in $name.Split('/')) { throw 'Unsafe archive path.' }
        if ($entry.EntryType -eq [System.Formats.Tar.TarEntryType]::Directory) { continue }
        if ($entry.EntryType -notin @([System.Formats.Tar.TarEntryType]::RegularFile,[System.Formats.Tar.TarEntryType]::V7RegularFile)) { throw 'Unexpected archive link/special entry.' }
        if (!$expected.ContainsKey($name) -or $seen.ContainsKey($name)) { throw 'Unexpected/duplicate archive member.' }
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $digest=[BitConverter]::ToString($sha.ComputeHash($entry.DataStream)).Replace('-','') } finally { $sha.Dispose() }
        if ($digest -cne $expected[$name]) { throw 'Archived file hash mismatch.' }
        $seen[$name]=$true
    }
} finally { $reader.Dispose(); $gzip.Dispose(); $stream.Dispose() }
if ($seen.Count -ne $expected.Count) { throw 'Archive missing expected files.' }
$result=[ordered]@{Release=$manifest.Release;Product=$manifest.Product;Runtime=$manifest.Runtime;Role=$role;NativeHeaders='PASS - static ELF identity only';ArchiveSha256=$archiveHash;ArchiveBytes=(Get-Item -LiteralPath $archive).Length;VerifiedFiles=$seen.Count;PayloadHashes='PASS';ArchiveHashesAndInventory='PASS';NativeLinuxSmoke='NOT RUN - native role/runtime acceptance deferred';Deployed=$false;Signed=$false}
$json=$result | ConvertTo-Json
$json | Set-Content -LiteralPath (Join-Path $root 'package-verification.json') -Encoding UTF8
Write-Output $json
