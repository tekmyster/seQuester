[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageDirectory)
$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($PackageDirectory); $payload=Join-Path $root 'payload'
$manifest=Get-Content -LiteralPath (Join-Path $payload 'manifest.json') -Raw | ConvertFrom-Json
& (Join-Path $PSScriptRoot 'verify-unix-release-guard.ps1') -Payload $payload
if($manifest.Product -ne 'Ransom Free Unix Endpoint' -or $manifest.Runtime -notin @('linux-x64','linux-arm64','osx-x64','osx-arm64') -or $manifest.Signed -ne $false){throw 'Incorrect endpoint package identity.'}
$expected=@{}
foreach($file in $manifest.Files){
    if($file.Path.StartsWith('/') -or $file.Path.Contains('\') -or '..' -in $file.Path.Split('/') -or $expected.ContainsKey($file.Path)){throw 'Invalid manifest path.'}
    $path=Join-Path $payload $file.Path
    if((Get-Item -LiteralPath $path).Length -ne $file.Bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.Sha256){throw 'Payload mismatch.'}
    $expected[$file.Path]=$file.Sha256
}
foreach($name in @('manifest.json','SHA256SUMS')){$expected[$name]=(Get-FileHash -LiteralPath (Join-Path $payload $name) -Algorithm SHA256).Hash}
if(@(Get-ChildItem -LiteralPath $payload -Recurse -File).Count -ne $expected.Count){throw 'Unexpected payload file.'}
$seen=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path $payload 'SHA256SUMS'))){
    if($line -cnotmatch '^([0-9a-f]{64})  (.+)$'){throw 'Invalid checksum line.'}
    $name=$Matches[2];$hash=$Matches[1].ToUpperInvariant()
    if($name -eq 'SHA256SUMS' -or $seen.ContainsKey($name) -or !$expected.ContainsKey($name) -or $expected[$name] -cne $hash){throw 'Checksum inventory mismatch.'}
    $seen[$name]=$true
}
if($seen.Count -ne $expected.Count-1){throw 'Checksum inventory incomplete.'}
$archive=Join-Path $root ($manifest.Release+'.tar.gz')
$hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if([IO.File]::ReadAllText($archive+'.sha256').Trim() -cne ($hash+'  '+[IO.Path]::GetFileName($archive))){throw 'Archive checksum mismatch.'}
Add-Type -AssemblyName System.Formats.Tar
$stream=[IO.File]::OpenRead($archive);$gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Decompress);$reader=[System.Formats.Tar.TarReader]::new($gzip)
$seen=@{}
try{
    while($entry=$reader.GetNextEntry()){
        $name=$entry.Name;if($name.StartsWith('./')){$name=$name.Substring(2)}
        if($name.StartsWith('/') -or $name.Contains('\') -or '..' -in $name.Split('/')){throw 'Unsafe archive member.'}
        if($entry.EntryType -eq [System.Formats.Tar.TarEntryType]::Directory){continue}
        if($entry.EntryType -notin @([System.Formats.Tar.TarEntryType]::RegularFile,[System.Formats.Tar.TarEntryType]::V7RegularFile)){throw 'Link/special archive member rejected.'}
        if(!$expected.ContainsKey($name) -or $seen.ContainsKey($name)){throw 'Unexpected/duplicate member.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$digest=[Convert]::ToHexString($sha.ComputeHash($entry.DataStream))}finally{$sha.Dispose()}
        if($digest -cne $expected[$name]){throw 'Archive member hash mismatch.'}
        $seen[$name]=$true
    }
}finally{$reader.Dispose();$gzip.Dispose();$stream.Dispose()}
if($seen.Count -ne $expected.Count){throw 'Archive is incomplete.'}
$result=[ordered]@{Release=$manifest.Release;Runtime=$manifest.Runtime;Archive=$archive;ArchiveSha256=$hash;ArchiveBytes=(Get-Item -LiteralPath $archive).Length;VerifiedFiles=$seen.Count;PayloadHashes='PASS';ArchiveHashesAndInventory='PASS';NativeTests='NOT RUN';Signed=$false;Deployed=$false}
$json=$result|ConvertTo-Json
$json|Set-Content -LiteralPath (Join-Path $root 'package-verification.json') -Encoding UTF8
Write-Output $json
