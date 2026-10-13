[CmdletBinding()]
param([string]$WorkRoot='D:\Codex\RansomFree',[string]$BaselineArchive='D:\Codex\RansomFree\artifacts\management-wwwroot-baseline-20260914T0100Z\ransomfree-wwwroot-baseline-20260914T0100Z.zip')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$baselineHash='5ABEF63849C7CF32CBBBCB134AD9AADDC288FF237B7555DAFA2D88E44F06E911'
if((Get-FileHash -LiteralPath $BaselineArchive -Algorithm SHA256).Hash -cne $baselineHash){throw 'Unreviewed live baseline.'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$baseline=[IO.Compression.ZipFile]::OpenRead($BaselineArchive)
try{
    $reader=[IO.StreamReader]::new($baseline.GetEntry('wwwroot-baseline-manifest.json').Open());try{$baselineJson=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $baselineFiles=$baselineJson|ConvertFrom-Json
    if($baselineFiles.Count -ne 42 -or $baseline.Entries.Count -ne 43){throw 'Unexpected baseline inventory.'}
    $seenBaseline=@{}
    foreach($file in $baselineFiles){
        if($file.Path -cnotmatch '^[a-z0-9.-]+\.(html|css|js)(\.br|\.gz)?$' -or $seenBaseline.ContainsKey($file.Path)){throw 'Unsafe/duplicate baseline path.'}
        $seenBaseline[$file.Path]=$true
        $entry=$baseline.GetEntry('wwwroot\'+$file.Path);if(!$entry -or $entry.Length -ne $file.Length){throw 'Baseline member mismatch.'}
        $stream=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create();try{$digest=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$sha.Dispose()}
        if($digest -ne $file.Sha256){throw 'Baseline content mismatch.'}
    }
}finally{$baseline.Dispose()}
$release='sequester-console-0.6.4-ux.'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$root=Join-Path $WorkRoot ('packages\console-ux\'+$release)
if(Test-Path -LiteralPath $root){throw 'Immutable destination already exists.'}
$payload=Join-Path $root 'payload';[void][IO.Directory]::CreateDirectory((Join-Path $payload 'wwwroot'))
foreach($file in Get-ChildItem -LiteralPath (Join-Path $repo 'src\seQuester.Server\wwwroot') -File){
    if($file.Extension -notin @('.html','.css','.js')){throw 'Unexpected non-UI source; review before packaging.'}
    if($file.Extension -eq '.js'){& node --check $file.FullName;if($LASTEXITCODE -ne 0){throw 'JavaScript syntax failure.'}}
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $payload 'wwwroot')
}
foreach($file in $baselineFiles|Where-Object Path -match '\.(html|css|js)$'){
    if(!(Test-Path -LiteralPath (Join-Path $payload ('wwwroot\'+$file.Path)))){throw 'Existing live screen/asset would be omitted.'}
}
foreach($file in Get-ChildItem -LiteralPath (Join-Path $payload 'wwwroot') -File){
    foreach($suffix in @('.gz','.br')){
        $target=$file.FullName+$suffix;$input=[IO.File]::OpenRead($file.FullName);$output=[IO.File]::Create($target)
        $compressor=if($suffix -eq '.gz'){[IO.Compression.GZipStream]::new($output,[IO.Compression.CompressionLevel]::Optimal)}else{[IO.Compression.BrotliStream]::new($output,[IO.Compression.CompressionLevel]::Optimal)}
        try{$input.CopyTo($compressor)}finally{$compressor.Dispose();$output.Dispose();$input.Dispose()}
        $compressed=[IO.File]::OpenRead($target)
        $decoder=if($suffix -eq '.gz'){[IO.Compression.GZipStream]::new($compressed,[IO.Compression.CompressionMode]::Decompress)}else{[IO.Compression.BrotliStream]::new($compressed,[IO.Compression.CompressionMode]::Decompress)}
        $sha=[Security.Cryptography.SHA256]::Create();try{$digest=[BitConverter]::ToString($sha.ComputeHash($decoder)).Replace('-','')}finally{$sha.Dispose();$decoder.Dispose();$compressed.Dispose()}
        if($digest -cne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash){throw 'Compressed asset does not match source.'}
    }
}
Copy-Item -LiteralPath (Join-Path $repo 'UI_COPY_STANDARD.md') -Destination $payload
Copy-Item -LiteralPath (Join-Path $repo 'packaging\console-ux\README.md') -Destination $payload
$encoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $payload 'baseline-wwwroot-manifest.json'),$baselineJson,$encoding)
[IO.File]::WriteAllText((Join-Path $payload 'RELEASE_ID'),$release+"`n",$encoding)
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object{[ordered]@{Path=$_.FullName.Substring($payload.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
$manifest=[ordered]@{Release=$release;ProductLine='Quiver';Product='seQuester';Role='Management console static assets';CompatibleServer='0.6.4 API contract; baseline-bound UX1';ExpectedWebRoot='C:\Program Files\RansomFree\Server\releases\20260913-attribution-v1\app\wwwroot';ExpectedBackendSha256='0b10c51edc94226ebff3aaabc9700240da0df2686c0facc9873876c6265c66f0';ExpectedLauncherSha256='cae1872d9aa5c9a6636f7eb352d6e13b50735ae5a355abcc8b155b2535d3e970';BaselineArchiveSha256=$baselineHash;BaselineFiles=42;WebFiles=45;Signed=$false;BackendChanges=$false;LiveDeployment=$false;Files=$files}
[IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),($manifest|ConvertTo-Json -Depth 6)+"`n",$encoding)
$archive=Join-Path $root ($release+'.zip')
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($payload,$archive,[IO.Compression.CompressionLevel]::Optimal,$false)
# Verify every archived byte without extracting or executing content.
$expected=@{};foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File){$expected[$file.FullName.Substring($payload.Length+1).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
$zip=[IO.Compression.ZipFile]::OpenRead($archive);$seen=@{}
try{foreach($entry in $zip.Entries){
    if(!$expected.ContainsKey($entry.FullName)-or$seen.ContainsKey($entry.FullName)){throw 'Unexpected/duplicate archive member.'}
    $stream=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create()
    try{$digest=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$sha.Dispose()}
    if($digest -cne $expected[$entry.FullName]){throw 'Archived content hash mismatch.'};$seen[$entry.FullName]=$true
}}finally{$zip.Dispose()}
if($seen.Count -ne $expected.Count){throw 'Missing archive members.'}
$hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive+'.sha256'),$hash+'  '+[IO.Path]::GetFileName($archive)+"`n",$encoding)
$report=[ordered]@{Release=$release;Archive=$archive;Sha256=$hash;Bytes=(Get-Item -LiteralPath $archive).Length;VerifiedFiles=$seen.Count;ArchiveIntegrity='PASS';Signed=$false;LiveDeployment=$false;NativeDesktopAcceptance='Not included; separate gate'}
$json=$report|ConvertTo-Json;[IO.File]::WriteAllText((Join-Path $root 'package-verification.json'),$json+"`n",$encoding);$json
