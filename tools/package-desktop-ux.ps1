[CmdletBinding()]
param([Parameter(Mandatory)][string]$PublishRoot,[Parameter(Mandatory)][string]$ExpectedManifestSha256,[string]$WorkRoot='D:\Codex\RansomFree')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem
$repo=Split-Path $PSScriptRoot -Parent
$manifestPath=Join-Path $PublishRoot 'publish-manifest.json'
if((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ne $ExpectedManifestSha256){throw 'Publish manifest identity mismatch.'}
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
$expectedNames=@('win-x64','win-x64-readonly','linux-x64','linux-arm64','osx-x64','osx-arm64')
if($manifest.Builds.Count -ne 6){throw 'Expected six desktop components.'}
$seenBuilds=@{}
foreach($build in $manifest.Builds){
    if($build.Directory -cnotin $expectedNames -or $seenBuilds.ContainsKey($build.Directory)){throw 'Unknown/duplicate desktop component.'}
    $seenBuilds[$build.Directory]=$true
    $runtime=if($build.Directory -eq 'win-x64-readonly'){'win-x64'}else{$build.Directory}
    if($build.Runtime -cne $runtime){throw 'Runtime mismatch.'}
    $directory=Join-Path $PublishRoot $build.Directory;$seen=@{}
    & (Join-Path $PSScriptRoot 'verify-brand-assets.ps1') -AssetRoot (Join-Path $directory 'Branding') | Out-Null
    foreach($file in $build.Files){
        if($file.Path -notmatch '^[A-Za-z0-9_.+/-]+$' -or $file.Path.StartsWith('/') -or $file.Path.Split('/') -contains '..' -or $seen.ContainsKey($file.Path)){throw 'Unsafe/duplicate publish path.'}
        $seen[$file.Path]=$true;$path=Join-Path $directory $file.Path;$item=Get-Item -LiteralPath $path
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -ne $file.Bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.Sha256){throw 'Publish content mismatch.'}
    }
    if(@(Get-ChildItem -LiteralPath $directory -Recurse -File).Count -ne $seen.Count){throw 'Extra publish files.'}
}
$release='sequester-desktop-bundles.'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$root=Join-Path $WorkRoot ('packages\desktop-ux\'+$release)
if(Test-Path -LiteralPath $root){throw 'Immutable output exists.'}
[void][IO.Directory]::CreateDirectory($root)
$reports=@();$utf8=[Text.UTF8Encoding]::new($false)
foreach($build in $manifest.Builds){
    $id=$build.Directory;$mac=$id.StartsWith('osx-');$windows=$id.StartsWith('win-')
    $payload=Join-Path $root ($id+'-payload')
    $appRelative=if($mac){'seQuester Endpoint.app/Contents/MacOS'}else{'app'}
    $app=Join-Path $payload $appRelative;[void][IO.Directory]::CreateDirectory($app)
    foreach($file in $build.Files){$target=Join-Path $app $file.Path;[void][IO.Directory]::CreateDirectory((Split-Path $target -Parent));Copy-Item -LiteralPath (Join-Path (Join-Path $PublishRoot $id) $file.Path) -Destination $target;if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $file.Sha256){throw 'Staged content differs from frozen publish manifest.'}}
    $hostName=if($id -eq 'win-x64'){'RansomFree.exe'}elseif($id -eq 'win-x64-readonly'){'RansomFree.Tray.exe'}else{'RansomFree.UnixDesktop'}
    $hostPath=Join-Path $app $hostName;$stream=[IO.File]::OpenRead($hostPath)
    try{$reader=[IO.BinaryReader]::new($stream);$magic=$reader.ReadUInt32()
        if($windows){if(($magic -band 65535) -ne 23117){throw 'Expected PE host.'};$stream.Position=60;$offset=$reader.ReadInt32();$stream.Position=$offset;if($reader.ReadUInt32() -ne 17744 -or $reader.ReadUInt16() -ne 34404){throw 'Expected x64 PE host.'}}
        elseif($mac){if($magic -ne 4277009103){throw 'Expected 64-bit Mach-O host.'};$cpu=$reader.ReadUInt32();$expectedCpu=if($id.EndsWith('arm64')){16777228}else{16777223};if($cpu -ne $expectedCpu){throw 'Mach-O CPU mismatch.'}}
        else{if($magic -ne 1179403647 -or $reader.ReadByte() -ne 2 -or $reader.ReadByte() -ne 1){throw 'Expected little-endian ELF64 host.'};$stream.Position=18;$cpu=$reader.ReadUInt16();$expectedCpu=if($id.EndsWith('arm64')){183}else{62};if($cpu -ne $expectedCpu){throw 'ELF CPU mismatch.'}}
    }finally{$stream.Dispose()}
    $dll=if($windows){[IO.Path]::ChangeExtension($hostPath,'.dll')}else{$hostPath+'.dll'}
    if([Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion -ne ($build.Version+'.0')){throw 'Component assembly version mismatch.'}
    if($mac){
        $plist='<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.ransomfree.endpoint-menu</string><key>CFBundleName</key><string>seQuester Endpoint</string><key>CFBundleExecutable</key><string>RansomFree.UnixDesktop</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>'+ $build.Version +'</string><key>CFBundleVersion</key><string>'+ $build.Version +'</string><key>LSUIElement</key><true/><key>LSMinimumSystemVersion</key><string>14.0</string></dict></plist>'
        $plist=$plist.Replace('<key>CFBundleExecutable</key>','<key>CFBundleIconFile</key><string>sequester.icns</string><key>CFBundleExecutable</key>')
        [void][xml]$plist;[IO.File]::WriteAllText((Join-Path $payload 'seQuester Endpoint.app/Contents/Info.plist'),$plist,$utf8)
        $resources=Join-Path $payload 'seQuester Endpoint.app/Contents/Resources';[void][IO.Directory]::CreateDirectory($resources)
        Copy-Item -LiteralPath (Join-Path $app 'Branding/sequester.icns') -Destination $resources
    }
    Copy-Item -LiteralPath (Join-Path $repo 'packaging\desktop-ux\README.md') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $repo 'UI_COPY_STANDARD.md') -Destination $payload
    $files=@(Get-ChildItem -LiteralPath $payload -Recurse -File|Sort-Object FullName|ForEach-Object{[ordered]@{Path=$_.FullName.Substring($payload.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    $metadata=[ordered]@{Release=$release;Component=$id;Runtime=$build.Runtime;Version=$build.Version;Role=$build.Role;SourceManifestSha256=$ExpectedManifestSha256;Signed=$false;Installer=$false;Deployed=$false;NativeAcceptance='PENDING';Files=$files}
    [IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),($metadata|ConvertTo-Json -Depth 8),$utf8)
    $archive=Join-Path $root ($release+'-'+$id+'.zip')
    $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try{foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File){
        $name=$file.FullName.Substring($payload.Length+1).Replace('\','/')
        $entry=[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$file.FullName,$name,[IO.Compression.CompressionLevel]::Optimal)
        $mode=if(!$windows -and $name -ceq ($appRelative+'/'+$hostName)){33261}else{33188}
        $entry.ExternalAttributes=[int]($mode -shl 16)
    }}finally{$zip.Dispose()}
    $expected=@{};foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File){$expected[$file.FullName.Substring($payload.Length+1).Replace('\','/')]=$file}
    $zip=[IO.Compression.ZipFile]::OpenRead($archive);$seen=@{}
    try{foreach($entry in $zip.Entries){
        if(!$expected.ContainsKey($entry.FullName)-or$seen.ContainsKey($entry.FullName)){throw 'Unexpected/duplicate ZIP member.'}
        $source=$expected[$entry.FullName];if($entry.Length -ne $source.Length){throw 'ZIP length mismatch.'}
        $stream=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$sha.Dispose()}
        if($hash -ne (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash){throw 'ZIP content mismatch.'};$seen[$entry.FullName]=$true
        if(!$windows -and $entry.FullName -ceq ($appRelative+'/'+$hostName) -and (($entry.ExternalAttributes -shr 16) -band 511) -ne 493){throw 'Executable mode missing.'}
    }}finally{$zip.Dispose()}
    if($seen.Count -ne $expected.Count){throw 'Missing ZIP member.'}
    $archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(($archive+'.sha256'),$archiveHash+'  '+[IO.Path]::GetFileName($archive)+"`n",$utf8)
    $reports+=[ordered]@{Component=$id;Version=$build.Version;Archive=$archive;Bytes=(Get-Item -LiteralPath $archive).Length;Sha256=$archiveHash;Files=$seen.Count;Integrity='PASS';HostArchitecture='PASS';AssemblyVersion='PASS';Signed=$false;NativeAcceptance='PENDING'}
}
[IO.File]::WriteAllText((Join-Path $root 'package-verification.json'),($reports|ConvertTo-Json -Depth 6),$utf8)
$reports|ConvertTo-Json -Depth 6
