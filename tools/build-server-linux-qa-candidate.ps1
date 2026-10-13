[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$SourceManifest,
 [Parameter(Mandatory)][string]$WorkRoot,
 [ValidateSet('linux-x64','linux-arm64')][string]$Runtime='linux-x64',
 [string]$Dotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe',
 [string]$PackageCache='D:\Codex\RansomFree\nuget-packages',
 [string]$Bash='C:\Program Files\Git\bin\bash.exe',
 [string]$Python='py',
 [string]$RelayProof,
 [string]$RelayDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$utf8=[Text.UTF8Encoding]::new($false)
function Write-Json($path,$value){[IO.File]::WriteAllText($path,($value|ConvertTo-Json -Depth 20)+"`n",$utf8)}
function Assert-Source {
 $entries=@(Get-Content -LiteralPath $SourceManifest -Raw|ConvertFrom-Json)
 $actual=@(Get-ChildItem -LiteralPath $repo -File -Recurse)
 if($entries.Count -ne $actual.Count){throw 'Source tree file count changed.'}
 foreach($entry in $entries){if((Get-FileHash -LiteralPath (Join-Path $repo $entry.Path)).Hash -ne $entry.Sha256){throw "Source changed: $($entry.Path)"}}
}
Assert-Source
$sourceHash=(Get-FileHash -LiteralPath $SourceManifest).Hash
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+$sourceHash.Substring(0,12).ToLowerInvariant()
$run=Join-Path $WorkRoot ('qa-staging-'+$stamp+'-'+$Runtime)
if(Test-Path -LiteralPath $run){throw 'Immutable output already exists.'}
New-Item -ItemType Directory -Path $run -Force|Out-Null
$env:TEMP=Join-Path $run 'temp';$env:TMP=$env:TEMP
$env:NUGET_PACKAGES=$PackageCache
$env:NUGET_HTTP_CACHE_PATH=Join-Path $run 'nuget-http-cache'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1';$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
New-Item -ItemType Directory -Path $env:TEMP -Force|Out-Null
& $Dotnet --info | Out-File (Join-Path $run 'dotnet-info.txt')
if($LASTEXITCODE){throw 'SDK inspection failed.'}
$artifacts=Join-Path $run 'artifacts'
$roles=@(
 @{Name='management';Version='0.6.5';Project='seQuester.Server';Assembly='RansomFree.Server';Packaging='linux-management'},
 @{Name='client';Version='0.9.9';Project='seQuester.LinuxAgent';Assembly='RansomFree.LinuxAgent';Packaging='linux-client'}
)
$outputs=@()
foreach($role in $roles){
 $release='ransomfree-'+$role.Name+'-'+$role.Version+'-dev.'+$stamp+'-'+$Runtime
 $payload=Join-Path $run $release
 New-Item -ItemType Directory -Path $payload -Force|Out-Null
 $app=Join-Path $payload 'app'
 $log=Join-Path $run ($role.Name+'-publish.log')
 & $Dotnet publish (Join-Path $repo "src/$($role.Project)/$($role.Project).csproj") -c Release -r $Runtime --self-contained true --artifacts-path $artifacts -o $app -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false 2>&1 | Out-File $log
 if($LASTEXITCODE){throw "Publication failed: $log"}
 if([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $app ($role.Assembly+'.dll'))).FileVersion -ne ($role.Version+'.0')){throw 'Assembly identity mismatch.'}
 Copy-Item -Path (Join-Path $repo "packaging/$($role.Packaging)/*") -Destination $payload -Recurse
 $nativeGaps=@('Native Linux three-pass QA has not run for this source, installer or binaries.','No installation, service transition, upgrade or rollback acceptance.','No deployment or release approval.')
 if($role.Name -eq 'client'){
  $desktop=Join-Path $payload 'desktop'
  & $Dotnet publish (Join-Path $repo 'src/seQuester.UnixDesktop/seQuester.UnixDesktop.csproj') -c Release -r $Runtime --self-contained true --artifacts-path $artifacts -o $desktop -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false 2>&1 | Out-File (Join-Path $run 'desktop-publish.log')
  if($LASTEXITCODE){throw 'Desktop publication failed.'}
  if([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $desktop 'RansomFree.UnixDesktop.dll')).FileVersion -ne '0.9.2.0'){throw 'Desktop identity mismatch.'}
  if($RelayProof -and $RelayDirectory){
   $proof=Get-Content -LiteralPath $RelayProof -Raw|ConvertFrom-Json
   if($proof.Runtime -ne $Runtime -or $proof.Version -ne '0.9.1' -or $proof.ProtocolVersion -ne 1){throw 'Native relay proof identity mismatch.'}
   foreach($pair in @(@('Program.cs',$proof.ProgramSha256),@('seQuester.AuditRelay.csproj',$proof.ProjectSha256))){if((Get-FileHash -LiteralPath (Join-Path $repo ('src/seQuester.AuditRelay/'+$pair[0]))).Hash -ne $pair[1]){throw 'Native relay source mismatch.'}}
   if((Get-FileHash -LiteralPath (Join-Path $RelayDirectory 'RansomFree.AuditRelay')).Hash -ne $proof.BinarySha256){throw 'Native relay binary mismatch.'}
   $relay=Join-Path $payload 'audit-relay';New-Item -ItemType Directory -Path $relay|Out-Null
   Copy-Item -LiteralPath (Join-Path $RelayDirectory 'RansomFree.AuditRelay') -Destination $relay
   foreach($item in $proof.EvidenceFiles.PSObject.Properties){$file=Join-Path $RelayDirectory $item.Name;if((Get-FileHash -LiteralPath $file).Hash -ne $item.Value){throw 'Relay evidence mismatch.'};Copy-Item -LiteralPath $file -Destination $relay}
   Copy-Item -LiteralPath $RelayProof -Destination (Join-Path $relay 'UNCHANGED-RELAY-PROVENANCE.json')
   [IO.File]::WriteAllText((Join-Path $relay 'LAUNCHER_IDENTITY'),$release+"`n"+$Runtime+"`n"+$proof.BinarySha256.ToLowerInvariant()+"`n",$utf8)
   $nativeGaps+='Reused unchanged relay proof is historical component provenance only; it does not validate the new installer, agent, or combined runtime.'
  }else{
   $nativeGaps+='Native AOT audit relay absent: this architecture staging tree is incomplete and cannot be installed.'
  }
 }
 [IO.File]::WriteAllText((Join-Path $payload 'RELEASE_ID'),$release+"`n",$utf8)
 [IO.File]::WriteAllText((Join-Path $payload 'RUNTIME_ID'),$Runtime+"`n",$utf8)
 # Only parse shell files. Never execute installers, service operations or native hosts.
 foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File -Filter '*.sh'){
  & $Bash -n $file.FullName 2>&1|Out-File (Join-Path $run ($role.Name+'-shell.log')) -Append
  if($LASTEXITCODE){throw 'Shell syntax check failed.'}
 }
 $machine=if($Runtime -eq 'linux-x64'){62}else{183}
 foreach($base in @($app)+$(if($role.Name -eq 'client'){@($desktop)}else{@()})){
  foreach($file in Get-ChildItem -LiteralPath $base -File){
   if($file.Extension -eq '.so' -or $file.Name -in @('RansomFree.Server','RansomFree.LinuxAgent','RansomFree.UnixDesktop')){
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    if($bytes.Length -lt 20 -or $bytes[0] -ne 127 -or [Text.Encoding]::ASCII.GetString($bytes,1,3) -ne 'ELF' -or $bytes[4] -ne 2 -or $bytes[5] -ne 1 -or $bytes[18] -ne $machine -or $bytes[19] -ne 0){throw "ELF architecture mismatch: $($file.Name)"}
   }
  }
 }
 $libraries=@{}
 foreach($deps in Get-ChildItem -LiteralPath $payload -Recurse -Filter '*.deps.json'){
  $data=Get-Content -LiteralPath $deps.FullName -Raw|ConvertFrom-Json
  foreach($lib in $data.libraries.PSObject.Properties){if($lib.Value.type -eq 'package'){$libraries[$lib.Name]=$lib.Value}}
 }
 $components=@(foreach($key in ($libraries.Keys|Sort-Object)){$cut=$key.LastIndexOf('/');$name=$key.Substring(0,$cut);$version=$key.Substring($cut+1);[ordered]@{type='library';name=$name;version=$version;purl=('pkg:nuget/'+$name+'@'+$version)}})
 Write-Json (Join-Path $payload 'sbom.cdx.json') ([ordered]@{bomFormat='CycloneDX';specVersion='1.5';version=1;metadata=@{timestamp=[DateTime]::UtcNow.ToString('o');component=@{type='application';name=$role.Assembly;version=$role.Version}};components=$components})
 Write-Json (Join-Path $payload 'QA-ONLY.json') ([ordered]@{Status='UNACCEPTED QA STAGING ONLY';Release=$release;Runtime=$Runtime;SourceManifestSha256=$sourceHash;NativeAcceptance='PENDING';ReleaseApproval=$false;Signed=$false;Gaps=$nativeGaps;SbomScope='NuGet components from published deps.json; OS packages and native runtime subcomponents require native inventory.'})
 $files=@(Get-ChildItem -LiteralPath $payload -Recurse -File|Sort-Object FullName|ForEach-Object {[ordered]@{Path=[IO.Path]::GetRelativePath($payload,$_.FullName).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 Write-Json (Join-Path $payload 'manifest.json') ([ordered]@{Release=$release;SourceManifestSha256=$sourceHash;Files=$files})
 $sums=@(Get-ChildItem -LiteralPath $payload -Recurse -File|Sort-Object FullName|ForEach-Object {(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetRelativePath($payload,$_.FullName).Replace('\','/')})
 [IO.File]::WriteAllLines((Join-Path $payload 'SHA256SUMS'),$sums,$utf8)
 $archive=$payload+'-UNACCEPTED-QA-STAGING.zip'
 # Unix file type/mode metadata is required for reliable native extraction.
 $zipScript=@'
import pathlib, shutil, sys, zipfile
root=pathlib.Path(sys.argv[1])
hosts={'app/RansomFree.Server','app/RansomFree.LinuxAgent','desktop/RansomFree.UnixDesktop','audit-relay/RansomFree.AuditRelay'}
with zipfile.ZipFile(sys.argv[2], 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for file in sorted(root.rglob('*')):
        if not file.is_file(): continue
        name=file.relative_to(root).as_posix()
        entry=zipfile.ZipInfo(name)
        entry.create_system=3
        entry.external_attr=(0o100755 if name.endswith('.sh') or name in hosts else 0o100644)<<16
        entry.compress_type=zipfile.ZIP_DEFLATED
        with file.open('rb') as src, archive.open(entry,'w') as dst: shutil.copyfileobj(src,dst)
'@
 & $Python -3 -c $zipScript $payload $archive 2>&1 | Out-File (Join-Path $run ($role.Name+'-archive.log'))
 if($LASTEXITCODE){throw 'Unix-mode archive creation failed.'}
 $outputs+=[ordered]@{Role=$role.Name;Release=$release;Payload=$payload;Archive=$archive;ArchiveSha256=(Get-FileHash -LiteralPath $archive).Hash;PayloadManifestSha256=(Get-FileHash -LiteralPath (Join-Path $payload 'manifest.json')).Hash;Status='UNACCEPTED QA STAGING ONLY'}
}
Assert-Source
Write-Json (Join-Path $run 'build-result.json') ([ordered]@{SourceManifestSha256=$sourceHash;Runtime=$Runtime;Outputs=$outputs;NativeTests='NOT RUN';InstallersExecuted=$false;WindowsPackageBuilt=$false})
Get-Content (Join-Path $run 'build-result.json')
