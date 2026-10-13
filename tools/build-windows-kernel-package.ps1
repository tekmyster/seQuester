[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Driver,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedDriverSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{6}(\.[0-9]+)?$')][string]$Altitude,
    [ValidateSet('IsolatedTest','MicrosoftAssigned')][string]$AltitudeStatus='IsolatedTest',
    [string]$AssignmentRecord,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$AssignmentRecordSha256,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$ToolchainRoot='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain',
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string]$DriverVersion='0.1.0.4',
    [datetime]$DriverDate=[datetime]'2026-10-01'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# This builds a submission/qualification candidate only. It neither installs a
# driver nor certifies its signature, altitude allocation, or OS compatibility.
$repo=Split-Path $PSScriptRoot -Parent
$source=(Get-Item -LiteralPath $Driver).FullName
if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $ExpectedDriverSha256){throw 'Driver differs from the accepted input hash.'}
if([decimal]::Parse($Altitude,[Globalization.CultureInfo]::InvariantCulture) -lt 360000 -or [decimal]::Parse($Altitude,[Globalization.CultureInfo]::InvariantCulture) -ge 390000){throw 'Altitude is outside FSFilter Activity Monitor.'}
$assignment=$null
if($AltitudeStatus -eq 'MicrosoftAssigned'){
    if([decimal]::Parse($Altitude,[Globalization.CultureInfo]::InvariantCulture) -eq [decimal]::Parse('385200.923',[Globalization.CultureInfo]::InvariantCulture)){throw 'The isolated test altitude cannot be promoted to an assigned altitude.'}
    if(!$AssignmentRecord -or !$AssignmentRecordSha256){throw 'Archive and pin the reviewed Microsoft assignment before preparing its package.'}
    $record=Get-Item -LiteralPath $AssignmentRecord
    if($record.Length -eq 0 -or (Get-FileHash -LiteralPath $record.FullName).Hash -ine $AssignmentRecordSha256){throw 'Assignment record is empty or changed.'}
    $assignment=[ordered]@{Record=$record.Name;Sha256=$AssignmentRecordSha256.ToUpperInvariant();Validation='Operator-reviewed Microsoft correspondence; not authenticated by this builder'}
}elseif($AssignmentRecord -or $AssignmentRecordSha256){throw 'An isolated test package cannot claim assignment evidence.'}
$infverif=Join-Path $ToolchainRoot 'wdk\c\tools\10.0.26100.0\x64\infverif.exe'
$inf2cat=Join-Path $ToolchainRoot 'wdk\c\bin\10.0.26100.0\x86\Inf2Cat.exe'
foreach($tool in $infverif,$inf2cat){if(!(Test-Path -LiteralPath $tool -PathType Leaf)){throw "Missing WDK tool: $tool"}}
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Package destination already exists; existing evidence is never overwritten.'}
New-Item -ItemType Directory -Path $output|Out-Null
$checks=@()
$profiles=@(
    @{Name='server-legacy';Template='legacy';Os='Server6_3_X64,ServerRS5_X64';Validation=@('/v');Scope=@('6.3.9600.18734 x64','10.0.17763.9020 x64')},
    @{Name='windows10';Template='modern';Os='10_VB_X64';Validation=@('/v','/u');Scope=@('10.0.19045.6456 x64')}
)
foreach($profile in $profiles){
    $folder=Join-Path $output $profile.Name;New-Item -ItemType Directory -Path $folder|Out-Null
    Copy-Item -LiteralPath $source -Destination (Join-Path $folder 'SeQuesterActor.sys')
    if((Get-FileHash -LiteralPath (Join-Path $folder 'SeQuesterActor.sys')).Hash -ine $ExpectedDriverSha256){throw 'Driver copy hash mismatch.'}
    $template=Join-Path $repo ('packaging\windows-kernel\SeQuesterActor.'+$profile.Template+'.inf.in')
    $body=[IO.File]::ReadAllText($template).Replace('@ALTITUDE@',$Altitude).Replace('@DRIVER_VERSION@',$DriverVersion).Replace('@DRIVER_DATE@',$DriverDate.ToString('MM/dd/yyyy',[Globalization.CultureInfo]::InvariantCulture))
    if($body -match '@[A-Z_]+@'){throw 'Unresolved INF token.'}
    $inf=Join-Path $folder 'SeQuesterActor.inf'
    [IO.File]::WriteAllText($inf,($body -replace '\r?\n',"`r`n"),[Text.Encoding]::ASCII)
    $log=@(& $infverif @($profile.Validation) $inf 2>&1);$exit=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $output ($profile.Name+'-infverif.log'))
    if($exit -ne 0){throw "INF validation failed: $($profile.Name). Evidence retained."}
    $log=@(& $inf2cat ('/driver:'+$folder) ('/os:'+$profile.Os) /verbose 2>&1);$exit=$LASTEXITCODE
    $log|Set-Content -LiteralPath (Join-Path $output ($profile.Name+'-inf2cat.log'))
    if($exit -ne 0 -or !(Test-Path -LiteralPath (Join-Path $folder 'SeQuesterActor.cat'))){throw "Catalog generation failed: $($profile.Name). Evidence retained."}
    $checks += [ordered]@{Profile=$profile.Name;InfVerif='Passed';Inf2Cat='Passed';Inf2CatTargets=$profile.Os;QualificationTargetBuilds=$profile.Scope;NativeQualification='Requires separate evidence tied to these driver bytes';PackageInstallationQualification='Pending'}
}
if($assignment){
    $copiedRecord=Join-Path $output 'altitude-assignment.record'
    Copy-Item -LiteralPath $AssignmentRecord -Destination $copiedRecord
    if((Get-FileHash -LiteralPath $copiedRecord).Hash -ine $AssignmentRecordSha256){throw 'Assignment record changed during packaging.'}
}
$files=@(Get-ChildItem -LiteralPath $output -Recurse -File|Sort-Object FullName|ForEach-Object{[ordered]@{Path=$_.FullName.Substring($output.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
$manifest=[ordered]@{
    SchemaVersion=1;Product='seQuester';DriverVersion=$DriverVersion;Protocol=4;CreatedUtc=[DateTime]::UtcNow.ToString('o')
    DriverSha256=$ExpectedDriverSha256.ToUpperInvariant();Altitude=$Altitude;AltitudeStatus=$AltitudeStatus;Assignment=$assignment
    ProductionReady=$false;MicrosoftSigning='Pending';HlkCertification='Pending';PackageInstallationQualification='Pending';Checks=$checks;Files=$files
}
$manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding utf8
[ordered]@{Output=$output;ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $output 'manifest.json')).Hash;Checks=$checks;ProductionReady=$false}|ConvertTo-Json -Depth 5
