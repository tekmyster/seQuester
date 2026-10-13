param([Parameter(Mandatory)][string]$Package,[Parameter(Mandatory)][string]$ResultDirectory)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if(Test-Path -LiteralPath $ResultDirectory){throw 'Test results already exist'}
New-Item -ItemType Directory -Path $ResultDirectory|Out-Null
$checks=[Collections.Generic.List[string]]::new()
function Check([bool]$condition,[string]$name){if(!$condition){throw $name};$checks.Add($name)}
$manifest=Get-Content (Join-Path $Package 'manifest.json') -Raw|ConvertFrom-Json
Check ($manifest.ProductionReady -eq $false -and $manifest.MicrosoftSigning -eq 'Pending') 'WDK validation does not claim Microsoft signing or production readiness'
Check ($manifest.AltitudeStatus -eq 'IsolatedTest' -and $null -eq $manifest.Assignment) 'Test altitude remains explicitly unassigned'
foreach($f in $manifest.Files){Check ((Get-FileHash (Join-Path $Package $f.Path)).Hash -eq $f.Sha256) ('Immutable package file: '+$f.Path)}
foreach($profile in 'server-legacy','windows10'){
 $body=Get-Content (Join-Path $Package ($profile+'\SeQuesterActor.inf')) -Raw
 Check ($body.Contains('StartType = 3') -and $body.Contains('Dependencies = FltMgr')) ($profile+' demand start with Filter Manager dependency')
 Check ($body.Contains('"385200.923"') -and $body.Contains('Flags",0x00010001,0')) ($profile+' exact lab altitude and automatic attachment flags')
 Check ((Get-Content (Join-Path $Package ($profile+'-infverif.log')) -Raw) -notmatch 'WARNING\(|ERROR\(') ($profile+' WDK validator has no warnings or errors')
}
$modern=Get-Content (Join-Path $Package 'windows10\SeQuesterActor.inf') -Raw
$legacy=Get-Content (Join-Path $Package 'server-legacy\SeQuesterActor.inf') -Raw
Check ($modern.Contains('ServiceBinary = %13%\SeQuesterActor.sys') -and !$modern.Contains('[DefaultUninstall')) 'Modern INF uses Driver Store and primitive uninstall semantics'
Check ($legacy.Contains('ServiceBinary = %12%\SeQuesterActor.sys') -and $legacy.Contains('LegacyUninstall = 1')) 'Server INF retains downlevel service installation and uninstall support'
$driver=Join-Path $Package 'server-legacy\SeQuesterActor.sys'
$builder=Join-Path $PSScriptRoot 'build-windows-kernel-package.ps1'
$common=@{Driver=$driver;ExpectedDriverSha256=$manifest.DriverSha256;Altitude='385200.923'}
function Reject([string]$name,[hashtable]$changes,[string]$expected){
 $arguments=$common.Clone();$arguments.OutputDirectory=Join-Path $ResultDirectory ('rejected-'+$checks.Count)
 foreach($k in $changes.Keys){$arguments[$k]=$changes[$k]}
 $failed=$false
 try{& $builder @arguments|Out-Null}catch{$failed=$_.Exception.Message -match $expected}
 Check $failed $name
 if($arguments.OutputDirectory -ne $Package){Check (!(Test-Path -LiteralPath $arguments.OutputDirectory)) ($name+' makes no output changes')}
}
Reject 'Mismatched driver bytes rejected' @{ExpectedDriverSha256=('0'*64)} 'accepted input hash'
Reject 'Existing package not overwritten' @{OutputDirectory=$Package} 'already exists'
Reject 'Wrong load-order range rejected' @{Altitude='123456'} 'outside FSFilter'
Reject 'INF injection rejected' @{Altitude="385200`r`nStartType=0"} 'validate argument'
Reject 'Test altitude cannot masquerade as Microsoft allocation' @{AltitudeStatus='MicrosoftAssigned'} 'cannot be promoted'
Reject 'Equivalent fractional test altitude cannot masquerade as allocation' @{Altitude='385200.9230';AltitudeStatus='MicrosoftAssigned'} 'cannot be promoted'
Reject 'Assigned altitude requires pinned correspondence' @{Altitude='365123';AltitudeStatus='MicrosoftAssigned'} 'Archive and pin'
$record=Join-Path $ResultDirectory 'synthetic-assignment.txt';[IO.File]::WriteAllText($record,'Synthetic refusal test only; not an assignment')
Reject 'Changed assignment evidence rejected' @{Altitude='365123';AltitudeStatus='MicrosoftAssigned';AssignmentRecord=$record;AssignmentRecordSha256=('0'*64)} 'empty or changed'
Reject 'Lab package cannot claim assignment evidence' @{AssignmentRecord=$record} 'cannot claim'
foreach($f in $manifest.Files){if((Get-FileHash (Join-Path $Package $f.Path)).Hash -ne $f.Sha256){throw 'Refusal test altered original package'}}
Check $true 'All refusal paths preserved the original package bytes'
[ordered]@{Passed=$true;Checks=$checks.Count;Cases=@($checks);PackageManifestSha256=(Get-FileHash (Join-Path $Package 'manifest.json')).Hash;RecordedUtc=[DateTime]::UtcNow.ToString('o');Scope='WDK packaging and refusal-path checks only; native installation recorded separately'}|ConvertTo-Json -Depth 4|Set-Content (Join-Path $ResultDirectory 'RESULTS.json')
Write-Output ("Passed "+$checks.Count+" package checks")
