param([Parameter(Mandatory)][string]$BuildDirectory,[Parameter(Mandatory)][string]$ActorDirectory,[Parameter(Mandatory)][string]$QaParent,[Parameter(Mandatory)][string]$ExpectedHost,[switch]$Worker,[string]$RunRoot)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME-cne$ExpectedHost){throw 'Exact owned host required'}
if(!(Test-Path (Join-Path $QaParent 'reports'))){throw 'Existing qualified report parent required; no ACL changes'}
if(!$Worker){
 $id=[guid]::NewGuid().ToString('N');$RunRoot=Join-Path $QaParent ('api-observer-'+$id)
 if(Test-Path $RunRoot){throw 'Fresh owned run required'}
 New-Item -ItemType Directory $RunRoot|Out-Null
 $plan=[ordered]@{BuildDirectory=$BuildDirectory;ActorDirectory=$ActorDirectory;QaParent=$QaParent;ExpectedHost=$ExpectedHost;RunRoot=$RunRoot}
 $plan|ConvertTo-Json|Set-Content (Join-Path $RunRoot 'plan.json')
 $task='sequester-api-observer-'+$id
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$a=@{};`$o=Get-Content '$RunRoot\plan.json' -Raw|ConvertFrom-Json;foreach(`$p in `$o.PSObject.Properties){`$a[`$p.Name]=`$p.Value};& '$PSCommandPath' @a -Worker"))
 $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+$encoded)
 $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
 Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::Zero))|Out-Null
 try {
  Start-ScheduledTask $task;$deadline=[datetime]::UtcNow.AddMinutes(5)
  $result=Join-Path $RunRoot 'RESULT.json'
  while(!(Test-Path $result)-and[datetime]::UtcNow-lt$deadline){Start-Sleep -Seconds 2}
  if(!(Test-Path $result)){throw 'Owned test unresolved; task and process retained for investigation'}
  Get-Content $result -Raw
 }finally {if((Get-ScheduledTask $task).State-ne'Running'){Unregister-ScheduledTask $task -Confirm:$false}}
 return
}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value-cne'S-1-5-18'){throw 'SYSTEM worker required'}
$manifest=Get-Content (Join-Path $BuildDirectory 'BUILD-MANIFEST.json') -Raw|ConvertFrom-Json
foreach($output in $manifest.Outputs){if((Get-FileHash (Join-Path $BuildDirectory $output.Name)).Hash-cne$output.Sha256){throw 'Observer input changed'}}
foreach($file in (Get-Content (Join-Path $ActorDirectory 'ACTOR-MANIFEST.json') -Raw|ConvertFrom-Json).Files){if((Get-FileHash (Join-Path $ActorDirectory $file.Path)).Hash-cne$file.Sha256){throw 'Actor input changed'}}
$reportRoot=Join-Path (Join-Path $QaParent 'reports') (Split-Path $RunRoot -Leaf)
New-Item -ItemType Directory $reportRoot|Out-Null
$cases=@();$negative=@();$errorText=$null;$unresolved=$null
function SameToken($actual,$truth){
 if(!$actual-or$actual.State-cne'captured'){return $false}
 foreach($pair in @(@('Sid','UserSid'),@('TokenId','TokenId'),@('AuthenticationId','AuthenticationId'),@('ModifiedId','ModifiedId'),@('Type','TokenType'),@('ImpersonationLevel','ImpersonationLevel'),@('SessionId','SessionId'),@('IntegrityRid','IntegrityRid'),@('Elevated','Elevated'))){if($actual.($pair[0])-cne$truth.($pair[1])){return $false}}
 return $true
}
try {
 foreach($operation in @('denied-handle-read','denied-handle-write','denied-handle-append','denied-handle-truncate','denied-handle-rename','denied-handle-delete','locked-handle-read','locked-handle-write')){
  $file=Join-Path $RunRoot ($operation+'.bin');[IO.File]::WriteAllBytes($file,[byte[]]::new(8192))
  $truthPath=Join-Path $reportRoot ($operation+'.actor.json');$log=Join-Path $reportRoot ($operation+'.observer.jsonl')
  $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=Join-Path $BuildDirectory 'Launch64.exe';$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle='Hidden';$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $argument='"'+$operation+'" "'+$file+'" "'+$truthPath+'" --exit-immediately'
  # The launcher's fourth argument is the child's complete command line.
  $escaped=$argument.Replace('"','\"')
  $start.Arguments='"'+(Join-Path $BuildDirectory 'Observer64.dll')+'" "'+(Join-Path $ActorDirectory 'WindowsActorFixture.exe')+'" "'+$escaped+'"'
  $start.EnvironmentVariables['SQ_FIXTURE_LOCAL_SERVICE']='1';$start.EnvironmentVariables['SQ_OBSERVER_TARGET']=$file;$start.EnvironmentVariables['SQ_OBSERVER_LOG']=$log
  $lock=$null
  try {
   if($operation.StartsWith('locked-')){$lock=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete);$lock.Lock(0,1)}
   $child=[Diagnostics.Process]::Start($start)
   if(!$child.WaitForExit(45000)){$unresolved=$child.Id;throw 'Owned launcher unresolved; no forced termination'}
   $stdout=$child.StandardOutput.ReadToEnd();$stderr=$child.StandardError.ReadToEnd();$stderr|Set-Content ($truthPath+'.stderr')
   if($child.ExitCode-ne0){throw ('Owned launch failed '+$operation+' '+$stderr)}
   $owned=$stdout.Trim()|ConvertFrom-Json;$truth=Get-Content $truthPath -Raw|ConvertFrom-Json
   if(!$owned.ProcessBirthKnown-or$truth.ProcessId-ne$owned.Pid-or$truth.ProcessCreatedUtcFileTime-ne$owned.ProcessCreatedFileTime){throw 'Actual actor differs from owned child handle'}
   $observed=@();if(Test-Path $log){$observed=@(Get-Content $log|ForEach-Object {$_|ConvertFrom-Json})}
   $major=switch($operation){{$_-match'read$'}{'NtReadFile'};{$_-match'(write|append)$'}{'NtWriteFile'};default{'NtSetInformationFile'}}
   $matched=@($observed|Where-Object {$_.Operation-ceq$major-and$_.Pid-eq$truth.ProcessId-and$_.ProcessCreatedFileTime-eq$truth.ProcessCreatedUtcFileTime-and$_.ThreadId-eq$truth.ThreadId-and$_.Path-ieq$file-and$_.Impersonating-eq$true-and$_.TokenObservationStableAcrossCall-and(SameToken $_.ProcessPrimary $truth.Primary)-and(SameToken $_.ThreadEffective $truth.Effective)-and$_.NtStatus-in$(if($operation.StartsWith('locked-')){@('0xC0000054','0xC0000055')}else{@('0xC0000022')})})
   $expected=if($operation.StartsWith('locked-')){33}else{5}
   if($truth.Outcome-cne'Failed'-or$truth.NativeWin32Error-ne$expected-or(Get-Item $file).Length-ne8192-or(Test-Path ($file+'.renamed'))){throw 'Actor outcome or target bytes changed'}
   $cases+=,[ordered]@{Operation=$operation;Pid=$truth.ProcessId;ThreadId=$truth.ThreadId;NativeError=$truth.NativeWin32Error;ObserverMatched=$matched.Count-gt0;ObserverRecords=$observed;Truth=$truth;OwnerTruth=$owned}
  }finally{if($lock){$lock.Unlock(0,1);$lock.Dispose()}}
 }
 if(Test-Path (Join-Path $BuildDirectory 'Bypass64.exe')){
  foreach($mode in @('normal','direct')){
   $file=Join-Path $RunRoot ($mode+'-negative.bin');[IO.File]::WriteAllBytes($file,[byte[]]::new(8192))
   $log=Join-Path $reportRoot ($mode+'-negative.observer.jsonl')
   $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=Join-Path $BuildDirectory 'Launch64.exe';$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle='Hidden';$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $truthPath=Join-Path $reportRoot ($mode+'-negative.truth.json')
   $argument=$mode+' "'+$file+'" "'+$truthPath+'"';$start.Arguments='"'+(Join-Path $BuildDirectory 'Observer64.dll')+'" "'+(Join-Path $BuildDirectory 'Bypass64.exe')+'" "'+$argument.Replace('"','\"')+'"'
   $start.EnvironmentVariables['SQ_OBSERVER_TARGET']=$file;$start.EnvironmentVariables['SQ_OBSERVER_LOG']=$log
   $child=[Diagnostics.Process]::Start($start)
   if(!$child.WaitForExit(45000)){$unresolved=$child.Id;throw 'Owned negative launcher unresolved; retained'}
   $stdout=$child.StandardOutput.ReadToEnd();$stderr=$child.StandardError.ReadToEnd()
   if($child.ExitCode-ne0){throw ('Owned negative fixture failed '+$mode+' '+$stderr)}
   $stdout|Set-Content ($truthPath+'.launcher.json');$stderr|Set-Content ($truthPath+'.stderr')
   $outputs=@($stdout.Trim()-split"`n"|ForEach-Object {$_|ConvertFrom-Json});$owner=@($outputs|Where-Object {$_.ProcessBirthKnown});$truth=@(Get-Content $truthPath -Raw|ConvertFrom-Json)
   if($owner.Count-ne1-or$truth.Count-ne1-or$owner[0].Pid-ne$truth[0].Pid-or$truth[0].NtStatus-cne'0xC0000022'-or$truth[0].Direct-ne($mode-ceq'direct')-or(Get-Item $file).Length-ne8192){throw 'Negative fixture native/owned-process truth mismatch'}
   $observed=@();if(Test-Path $log){$observed=@(Get-Content $log|ForEach-Object {$_|ConvertFrom-Json})}
   $matched=@($observed|Where-Object {$_.Pid-eq$truth[0].Pid-and$_.ThreadId-eq$truth[0].ThreadId-and$_.ProcessCreatedFileTime-eq$owner[0].ProcessCreatedFileTime-and$_.Operation-ceq'NtReadFile'-and$_.NtStatus-ceq'0xC0000022'-and$_.Path-ieq$file})
   if($mode-ceq'normal'-and!$matched.Count){throw 'Normal-call positive control absent'}
   if($mode-ceq'direct'-and$matched.Count){throw 'Negative control unexpectedly captured; reassess coverage'}
   $negative+=,[ordered]@{Mode=$mode;ObserverMatched=$matched.Count-gt0;ExpectedObservation=$mode-ceq'normal';Truth=$truth[0];OwnerTruth=$owner[0];Observed=$observed}
  }
 }
}catch{$errorText=$_.Exception.Message}
$result=[ordered]@{Host=$ExpectedHost;RunRoot=$RunRoot;PrototypeOnly=$true;IndependentKernelEvidence=$false;Passed=(!$errorText-and$cases.Count-eq8-and!@($cases|Where-Object {!$_.ObserverMatched}).Count);Error=$errorText;OwnedLauncherUnresolved=$unresolved;NoAclOrCredentialChanges=$true;NoSensorSettingsOrServiceChanges=$true;Cases=$cases;NegativeControls=$negative;CompletedUtc=[datetime]::UtcNow.ToString('o')}
$temporary=Join-Path $RunRoot 'RESULT.pending';$result|ConvertTo-Json -Depth 24|Set-Content $temporary;Move-Item -LiteralPath $temporary -Destination (Join-Path $RunRoot 'RESULT.json')
