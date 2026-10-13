param([string]$ResultsDirectory='D:\Codex\RansomFree\release-qa', [Parameter(Mandatory)][string]$PublishedServer)
$ErrorActionPreference='Stop'
$source=Split-Path $PSScriptRoot -Parent
$out=$ResultsDirectory
$qaTemp=if((Get-PSDrive D -ErrorAction SilentlyContinue).Free-gt2GB){'D:\Codex\RansomFree\temp'}else{Join-Path $out 'temp'}
New-Item -ItemType Directory -Path $qaTemp -Force|Out-Null
$env:TEMP=$qaTemp;$env:TMP=$env:TEMP
$env:RF_QA_RESULTS=Join-Path $out 'test-results'
$dotnet='C:\Program Files\dotnet\dotnet.exe'
$server=(Resolve-Path -LiteralPath $PublishedServer).Path
New-Item -ItemType Directory -Path (Join-Path $out 'logs') -Force|Out-Null
Set-Location $source
$projects=@('tests/seQuester.Server.Tests','tests/seQuester.Canary.Tests','tools/EventHistoryFixture','tools/ActivityContractFixture','tools/DecoyServiceFixture','tools/DecoyJobsFixture','tools/TrustGovernanceFixture','tools/WhitelistFixture','tools/ServiceDeliveryFixture','tools/DecoySessionFixture','tools/EndpointHealthSummaryFixture','tools/WindowsProtectionFixture','tools/WindowsTrustCaptureFixture','tools/WindowsAuditParserFixture','tools/AuditPacketFixture','tools/AuditHealthFixture','tools/AuditStatusFixture','tools/AuditRuleFixture','tools/TrustCacheFixture','tools/N05ServerFixture')
$results=@()
$projects+=@('tools/AdvancedTrustFixture','tools/LinuxIoFixture','tools/NativeResponseFixture','tools/SyslogReceiptFixture')
$uxLog=Join-Path $out 'logs/product-ux.txt'
& 'C:\Program Files\nodejs\node.exe' (Join-Path $source 'tools/check-product-ux.mjs') --self-test *> $uxLog
$uxExit=$LASTEXITCODE
if($uxExit-eq0){& 'C:\Program Files\nodejs\node.exe' (Join-Path $source 'tools/check-product-ux.mjs') *>> $uxLog;$uxExit=$LASTEXITCODE}
$results+=@{Name='product-ux';Stage='Executed';Exit=$uxExit;Log=$uxLog}
Write-Output ('product-ux: '+$uxExit)
foreach($project in $projects){
 $projectFiles=@(Get-ChildItem -LiteralPath $project -Filter '*.csproj' -File)
 if($projectFiles.Count-ne1){throw "Expected exactly one project file in $project"}
 $projectFile=$projectFiles[0].FullName
 $projectName=[IO.Path]::GetFileNameWithoutExtension($projectFile)
 [xml]$projectDefinition=Get-Content -LiteralPath $projectFile -Raw
 $assemblyNode=$projectDefinition.SelectSingleNode('/Project/PropertyGroup/AssemblyName')
 $name=if($assemblyNode){$assemblyNode.InnerText}else{$projectName}
 $log=Join-Path $out ('logs/'+$name+'.txt')
 & $dotnet build $projectFile -c Release --artifacts-path (Join-Path $out 'artifacts') -p:NuGetAudit=false -v quiet *> ($log+'.build')
 if($LASTEXITCODE-ne0){$results+=@{Name=$name;Stage='Build';Exit=$LASTEXITCODE;Log=$log+'.build'};Write-Output ('FAIL BUILD '+$name);continue}
 $bin=Join-Path $out ('artifacts/bin/'+$projectName+'/release/'+$name+'.dll')
 $params=@($bin)
 if($name-in@('RansomFree.Server.Tests','EventHistoryFixture','N05ServerFixture')){$params+=@($dotnet,$server)}
 if($name-eq'RansomFree.Canary.Tests'){
  $receiver=Join-Path $out 'receiver'
  & $dotnet publish src/seQuester.Receiver/seQuester.Receiver.csproj -c Release --artifacts-path (Join-Path $out 'artifacts') -o $receiver -p:NuGetAudit=false -v quiet *> ($log+'.receiver-build')
  if($LASTEXITCODE-ne0){throw 'Receiver fixture publish failed'}
  $params+=@($dotnet,(Join-Path $receiver 'RansomFree.Receiver.dll'))
 }
 Push-Location $out
 try{& $dotnet @params *> $log;$exit=$LASTEXITCODE}finally{Pop-Location}
 $passes=@(Get-Content $log|Where-Object {$_-match'^PASS[: ]'}).Count
 $results+=@{Name=$name;Stage='Executed';Exit=$exit;PassLines=$passes;Log=$log}
 Write-Output (('{0}: {1}, {2} pass lines' -f $name,$exit,$passes))
 $results|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $out 'REGRESSION.json') -Encoding utf8
}
foreach($name in 'sensor-table-dom','event-history-dom','ui-presentation-fixture'){
 $log=Join-Path $out ('logs/'+$name+'.txt')
 & 'C:\Program Files\nodejs\node.exe' (Join-Path $source ('tools/'+$name+'.mjs')) *> $log
 $exit=$LASTEXITCODE;$results+=@{Name=$name;Stage='Executed';Exit=$exit;PassLines=@(Get-Content $log|Where-Object {$_-match'^PASS[: ]'}).Count;Log=$log}
 Write-Output ($name+': '+$exit)
}
$results|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $out 'REGRESSION.json') -Encoding utf8
if(@($results|Where-Object {$_.Exit-ne0}).Count){exit 1}
