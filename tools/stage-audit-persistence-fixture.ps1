$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$context='D:\Codex\RansomFree\audit-health-0.9.10-fixture-r1'
$agentSourceRevision='8c36e2aedf3abe06513bce3c1b5e1d9ae6ab9b5a'
if(Test-Path -LiteralPath (Join-Path $context 'FIXTURE-SHA256SUMS')){throw 'Frozen fixture context already exists.'}
$env:TEMP='D:\Codex\RansomFree\temp';$env:TMP=$env:TEMP
$env:NUGET_PACKAGES='D:\Codex\RansomFree\nuget-packages';$env:NUGET_HTTP_CACHE_PATH='D:\Codex\RansomFree\nuget-http-cache'
$sdk='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe'
[void][IO.Directory]::CreateDirectory($context)
foreach($entry in @(@('src/seQuester.LinuxAgent','app'),@('tools/AuditStatusFixture','status-fixture'),@('tools/AuditHealthFixture','health-fixture'),@('tools/EndpointHealthSummaryFixture','summary-fixture'),@('tools/AuditRuleMaskFixture','mask-fixture'),@('tools/AuditRuleFixture','fixture'))){
    & $sdk publish (Join-Path $repo $entry[0]) -c Release -r linux-x64 --self-contained true --artifacts-path D:\Codex\RansomFree\artifacts -o (Join-Path $context $entry[1]) -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false -p:SourceRevisionId=$agentSourceRevision
    if($LASTEXITCODE -ne 0){throw 'Fixture publish failed; partial output preserved.'}
}
foreach($entry in @(@('tools/audit-launcher-fixture.Dockerfile','Dockerfile'),@('tools/audit-launcher-fixture.sh','fixture.sh'),@('tools/audit-rule-lifecycle-fixture.sh','lifecycle.sh'),@('packaging/linux-client/audit/launch-relay.sh','launch-relay.sh'),@('packaging/linux-client/audit/sequester.conf.example','sequester.conf.example'),@('packaging/linux-client/audit/sequester-audit-rules.service','sequester-audit-rules.service'))){Copy-Item -LiteralPath (Join-Path $repo $entry[0]) -Destination (Join-Path $context $entry[1])}
[void][IO.Directory]::CreateDirectory((Join-Path $context 'harness'))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'audit-mask-debian.Dockerfile') -Destination (Join-Path $context 'Debian.Dockerfile')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'audit-mask-fixture.sh') -Destination (Join-Path $context 'mask.sh')
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'AuditLauncherFixture') -File | Copy-Item -Destination (Join-Path $context 'harness')
foreach($file in Get-ChildItem -LiteralPath $context -File | Where-Object { $_.Extension -in @('.sh','.service','.example','.Dockerfile') -or $_.Name -eq 'Dockerfile' }){
    [IO.File]::WriteAllText($file.FullName,[IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
}
foreach($name in @('fixture.sh','lifecycle.sh','launch-relay.sh','mask.sh')){& 'C:\Program Files\Git\bin\bash.exe' -n (Join-Path $context $name);if($LASTEXITCODE -ne 0){throw 'Fixture syntax failed.'}}
$files=@(Get-ChildItem -LiteralPath $context -Recurse -File | Sort-Object FullName)
$sums=@($files|ForEach-Object{(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.FullName.Substring($context.Length+1).Replace('\','/')})
[IO.File]::WriteAllText((Join-Path $context 'FIXTURE-SHA256SUMS'),($sums -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
$archive=$context+'.tar.gz'
if(Test-Path -LiteralPath $archive){throw 'Fixture archive already exists.'}
& tar --format=ustar -czf $archive -C $context .
if($LASTEXITCODE -ne 0){throw 'Fixture archive failed.'}
[pscustomobject]@{Archive=$archive;Sha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash;Files=$files.Count+1}|ConvertTo-Json
