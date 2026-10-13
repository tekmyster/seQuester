[CmdletBinding()]
param(
    [ValidateSet('linux-x64','linux-arm64','osx-x64','osx-arm64')][string]$Runtime='linux-x64',
    [string]$Dotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe',
    [string]$WorkRoot='D:\Codex\RansomFree',
    [string]$Bash='C:\Program Files\Git\bin\bash.exe',
    [string]$AuditRelayDirectory,
    [string]$AuditRelayEvidence=(Join-Path $PSScriptRoot 'audit-relay-build1.json')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$linux=$Runtime.StartsWith('linux-')
$platform=if($linux){'linux-client'}else{'macos-client'}
$project=if($linux){'seQuester.LinuxAgent'}else{'seQuester.MacAgent'}
$assembly=if($linux){'RansomFree.LinuxAgent'}else{'RansomFree.MacAgent'}
[xml]$projectXml=[IO.File]::ReadAllText((Join-Path $repo "src\$project\$project.csproj"))
$version=[string]$projectXml.Project.PropertyGroup.Version
if($version -notmatch '^\d+\.\d+\.\d+$'){throw 'Project release version unavailable.'}
if($linux){
    if(!$AuditRelayDirectory){throw 'Linux packaging requires a separately built Native AOT relay and matching evidence. No JIT fallback.'}
    $relayProof=Get-Content -LiteralPath $AuditRelayEvidence -Raw | ConvertFrom-Json
    if($relayProof.Runtime -ne $Runtime -or $relayProof.ProtocolVersion -ne 1){throw 'Native AOT relay runtime/protocol mismatch; build this architecture before packaging.'}
    [xml]$relayProjectXml=[IO.File]::ReadAllText((Join-Path $repo 'src\seQuester.AuditRelay\seQuester.AuditRelay.csproj'))
    if($relayProof.Version -ne [string]$relayProjectXml.Project.PropertyGroup.Version){throw 'Native AOT relay project/evidence version mismatch.'}
    foreach($item in @(@('Program.cs',$relayProof.ProgramSha256),@('seQuester.AuditRelay.csproj',$relayProof.ProjectSha256))){
        if((Get-FileHash -LiteralPath (Join-Path $repo ('src\seQuester.AuditRelay\'+$item[0])) -Algorithm SHA256).Hash -cne $item[1]){throw 'Relay source differs from native build evidence.'}
    }
    if((Get-FileHash -LiteralPath (Join-Path $AuditRelayDirectory 'RansomFree.AuditRelay') -Algorithm SHA256).Hash -cne $relayProof.BinarySha256){throw 'Native AOT binary hash mismatch.'}
    foreach($property in $relayProof.EvidenceFiles.PSObject.Properties){
        if((Get-FileHash -LiteralPath (Join-Path $AuditRelayDirectory $property.Name) -Algorithm SHA256).Hash -cne $property.Value){throw 'Native build evidence hash mismatch.'}
    }
}
$env:TEMP=Join-Path $WorkRoot 'temp'; $env:TMP=$env:TEMP
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; $env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$env:NUGET_PACKAGES=Join-Path $WorkRoot 'nuget-packages'
$env:NUGET_HTTP_CACHE_PATH=Join-Path $WorkRoot 'nuget-http-cache'
[void][IO.Directory]::CreateDirectory($env:TEMP)
$release='ransomfree-client-'+$version+'-dev.'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,12)+'-'+$Runtime
$output=Join-Path $WorkRoot ('packages\'+$platform+'\'+$release)
if(Test-Path -LiteralPath $output){throw 'Immutable destination exists.'}
$payload=Join-Path $output 'payload'; [void][IO.Directory]::CreateDirectory($payload)
if($linux){
    $relayTarget=Join-Path $payload 'audit-relay';[void][IO.Directory]::CreateDirectory($relayTarget)
    foreach($name in @('RansomFree.AuditRelay')+@($relayProof.EvidenceFiles.PSObject.Properties.Name)){
        Copy-Item -LiteralPath (Join-Path $AuditRelayDirectory $name) -Destination (Join-Path $relayTarget $name)
    }
    [IO.File]::WriteAllText((Join-Path $relayTarget 'LAUNCHER_IDENTITY'),$release+"`n"+$Runtime+"`n"+$relayProof.BinarySha256.ToLowerInvariant()+"`n",[Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath $AuditRelayEvidence -Destination (Join-Path $relayTarget 'BUILD-PROVENANCE.json')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'audit-transport-evidence-20260913.json') -Destination (Join-Path $relayTarget 'TRANSPORT-FIXTURE-EVIDENCE.json')
    if($version -notin @('0.9.7','0.9.8','0.9.9','0.9.10')){throw 'Unreviewed health fixture release version.'}
    $healthEvidence=Join-Path $PSScriptRoot ("audit-health-evidence-$version.json")
    $healthProof=Get-Content -LiteralPath $healthEvidence -Raw | ConvertFrom-Json
    if($healthProof.AgentSourceCommit -notmatch '^[0-9a-f]{40}$'){throw 'Exact native-tested agent source commit required.'}
    if($healthProof.Version -ne $version -or $healthProof.NativeFixture -ne 'PASS' -or $healthProof.HealthCases -ne 25 -or $healthProof.StatusCases -ne 17 -or $healthProof.Launcher -ne 'PASS' -or $healthProof.NativeCommandFailure -ne 'PASS' -or $healthProof.FirstConnection -ne 'PASS' -or $healthProof.Reconnection -ne 'PASS'){throw 'Current native health/launcher/normal-exit/reconnection fixture evidence required.'}
    if($version -in @('0.9.8','0.9.9','0.9.10')){
        $requiredSummaryCases=if($version -in @('0.9.9','0.9.10')){39}else{24}
        if($healthProof.SummaryCases -ne $requiredSummaryCases){throw 'Current endpoint summary native fixture evidence required.'}
        foreach($required in @('src/seQuester.LinuxAgent/EndpointHealthSummary.cs','src/seQuester.LinuxAgent/LinuxWorker.cs','src/seQuester.LinuxAgent/Monitors.cs','tools/EndpointHealthSummaryFixture/Program.cs','tools/EndpointHealthSummaryFixture/EndpointHealthSummaryFixture.csproj','packaging/linux-client/install.sh')){
            if(!$healthProof.SourceHashes.PSObject.Properties[$required]){throw 'Summary/installer source evidence missing.'}
        }
    }
    foreach($property in $healthProof.SourceHashes.PSObject.Properties){
        if((Get-FileHash -LiteralPath (Join-Path $repo $property.Name) -Algorithm SHA256).Hash -cne $property.Value){throw 'Current health/collector/launcher/command source differs from native fixture evidence.'}
    }
    Copy-Item -LiteralPath $healthEvidence -Destination (Join-Path $relayTarget 'HEALTH-FIXTURE-EVIDENCE.json')
    $ruleProof=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'audit-rule-evidence-0.9.6.json') -Raw | ConvertFrom-Json
    if($ruleProof.PlannerCases -ne 23 -or $ruleProof.UserSystemdLifecycle -ne 'PASS' -or $ruleProof.Libaudit307 -ne 'PASS' -or $ruleProof.Libaudit402 -ne 'PASS'){throw 'Required bounded rule/mask fixture evidence unavailable.'}
    foreach($property in $ruleProof.SourceHashes.PSObject.Properties){
        if((Get-FileHash -LiteralPath (Join-Path $repo $property.Name) -Algorithm SHA256).Hash -cne $property.Value){throw 'Rule fixture source differs from tested evidence.'}
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'audit-rule-evidence-0.9.6.json') -Destination (Join-Path $relayTarget 'RULE-FIXTURE-EVIDENCE.json')
    # Current health fixture reruns the unchanged 17 status/exit cases and the
    # actual updated agent's rule/health failure paths. Its source gate includes
    # Program.cs and the unchanged status/reconciliation implementations.
}
$sourceRevisionArg=@()
if($linux){$sourceRevisionArg=@("-p:SourceRevisionId=$($healthProof.AgentSourceCommit)")}
& $Dotnet publish (Join-Path $repo "src\$project\$project.csproj") -c Release -r $Runtime --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') -o (Join-Path $payload 'app') -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false @sourceRevisionArg
if($LASTEXITCODE -ne 0){throw 'Cross-publish failed; partial artifact preserved.'}
if($linux -and (Get-FileHash -LiteralPath (Join-Path $payload 'app\RansomFree.LinuxAgent.dll') -Algorithm SHA256).Hash -cne $healthProof.AgentDllSha256){throw 'Published agent differs from exact native-tested fixture binary.'}
$packaging=Join-Path $repo "packaging\$platform"
foreach($file in Get-ChildItem -LiteralPath $packaging -Recurse -File){
    $target=Join-Path $payload $file.FullName.Substring($packaging.Length+1)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    Copy-Item -LiteralPath $file.FullName -Destination $target
}
$desktop=if($linux){Join-Path $payload 'desktop'}else{Join-Path $payload 'Native\Ransom Free Endpoint.app\Contents\MacOS'}
& $Dotnet publish (Join-Path $repo 'src\seQuester.UnixDesktop\seQuester.UnixDesktop.csproj') -c Release -r $Runtime --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') -o $desktop -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false
if($LASTEXITCODE -ne 0){throw 'Managed desktop cross-publish failed; partial artifact preserved.'}
if(!$linux){
    Copy-Item -LiteralPath (Join-Path $payload 'bundle\Info.plist') -Destination (Join-Path $payload 'Native\Ransom Free Endpoint.app\Contents\Info.plist')
    $resources=Join-Path $payload 'Native\Ransom Free Endpoint.app\Contents\Resources';[void][IO.Directory]::CreateDirectory($resources)
    Copy-Item -LiteralPath (Join-Path $desktop 'Branding\sequester.icns') -Destination $resources
}
# Authored endpoint applications are C#/.NET. Native runtime/framework libraries
# and standard OS service bootstrap shell scripts are expected dependencies.
if(@(Get-ChildItem -LiteralPath $payload -Recurse -File | Where-Object Extension -in @('.py','.swift','.m','.mm')).Count){throw 'Non-.NET application source found in current package.'}
$utf8=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $payload 'RELEASE_ID'),$release+"`n",$utf8)
& (Join-Path $PSScriptRoot 'verify-unix-release-guard.ps1') -Payload $payload -Bash $Bash
foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File | Where-Object Extension -in @('.sh','.service','.desktop','.example','.plist','.md')){
    [IO.File]::WriteAllText($file.FullName,[IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n"),$utf8)
}
if(!(Test-Path -LiteralPath $Bash)){throw 'Shell syntax parser unavailable.'}
foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -Filter *.sh){& $Bash -n $file.FullName; if($LASTEXITCODE -ne 0){throw 'Shell syntax failed.'}}
if($linux){
    $plugin=[IO.File]::ReadAllText((Join-Path $payload 'audit\sequester.conf.example'))
    if($plugin -match '(?m)^\s*args\s*=' -or $plugin -match '--audit-dispatch' -or $plugin -notmatch '(?m)^path = /opt/ransomfree-client/current/audit/launch-relay.sh$'){throw 'Audit plugin must invoke zero-argument launcher; auditd 3.0.7 rejects long/empty args.'}
    foreach($line in $plugin.Split("`n")){
        if($line.Length -ge 159){throw 'Auditd 3.0.7 plugin line limit exceeded.'}
        if($line.Trim() -and !$line.TrimStart().StartsWith('#') -and $line -notmatch '^\w+ = \S+$'){throw 'Invalid single-value audit plugin syntax.'}
    }
    $launcher=[IO.File]::ReadAllText((Join-Path $payload 'audit\launch-relay.sh'))
    if($launcher -notmatch '(?m)^exec /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs "\$relay"$' -or !$launcher.Contains('ransomfree-client-'+$version+'-dev.')){throw 'Launcher capability flags/release guard mismatch.'}
    $collectorUnit=[IO.File]::ReadAllText((Join-Path $payload 'audit\sequester-audit-collector.service'))
    if($collectorUnit -notmatch '(?m)^User=root$' -or $collectorUnit -notmatch '(?m)^Group=root$' -or $collectorUnit -notmatch '(?m)^CapabilityBoundingSet=$'){throw 'Collector root credential/capability contract regression.'}
    $loader=[IO.File]::ReadAllText((Join-Path $payload 'audit\sequester-audit-rules.service'))
    foreach($line in @('ExecStart=/opt/ransomfree-client/current/app/RansomFree.LinuxAgent --audit-reconcile-rules','BindsTo=auditd.service','PartOf=auditd.service','After=auditd.service local-fs.target remote-fs.target','WantedBy=auditd.service','RemainAfterExit=yes','ReadWritePaths=/var/lib/sequester-audit')){
        if($loader.Split("`n") -cnotcontains $line){throw 'Restart-bound reconciliation unit contract regression.'}
    }
    if($loader -match '/etc/audit/rules.d|ProtectHome=true|auditctl -R|Restart='){throw 'Unsafe rule-loader namespace/retry regression.'}
}
$native=if($linux){@($assembly,'libcoreclr.so','libhostfxr.so','libe_sqlite3.so')}else{@($assembly,'libcoreclr.dylib','libhostfxr.dylib','libe_sqlite3.dylib')}
$nativePaths=@($native|ForEach-Object{Join-Path $payload "app\$_"})
$nativePaths+=Join-Path $desktop 'RansomFree.UnixDesktop'
if($linux){$nativePaths+=Join-Path $payload 'audit-relay\RansomFree.AuditRelay'}
foreach($path in $nativePaths){
    $stream=[IO.File]::OpenRead($path)
    try{
        $header=[byte[]]::new(32);if($stream.Read($header,0,32)-ne 32){throw 'Short native header.'}
        if($linux){
            $machine=if($Runtime.EndsWith('arm64')){183}else{62}
            if($header[0]-ne 127 -or [Text.Encoding]::ASCII.GetString($header,1,3)-ne 'ELF' -or $header[4]-ne 2 -or $header[5]-ne 1 -or [BitConverter]::ToUInt16($header,18)-ne $machine){throw 'ELF runtime architecture mismatch.'}
        }else{
            # .NET native dependencies may be fat/universal Mach-O; record, do not pretend to execute.
            $magic=[BitConverter]::ToUInt32($header,0)
            if($magic -notin @(0xfeedfacfL,0xcafebabeL,0xbebafecaL,0xcafebabfL,0xbfbafecaL)){throw 'Not a Mach-O native payload.'}
        }
    }finally{$stream.Dispose()}
}
$sources=@(Get-ChildItem -LiteralPath (Join-Path $repo "src\$project"),(Join-Path $repo 'src\seQuester.LinuxAgent'),(Join-Path $repo 'src\seQuester.UnixDesktop'),(Join-Path $repo 'src\seQuester.Client'),(Join-Path $repo 'src\seQuester.Contracts'),(Join-Path $repo "packaging\$platform") -Recurse -File | Where-Object FullName -notmatch '\\(bin|obj|__pycache__)\\' | Sort-Object FullName -Unique | ForEach-Object {[ordered]@{Path=$_.FullName.Substring($repo.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
foreach($name in @('CanaryTemplates.cs','CallbackDocuments.cs','ImportedCanaries.cs','Syslog.cs','PasswordHash.cs','PasswordSettings.cs','Assets/canary.docx','Assets/canary.xlsx','Assets/canary.pdf')){
    $sources+=[ordered]@{Path=$name;Sha256=(Get-FileHash -LiteralPath (Join-Path $repo $name) -Algorithm SHA256).Hash}
}
if($linux){
    foreach($file in Get-ChildItem -LiteralPath (Join-Path $repo 'src\seQuester.AuditRelay') -File){$sources+=[ordered]@{Path=$file.FullName.Substring($repo.Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}}
}
[IO.File]::WriteAllText((Join-Path $payload 'source-inventory.json'),(ConvertTo-Json -InputObject $sources -Depth 5)+"`n",$utf8)
$report="Release: $release`nProduct: endpoint client, NOT management server`nPASS: locked self-contained .NET agent and Avalonia desktop cross-publish; agent native file headers; bash -n syntax (Windows parser); no Python/Swift/Objective-C application payload.`nNOT RUN: native service/install/monitor/tray/permissions, queue/reboot/recovery, callbacks, email, Wazuh, process response or acceptance tests.`nNOT SIGNED. Development-only. macOS Endpoint Security C# adapter is NOT IMPLEMENTED; baseline fsevents only in current package. Managed alert windows replace native notification-center integration.`nNo service, live host, firewall or canary deployed by this build.`n"
if($linux){$report+="Linux audit: Native AOT relay source/binary/evidence hashes and ELF architecture verified; separate managed collector. See audit-relay/BUILD-PROVENANCE.json for runner-reported MDWE startup self-test. Full auditd integration, active heartbeat and actual canary attribution NOT RUN at publication. --audit-dispatch is diagnostic stdin only, never an auditd plugin.`n"}
[IO.File]::WriteAllText((Join-Path $payload 'VERIFICATION-REPORT.txt'),$report,$utf8)
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object {[ordered]@{Path=$_.FullName.Substring($payload.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
$manifest=[ordered]@{Release=$release;Product='Ransom Free Unix Endpoint';Runtime=$Runtime;Version=$version;Signed=$false;ApplicationLanguage='C#';ApplicationRuntime='.NET 10';Desktop='Avalonia 12.1.2';MacEndpointSecurity='Pending C# adapter';NativeRuntimeTests='NOT RUN';BuiltUtc=[DateTime]::UtcNow.ToString('o');Files=$files}
[IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),($manifest|ConvertTo-Json -Depth 6)+"`n",$utf8)
$sums=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object {(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.FullName.Substring($payload.Length+1).Replace('\','/')})
[IO.File]::WriteAllText((Join-Path $payload 'SHA256SUMS'),($sums -join "`n")+"`n",$utf8)
$archive=Join-Path $output ($release+'.tar.gz')
& tar --format=ustar -czf $archive -C $payload .
if($LASTEXITCODE -ne 0){throw 'Archive creation failed.'}
$hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive+'.sha256'),$hash+'  '+[IO.Path]::GetFileName($archive)+"`n",$utf8)
& (Join-Path $PSScriptRoot 'verify-unix-client-package.ps1') -PackageDirectory $output
