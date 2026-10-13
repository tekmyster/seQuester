param([Parameter(Mandatory)][string]$OutputDirectory,[switch]$UseExistingLabIdentity,[switch]$FullSensorPipeline)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$frozen=Join-Path $OutputDirectory 'source'
$files=@(Get-ChildItem (Join-Path $repo 'src\seQuester.WindowsKernel') -File|Where-Object{$_.Extension-in@('.c','.h','.ps1')}|ForEach-Object{[IO.Path]::GetRelativePath($repo,$_.FullName)})
$files+=@('tools\WindowsApiObserverPrototype\DeferredTokenSensorTest.cpp','tools\WindowsApiObserverPrototype\CallbackTokenLabProtocol.h','tools\WindowsApiObserverPrototype\Build-DeferredTokenSensor.ps1')
$sources=@()
foreach($name in $files){$inputFile=Join-Path $repo $name;$destination=Join-Path $frozen $name;New-Item -ItemType Directory -Path (Split-Path $destination) -Force|Out-Null;Copy-Item -LiteralPath $inputFile -Destination $destination;$hash=(Get-FileHash $inputFile).Hash;if((Get-FileHash $destination).Hash-cne$hash){throw 'Freeze mismatch'};$sources+=@{Name=$name;Sha256=$hash}}
$pipeline=@{}
if($FullSensorPipeline){$pipeline=@{ExecutableStagingDiagnostic=$true;RemoteFilesystemDiagnostic=$true;ApcPinDiagnostic=$true;AcquisitionOutcomeDiagnostic=$true;AcquisitionOutcomeAdvertised=$true}}
& (Join-Path $frozen 'src\seQuester.WindowsKernel\Build-Prototype.ps1') -OutputDirectory $OutputDirectory -DeferredTokenDiagnostic @pipeline
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$previousInclude=$env:INCLUDE;$previousLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT ('/Fo'+$OutputDirectory+'\Fixture.obj') ('/Fe'+$OutputDirectory+'\DeferredTokenSensorTest.exe') (Join-Path $frozen 'tools\WindowsApiObserverPrototype\DeferredTokenSensorTest.cpp') /link fltLib.lib advapi32.lib
 if($LASTEXITCODE-ne0){throw 'Fixture compile failed'}
}finally{$env:INCLUDE=$previousInclude;$env:LIB=$previousLib}
$driver=Join-Path $OutputDirectory 'SeQuesterActor.sys'
$unsigned=(Get-FileHash $driver).Hash
if($UseExistingLabIdentity){
 $cert=Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My|Where-Object{$_.Thumbprint-eq'6D8FA1C72096287BF5DDB6BBA868A4825EF2B983'-and$_.HasPrivateKey}|Select-Object -First 1
 if(!$cert){throw 'Existing lab identity unavailable'}
 $signature=Set-AuthenticodeSignature -LiteralPath $driver -Certificate $cert -HashAlgorithm SHA256
 if($signature.SignerCertificate.Thumbprint-ne$cert.Thumbprint){throw 'Lab identity mismatch'}
}
foreach($row in $sources){if((Get-FileHash (Join-Path $repo $row.Name)).Hash-cne$row.Sha256){throw 'Source changed during build'}}
$manifest=[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$sources;DriverSha256=(Get-FileHash $driver).Hash;UnsignedDriverSha256=$unsigned;FixtureSha256=(Get-FileHash (Join-Path $OutputDirectory 'DeferredTokenSensorTest.exe')).Hash;DeferredContextBytes=2048;DeferredCommand=45;FullSensorPipeline=[bool]$FullSensorPipeline;Compiled=$true;RuntimeQualified=$false;ProductionIntegrated=$false}
$manifest|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
$manifest|ConvertTo-Json -Depth 5
