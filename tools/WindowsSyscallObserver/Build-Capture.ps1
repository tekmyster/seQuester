param([Parameter(Mandatory)][string]$OutputDirectory,[string]$BackendDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable capture build already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source=Join-Path $OutputDirectory 'source'
$names=@('tools\WindowsSyscallObserver\Capture.c','tools\WindowsSyscallObserver\Capture.h','tools\WindowsSyscallObserver\NtObserver.cpp','tools\WindowsSyscallObserver\Bridge.h','tools\WindowsSyscallObserver\Bridge.c','tools\WindowsSyscallObserver\Bridge.asm','tools\WindowsSyscallObserver\Device.c','tools\WindowsSyscallObserver\Device.h','tools\WindowsSyscallObserver\Build-Capture.ps1','src\seQuester.WindowsKernel\Driver.c','src\seQuester.WindowsKernel\Protocol.h')
$manifest=@()
$names+=@('tools\WindowsSyscallObserver\Wire.h')
$names+=@('tools\WindowsSyscallObserver\CodePin.h','tools\WindowsSyscallObserver\CodePin.c')
foreach($name in $names){
 $from=Join-Path $repo $name;$to=Join-Path $source $name
 New-Item -ItemType Directory -Path (Split-Path $to) -Force|Out-Null
 Copy-Item -LiteralPath $from -Destination $to
 $hash=(Get-FileHash $from).Hash
 if((Get-FileHash $to).Hash-cne$hash){throw 'Source freeze mismatch'}
 $manifest+=@{Name=$name;Sha256=$hash}
}
$driver=[IO.File]::ReadAllText((Join-Path $source 'src\seQuester.WindowsKernel\Driver.c'))
$start=$driver.IndexOf('static VOID CaptureToken(PACCESS_TOKEN token,SQ_TOKEN* output)')
$end=$driver.IndexOf('static VOID CaptureActor(', $start)
if($start-lt0-or$end-le$start){throw 'Existing token helper boundary changed'}
$generated=Join-Path $source 'tools\WindowsSyscallObserver\SharedCaptureToken.inc'
[IO.File]::WriteAllText($generated,$driver.Substring($start,$end-$start),[Text.UTF8Encoding]::new($false))
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$wdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\wdk\c'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$args=@('/nologo','/c','/kernel','/W4','/WX','/GS','/Zl','/Zi','/Od','/D_AMD64_','/DAMD64','/D_WIN64','/D_WIN32_WINNT=0x0603','/DNTDDI_VERSION=0x06030000',('/I'+(Join-Path $source 'src\seQuester.WindowsKernel')),('/I'+$wdk+'\Include\10.0.26100.0\km'),('/I'+$sdk+'\Include\10.0.26100.0\shared'),('/I'+$sdk+'\Include\10.0.26100.0\ucrt'),('/I'+$vc+'\include'),('/Fo'+$OutputDirectory+'\Capture.obj'),('/Fd'+$OutputDirectory+'\Capture.pdb'),(Join-Path $source 'tools\WindowsSyscallObserver\Capture.c'))
& ($vc+'\bin\Hostx64\x64\cl.exe') @args
if($LASTEXITCODE-ne0){throw 'Capture module compile failed'}
$bridgeArgs=@($args|Where-Object{$_-notlike'/Fo*'-and$_-notlike'/Fd*'-and$_-notlike'*.c'})
$bridgeArgs+=@(('/Fo'+$OutputDirectory+'\Bridge.obj'),('/Fd'+$OutputDirectory+'\Bridge.pdb'),(Join-Path $source 'tools\WindowsSyscallObserver\Bridge.c'))
& ($vc+'\bin\Hostx64\x64\cl.exe') @bridgeArgs
if($LASTEXITCODE-ne0){throw 'Root bridge accounting compile failed'}
$deviceArgs=@($bridgeArgs|Where-Object{$_-notlike'/Fo*'-and$_-notlike'/Fd*'-and$_-notlike'*.c'})
$deviceArgs+=@(('/Fo'+$OutputDirectory+'\Device.obj'),('/Fd'+$OutputDirectory+'\Device.pdb'),(Join-Path $source 'tools\WindowsSyscallObserver\Device.c'))
& ($vc+'\bin\Hostx64\x64\cl.exe') @deviceArgs
if($LASTEXITCODE-ne0){throw 'Protected native device compile failed'}
$pinArgs=@($bridgeArgs|Where-Object{$_-notlike'/Fo*'-and$_-notlike'/Fd*'-and$_-notlike'*.c'})
$pinArgs+=@(('/Fo'+$OutputDirectory+'\CodePin.obj'),('/Fd'+$OutputDirectory+'\CodePin.pdb'),(Join-Path $source 'tools\WindowsSyscallObserver\CodePin.c'))
& ($vc+'\bin\Hostx64\x64\cl.exe') @pinArgs
if($LASTEXITCODE-ne0){throw 'Code-page pinning compile failed'}
& ($vc+'\bin\Hostx64\x64\ml64.exe') /nologo /c /W3 /WX ('/Fo'+$OutputDirectory+'\BridgeAsm.obj') (Join-Path $source 'tools\WindowsSyscallObserver\Bridge.asm')
if($LASTEXITCODE-ne0){throw 'Native bridge assembly failed'}
$backendManifest=@()
if($BackendDirectory){
 $pins=@{'.'='b6999c888f11bea37c0a40ab34ea8310e47e4c31';'HyperPlatform'='d52a42d7365cb07a1e5703f038f7304e65fae780';'capstone'='512cc96485c6e1fd9cb425d7047beb905544c00f'}
 foreach($dir in $pins.Keys){
  $root=Join-Path $BackendDirectory $dir
  $head=& git -C $root rev-parse HEAD
  if($LASTEXITCODE-ne0-or$head-cne$pins[$dir]){throw 'Research dependency pin mismatch'}
  $dirty=& git -C $root status --porcelain --untracked-files=no
  if($LASTEXITCODE-ne0-or$dirty){throw 'Research dependency changed'}
 }
 $external=Join-Path $OutputDirectory 'research'
 $backendNames=@('DdiMon\ddi_mon.h','DdiMon\shadow_hook.h','LICENSE')
 $backendNames+=@(Get-ChildItem (Join-Path $BackendDirectory 'HyperPlatform\HyperPlatform') -File -Filter '*.h'|ForEach-Object{'HyperPlatform\HyperPlatform\'+$_.Name})
 foreach($name in $backendNames){
  $from=Join-Path $BackendDirectory $name;$to=Join-Path $external $name
  New-Item -ItemType Directory -Path (Split-Path $to) -Force|Out-Null
  Copy-Item -LiteralPath $from -Destination $to
  $backendManifest+=@{Name=$name;Sha256=(Get-FileHash $to).Hash}
 }
 $glue=Join-Path $external 'DdiMon\ddi_mon.cpp'
 Copy-Item -LiteralPath (Join-Path $source 'tools\WindowsSyscallObserver\NtObserver.cpp') -Destination $glue
 $glueArgs=@($args|Where-Object{$_-notlike'/Fo*'-and$_-notlike'/Fd*'-and$_-notlike'*.c'})
 $glueArgs+=@('/std:c++17','/EHs-c-','/D_HAS_EXCEPTIONS=0',('/I'+(Join-Path $source 'tools\WindowsSyscallObserver')),('/Fo'+$OutputDirectory+'\NtObserver.obj'),('/Fd'+$OutputDirectory+'\NtObserver.pdb'),$glue)
 & ($vc+'\bin\Hostx64\x64\cl.exe') @glueArgs
 if($LASTEXITCODE-ne0){throw 'Native Nt entry/return glue compile failed'}
}
foreach($row in $manifest){if((Get-FileHash (Join-Path $repo $row.Name)).Hash-cne$row.Sha256){throw 'Source changed during capture build'}}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$manifest;BackendHeaders=$backendManifest;GeneratedTokenHelperSha256=(Get-FileHash $generated).Hash;ObjectSha256=(Get-FileHash (Join-Path $OutputDirectory 'Capture.obj')).Hash;NtEntryReturnGlueCompiled=[bool]$BackendDirectory;Compiled=$true;DriverLinked=$false;RuntimeLoadAdmitted=$false;RuntimeQualified=$false;ProductionIntegrated=$false;Scope='owned-thread native capture module; backend lifecycle and device integration outstanding'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
