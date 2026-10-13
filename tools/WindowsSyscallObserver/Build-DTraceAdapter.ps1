param([Parameter(Mandatory)][string]$OutputDirectory,[Parameter(Mandatory)][string]$DTraceSourceDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable adapter output already exists'}
if((& git -C $DTraceSourceDirectory rev-parse HEAD)-cne'd394cf0f5bbcde8cae9801f73ec5eaef031dddad'){throw 'Public DTrace source pin changed'}
if(& git -C $DTraceSourceDirectory status --porcelain --untracked-files=no){throw 'DTrace source changed'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$source=Join-Path $OutputDirectory 'source';New-Item -ItemType Directory -Path $source|Out-Null
$inputs=@()
foreach($name in @('Capture.c','Capture.h','Wire.h','Device.c','Device.h','Bridge.h','DTraceAdapter.c','DTraceAdapter.h','Build-DTraceAdapter.ps1')){
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $source $name)
 $inputs+=@{Name=$name;Sha256=(Get-FileHash (Join-Path $source $name)).Hash}
}
$repository=Split-Path (Split-Path $PSScriptRoot)
Copy-Item -LiteralPath (Join-Path $repository 'src\RansomFree.WindowsKernel\Protocol.h') -Destination (Join-Path $source 'Protocol.h')
$tokenPath=Join-Path $repository 'src\RansomFree.WindowsKernel\Driver.c'
Copy-Item -LiteralPath $tokenPath -Destination (Join-Path $source 'WindowsKernelDriver.c')
$driver=[IO.File]::ReadAllText((Join-Path $source 'WindowsKernelDriver.c'))
$start=$driver.IndexOf('static VOID CaptureToken(PACCESS_TOKEN token,SQ_TOKEN* output)');$end=$driver.IndexOf('static VOID CaptureActor(',$start)
if($start-lt0-or$end-le$start){throw 'Existing token helper boundary changed'}
[IO.File]::WriteAllText((Join-Path $source 'SharedCaptureToken.inc'),$driver.Substring($start,$end-$start),[Text.UTF8Encoding]::new($false))
$header=Join-Path $DTraceSourceDirectory 'lib\libdtrace\compat\win32\inc\ntdtrace.h'
Copy-Item -LiteralPath $header -Destination (Join-Path $source 'ntdtrace.h')
foreach($name in @('Protocol.h','WindowsKernelDriver.c','SharedCaptureToken.inc','ntdtrace.h')){$inputs+=@{Name=$name;Sha256=(Get-FileHash (Join-Path $source $name)).Hash}}
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$wdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\wdk\c';$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$common=@('/nologo','/c','/kernel','/W4','/WX','/GS','/Zl','/Zi','/Od','/D_AMD64_','/DAMD64','/D_WIN64','/D_WIN32_WINNT=0x0A00','/DNTDDI_VERSION=0x0A000000','/D_KERNEL','/DSQ_DTRACE_BACKEND',('/I'+$source),('/I'+$wdk+'\Include\10.0.26100.0\km'),('/I'+$sdk+'\Include\10.0.26100.0\shared'),('/I'+$sdk+'\Include\10.0.26100.0\ucrt'),('/I'+$vc+'\include'))
$objects=@()
foreach($name in @('Capture','Device','DTraceAdapter')){
 $object=Join-Path $OutputDirectory ($name+'.obj');$objects+=$object
 & ($vc+'\bin\Hostx64\x64\cl.exe') @common ('/Fo'+$object) ('/Fd'+$OutputDirectory+'\'+$name+'.pdb') (Join-Path $source ($name+'.c')) *> (Join-Path $OutputDirectory ($name+'-compile.log'))
 if($LASTEXITCODE-ne0){Get-Content (Join-Path $OutputDirectory ($name+'-compile.log'));throw ('Adapter compile failed: '+$name)}
}
& ($vc+'\bin\Hostx64\x64\link.exe') /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /MACHINE:X64 /INTEGRITYCHECK /DEBUG /RELEASE ('/OUT:'+ $OutputDirectory+'\SqDtraceContextLab.sys') ('/PDB:'+ $OutputDirectory+'\SqDtraceContextLab.pdb') ('/LIBPATH:'+ $wdk+'\Lib\10.0.26100.0\km\x64') @objects ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowFastFailK.lib *> (Join-Path $OutputDirectory 'link.log')
if($LASTEXITCODE-ne0){Get-Content (Join-Path $OutputDirectory 'link.log');throw 'Context adapter link failed'}
foreach($row in $inputs){if((Get-FileHash (Join-Path $source $row.Name)).Hash-cne$row.Sha256){throw 'Frozen adapter source changed'}}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Compiled=$true;RuntimeQualified=$false;ProductionIntegrated=$false;DynamicUnloadAdmitted=$false;Inputs=$inputs;TokenHelperSourceSha256=(Get-FileHash $tokenPath).Hash;PublicDTraceCommit='d394cf0f5bbcde8cae9801f73ec5eaef031dddad';MicrosoftDriverSha256='37e11e97b48fb2c6c4d53b71262cceced5e86dba56df994c78ab676477a93ea2';DriverSha256=(Get-FileHash (Join-Path $OutputDirectory 'SqDtraceContextLab.sys')).Hash;Scope='Private owned-thread tracing callback context only; no normal syscall evidence or token-query claim'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
