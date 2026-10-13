param([string]$BuildRoot='D:\Codex\RansomFree\kernel-attribution-20260924',[string]$OutputDirectory,[switch]$ImageDiagnostic,[switch]$PostCreateDiagnostic,[switch]$ExecutableStagingDiagnostic,[switch]$CreationFaultDiagnostic,[switch]$RemoteFilesystemDiagnostic,[switch]$ApcPinDiagnostic,[switch]$AcquisitionOutcomeDiagnostic,[switch]$AcquisitionFaultQualification,[switch]$AcquisitionOutcomeAdvertised,[switch]$DeferredTokenDiagnostic)
$ErrorActionPreference='Stop'
if($CreationFaultDiagnostic-and!$ExecutableStagingDiagnostic){throw 'Creation faults require the explicit executable-staging diagnostic build'}
if($RemoteFilesystemDiagnostic-and!$ExecutableStagingDiagnostic){throw 'Remote file qualification requires the existing actor snapshot pipeline'}
if($ApcPinDiagnostic-and!$ExecutableStagingDiagnostic){throw 'APC branch qualification requires the existing actor snapshot pipeline'}
if($AcquisitionOutcomeDiagnostic-and!$ExecutableStagingDiagnostic){throw 'Acquisition diagnostics require the existing actor snapshot pipeline'}
if($AcquisitionFaultQualification-and!$AcquisitionOutcomeDiagnostic){throw 'Private acquisition faults require the explicit acquisition outcome diagnostic build'}
if($AcquisitionOutcomeAdvertised-and(!$AcquisitionOutcomeDiagnostic-or$AcquisitionFaultQualification-or$CreationFaultDiagnostic)){throw 'Advertised acquisition outcomes require the outcome pipeline without qualification fault controls'}
$compiler='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$wdk=Join-Path $BuildRoot 'toolchain\wdk\c'
$sdk=Join-Path $BuildRoot 'toolchain\sdk\c'
$output=if($OutputDirectory){[IO.Path]::GetFullPath($OutputDirectory)}else{Join-Path $BuildRoot 'windows-prototype'}
New-Item -ItemType Directory -Path $output -Force|Out-Null
$args=@('/nologo','/c','/kernel','/W4','/WX','/GS','/Zl','/Zi','/Od','/D_AMD64_','/DAMD64','/D_WIN64','/D_WIN32_WINNT=0x0603','/DNTDDI_VERSION=0x06030000',('/I'+(Join-Path $wdk 'Include\10.0.26100.0\km')),('/I'+(Join-Path $sdk 'Include\10.0.26100.0\shared')),('/I'+(Join-Path $sdk 'Include\10.0.26100.0\ucrt')),('/I'+(Join-Path $compiler 'include')),('/Fo'+(Join-Path $output 'Driver.obj')),('/Fd'+(Join-Path $output 'Driver.pdb')),(Join-Path $PSScriptRoot 'Driver.c'))
if($ImageDiagnostic-or$PostCreateDiagnostic-or$ExecutableStagingDiagnostic){$args=@('/DSQ_IMAGE_DIAGNOSTIC=1')+$args}
if($PostCreateDiagnostic-or$ExecutableStagingDiagnostic){$args=@('/DSQ_POST_CREATE_DIAGNOSTIC=1')+$args}
if($ExecutableStagingDiagnostic){$args=@('/DSQ_EXECUTABLE_STAGING_DIAGNOSTIC=1')+$args}
if($CreationFaultDiagnostic){$args=@('/DSQ_CREATION_FAULT_DIAGNOSTIC=1')+$args}
if($RemoteFilesystemDiagnostic){$args=@('/DSQ_REMOTE_FILESYSTEM_DIAGNOSTIC=1')+$args}
if($ApcPinDiagnostic){$args=@('/DSQ_APC_PIN_DIAGNOSTIC=1')+$args}
if($AcquisitionOutcomeDiagnostic){$args=@('/DSQ_ACQUISITION_OUTCOME_DIAGNOSTIC=1')+$args}
if($AcquisitionFaultQualification){$args=@('/DSQ_ACQUISITION_FAULT_QUALIFICATION=1')+$args}
if($AcquisitionOutcomeAdvertised){$args=@('/DSQ_ACQUISITION_OUTCOME_ADVERTISED=1')+$args}
if($DeferredTokenDiagnostic){$args=@('/DSQ_DEFERRED_TOKEN_DIAGNOSTIC=1')+$args}
& (Join-Path $compiler 'bin\Hostx64\x64\cl.exe') @args
if($LASTEXITCODE-ne0){throw 'Driver compile failed'}
$args=@('/nologo','/DRIVER','/SUBSYSTEM:NATIVE','/ENTRY:GsDriverEntry','/NODEFAULTLIB','/MACHINE:X64','/INTEGRITYCHECK','/DEBUG','/RELEASE',('/OUT:'+(Join-Path $output 'SeQuesterActor.sys')),('/PDB:'+(Join-Path $output 'SeQuesterActor.pdb')),('/LIBPATH:'+(Join-Path $wdk 'Lib\10.0.26100.0\km\x64')),(Join-Path $output 'Driver.obj'),'ntoskrnl.lib','hal.lib','fltMgr.lib','BufferOverflowFastFailK.lib')
& (Join-Path $compiler 'bin\Hostx64\x64\link.exe') @args
if($LASTEXITCODE-ne0){throw 'Driver link failed'}
Get-FileHash -LiteralPath (Join-Path $output 'SeQuesterActor.sys')|Select-Object Path,Hash
