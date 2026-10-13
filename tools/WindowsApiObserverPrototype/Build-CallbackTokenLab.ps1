param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable output exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$wdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\wdk\c'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$cl=Join-Path $vc 'bin\Hostx64\x64\cl.exe';$link=Join-Path $vc 'bin\Hostx64\x64\link.exe'
$frozen=Join-Path $OutputDirectory 'source';New-Item -ItemType Directory -Path $frozen|Out-Null
$files=@('CallbackTokenLab.c','CallbackPagingSender.c','CallbackTokenLabTest.cpp','CallbackTokenLabProtocol.h','Build-CallbackTokenLab.ps1')
$rows=@();foreach($name in $files){$path=Join-Path $PSScriptRoot $name;$hash=(Get-FileHash $path).Hash;Copy-Item -LiteralPath $path -Destination $frozen;$rows+=@{Name=$name;Sha256=$hash};if((Get-FileHash (Join-Path $frozen $name)).Hash-cne$hash){throw 'Freeze mismatch'}}
$includes=@(('/I'+(Join-Path $wdk 'Include\10.0.26100.0\km')),('/I'+(Join-Path $sdk 'Include\10.0.26100.0\shared')),('/I'+(Join-Path $sdk 'Include\10.0.26100.0\ucrt')),('/I'+(Join-Path $vc 'include')))
& $cl /nologo /c /kernel /W4 /WX /GS /Zl /D_AMD64_ /DAMD64 /D_WIN64 /D_WIN32_WINNT=0x0603 /DNTDDI_VERSION=0x06030000 @includes ('/Fo'+(Join-Path $OutputDirectory 'Driver.obj')) (Join-Path $frozen 'CallbackTokenLab.c')
if($LASTEXITCODE-ne0){throw 'Kernel compile failed'}
& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /MACHINE:X64 /INTEGRITYCHECK /RELEASE ('/OUT:'+(Join-Path $OutputDirectory 'SqCallbackTokenLab.sys')) ('/LIBPATH:'+(Join-Path $wdk 'Lib\10.0.26100.0\km\x64')) (Join-Path $OutputDirectory 'Driver.obj') ntoskrnl.lib hal.lib fltmgr.lib wdmsec.lib BufferOverflowFastFailK.lib
if($LASTEXITCODE-ne0){throw 'Kernel link failed'}
& $cl /nologo /c /kernel /W4 /WX /GS /Zl /D_AMD64_ /DAMD64 /D_WIN64 /D_WIN32_WINNT=0x0603 /DNTDDI_VERSION=0x06030000 @includes ('/Fo'+(Join-Path $OutputDirectory 'Sender.obj')) (Join-Path $frozen 'CallbackPagingSender.c')
if($LASTEXITCODE-ne0){throw 'Sender compile failed'}
& $link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /MACHINE:X64 /INTEGRITYCHECK /RELEASE ('/OUT:'+(Join-Path $OutputDirectory 'SqCallbackPagingSender.sys')) ('/LIBPATH:'+(Join-Path $wdk 'Lib\10.0.26100.0\km\x64')) (Join-Path $OutputDirectory 'Sender.obj') ntoskrnl.lib hal.lib fltmgr.lib wdmsec.lib BufferOverflowFastFailK.lib
if($LASTEXITCODE-ne0){throw 'Sender link failed'}
$env:INCLUDE=(Join-Path $vc 'include')+';'+(Join-Path $sdk 'Include\10.0.26100.0\ucrt')+';'+(Join-Path $sdk 'Include\10.0.26100.0\um')+';'+(Join-Path $sdk 'Include\10.0.26100.0\shared')
$env:LIB=(Join-Path $vc 'lib\x64')+';C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
& $cl /nologo /W4 /WX /EHsc /MT /DUNICODE /D_UNICODE ('/Fo'+(Join-Path $OutputDirectory 'Test.obj')) ('/Fe'+(Join-Path $OutputDirectory 'CallbackTokenLabTest.exe')) (Join-Path $frozen 'CallbackTokenLabTest.cpp') /link advapi32.lib
if($LASTEXITCODE-ne0){throw 'Fixture compile failed'}
$driver=Join-Path $OutputDirectory 'SqCallbackTokenLab.sys';$unsigned=(Get-FileHash $driver).Hash
$cert=Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My|Where-Object{$_.Thumbprint-eq'6D8FA1C72096287BF5DDB6BBA868A4825EF2B983'-and$_.HasPrivateKey}|Select-Object -First 1
if(!$cert){throw 'Existing lab identity unavailable'}
$signature=Set-AuthenticodeSignature -LiteralPath $driver -Certificate $cert -HashAlgorithm SHA256
if($signature.SignerCertificate.Thumbprint-ne$cert.Thumbprint){throw 'Lab signing identity mismatch'}
$sender=Join-Path $OutputDirectory 'SqCallbackPagingSender.sys'
$senderSignature=Set-AuthenticodeSignature -LiteralPath $sender -Certificate $cert -HashAlgorithm SHA256
if($senderSignature.SignerCertificate.Thumbprint-ne$cert.Thumbprint){throw 'Sender identity mismatch'}
foreach($row in $rows){if((Get-FileHash (Join-Path $PSScriptRoot $row.Name)).Hash-cne$row.Sha256){throw 'Source changed during build'}}
$manifest=[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$rows;DriverSha256=(Get-FileHash $driver).Hash;UnsignedDriverSha256=$unsigned;SenderSha256=(Get-FileHash $sender).Hash;FixtureSha256=(Get-FileHash (Join-Path $OutputDirectory 'CallbackTokenLabTest.exe')).Hash;Certificate=$cert.Thumbprint;Compiled=$true;RuntimeQualified=$false;ProductionIntegrated=$false;Scope='Isolated actual read callback reference; later PASSIVE query; artificial APC control identified separately'}
$manifest|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
$manifest|ConvertTo-Json -Depth 5

