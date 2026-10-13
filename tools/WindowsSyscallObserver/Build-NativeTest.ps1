param([Parameter(Mandatory)][string]$OutputDirectory,[switch]$DTraceContext,[switch]$Intake,[switch]$Producer)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable native test output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$names=@('tools\WindowsSyscallObserver\NativeTest.cpp','tools\WindowsSyscallObserver\Wire.h','tools\WindowsSyscallObserver\Device.h','tools\WindowsSyscallObserver\Build-NativeTest.ps1','src\seQuester.WindowsKernel\Protocol.h')
if($DTraceContext){$names+=@('tools\WindowsSyscallObserver\DTraceAdapter.h')}
$source=Join-Path $OutputDirectory 'source';$inputs=@()
foreach($name in $names){
 $from=Join-Path $repo $name;$to=Join-Path $source $name
 New-Item -ItemType Directory -Path (Split-Path $to) -Force|Out-Null
 Copy-Item -LiteralPath $from -Destination $to;$inputs+=@{Name=$name;Sha256=(Get-FileHash $to).Hash}
}
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$savedInclude=$env:INCLUDE;$savedLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 $flags=@();if($DTraceContext){$flags+=@('/DSQ_DTRACE_CONTEXT_TEST')};if($Intake){if($DTraceContext){throw 'Intake requires full token source'};$flags+=@('/DSQ_INTAKE_TEST')};if($Producer){if($Intake-or$DTraceContext){throw 'Producer mode requires its own managed receiver'};$flags+=@('/DSQ_MANAGED_PRODUCER')}
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT @flags ('/I'+$source+'\src\seQuester.WindowsKernel') ('/Fo'+$OutputDirectory+'\Test.obj') ('/Fe'+$OutputDirectory+'\SyscallNativeTest.exe') ($source+'\tools\WindowsSyscallObserver\NativeTest.cpp') /link advapi32.lib
 if($LASTEXITCODE-ne0){throw 'Native observer fixture compile/link failed'}
}finally{$env:INCLUDE=$savedInclude;$env:LIB=$savedLib}
foreach($row in $inputs){if((Get-FileHash (Join-Path $repo $row.Name)).Hash-cne$row.Sha256){throw 'Native fixture source changed during build'}}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$inputs;FixtureSha256=(Get-FileHash ($OutputDirectory+'\SyscallNativeTest.exe')).Hash;Compiled=$true;RuntimeQualified=$false;CentralIntegrated=$false;Cases=9;DTraceContextOnly=[bool]$DTraceContext;ManagedProducer=[bool]$Producer;TokenCaptureTested=$false}|ConvertTo-Json -Depth 5|Set-Content ($OutputDirectory+'\manifest.json')
