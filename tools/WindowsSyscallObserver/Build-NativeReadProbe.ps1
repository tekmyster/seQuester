param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable native test output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$names=@('tools\WindowsSyscallObserver\NativeReadProbe.cpp','tools\WindowsSyscallObserver\Wire.h','tools\WindowsSyscallObserver\Device.h','tools\WindowsSyscallObserver\Build-NativeReadProbe.ps1','src\seQuester.WindowsKernel\Protocol.h')
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
 $flags=@()
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT @flags ('/I'+$source+'\src\seQuester.WindowsKernel') ('/Fo'+$OutputDirectory+'\Test.obj') ('/Fe'+$OutputDirectory+'\SyscallNativeReadProbe.exe') ($source+'\tools\WindowsSyscallObserver\NativeReadProbe.cpp') /link advapi32.lib
 if($LASTEXITCODE-ne0){throw 'Native observer fixture compile/link failed'}
}finally{$env:INCLUDE=$savedInclude;$env:LIB=$savedLib}
foreach($row in $inputs){if((Get-FileHash (Join-Path $repo $row.Name)).Hash-cne$row.Sha256){throw 'Native fixture source changed during build'}}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$inputs;FixtureSha256=(Get-FileHash ($OutputDirectory+'\SyscallNativeReadProbe.exe')).Hash;Compiled=$true;RuntimeQualified=$false;CentralIntegrated=$false;Cases=0;DTraceContextOnly=[bool]$DTraceContext;ManagedProducer=$false;ReadOnlyProbe=$true;TokenCaptureTested=$false}|ConvertTo-Json -Depth 5|Set-Content ($OutputDirectory+'\manifest.json')
