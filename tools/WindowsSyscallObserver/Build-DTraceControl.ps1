param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable control fixture already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$source=Join-Path $OutputDirectory 'source';New-Item -ItemType Directory -Path $source|Out-Null
$inputs=@()
foreach($name in @('DTraceControl.cpp','DTraceAdapter.h','Device.h','Wire.h','Build-DTraceControl.ps1')){
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $source $name)
 $inputs+=@{Name=$name;Sha256=(Get-FileHash (Join-Path $source $name)).Hash}
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\src\RansomFree.WindowsKernel\Protocol.h') -Destination (Join-Path $source 'Protocol.h')
$inputs+=@{Name='Protocol.h';Sha256=(Get-FileHash (Join-Path $source 'Protocol.h')).Hash}
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$savedInclude=$env:INCLUDE;$savedLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT ('/Fo'+$OutputDirectory+'\Control.obj') ('/Fe'+$OutputDirectory+'\DTraceControl.exe') (Join-Path $source 'DTraceControl.cpp')
 if($LASTEXITCODE-ne0){throw 'DTrace control compile/link failed'}
}finally{$env:INCLUDE=$savedInclude;$env:LIB=$savedLib}
[ordered]@{Compiled=$true;RuntimeQualified=$false;Source=$inputs;FixtureSha256=(Get-FileHash (Join-Path $OutputDirectory 'DTraceControl.exe')).Hash}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
