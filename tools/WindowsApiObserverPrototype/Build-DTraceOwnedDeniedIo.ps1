param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path $OutputDirectory){throw 'New immutable output directory required'}
New-Item -ItemType Directory $OutputDirectory|Out-Null
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='C:\Program Files (x86)\Windows Kits\10'
$originalInclude=$env:INCLUDE;$originalLib=$env:LIB
try{
 $env:INCLUDE="$vc/include;$sdk/Include/10.0.22621.0/um;$sdk/Include/10.0.22621.0/shared;$sdk/Include/10.0.22621.0/ucrt"
 $env:LIB="$vc/lib/x64;$sdk/Lib/10.0.22621.0/um/x64;$sdk/Lib/10.0.22621.0/ucrt/x64"
 $sources=@('DTraceOwnedDeniedIo.cpp','DirectCall.asm','Build-DTraceOwnedDeniedIo.ps1')
 $inputs=@($sources|ForEach-Object{[ordered]@{Name=$_;Sha256=(Get-FileHash (Join-Path $PSScriptRoot $_)).Hash}})
 $frozen=Join-Path $OutputDirectory 'source';New-Item -ItemType Directory $frozen|Out-Null
 foreach($name in $sources){Copy-Item (Join-Path $PSScriptRoot $name) $frozen}
 & "$vc/bin/Hostx64/x64/ml64.exe" /nologo /c ('/Fo'+(Join-Path $OutputDirectory 'DirectCall.obj')) (Join-Path $frozen 'DirectCall.asm')
 if($LASTEXITCODE-ne0){throw 'Assembler failed'}
 & "$vc/bin/Hostx64/x64/cl.exe" /nologo /W4 /WX /EHsc /MT /std:c++17 /D_WIN32_WINNT=0x0603 ('/Fo'+(Join-Path $OutputDirectory 'Actor.obj')) ('/Fe'+(Join-Path $OutputDirectory 'DTraceOwnedDeniedIo.exe')) (Join-Path $frozen 'DTraceOwnedDeniedIo.cpp') (Join-Path $OutputDirectory 'DirectCall.obj')
 if($LASTEXITCODE-ne0){throw 'Fixture compile/link failed'}
 foreach($row in $inputs){if((Get-FileHash (Join-Path $frozen $row.Name)).Hash-cne$row.Sha256-or(Get-FileHash (Join-Path $PSScriptRoot $row.Name)).Hash-cne$row.Sha256){throw 'Build input changed'}}
 [ordered]@{Compiled=$true;RuntimeQualified=$false;ProductionIntegrated=$false;Utc=[datetime]::UtcNow.ToString('o');Inputs=$inputs;ActorSha256=(Get-FileHash (Join-Path $OutputDirectory 'DTraceOwnedDeniedIo.exe')).Hash;Compiler="$vc/bin/Hostx64/x64/cl.exe";Sdk='10.0.22621.0';Scope='Owned successfully opened handles: denied read, write, append, truncate, rename, delete and direct syscall read'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
}finally{$env:INCLUDE=$originalInclude;$env:LIB=$originalLib}
