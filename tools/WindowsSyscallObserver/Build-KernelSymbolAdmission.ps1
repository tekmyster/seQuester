param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Preserve immutable symbol tool'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'KernelSymbolAdmission.cpp') -Destination $OutputDirectory
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822';$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$oldInclude=$env:INCLUDE;$oldLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT ('/Fo'+$OutputDirectory+'\Symbols.obj') ('/Fe'+$OutputDirectory+'\KernelSymbolAdmission.exe') (Join-Path $OutputDirectory 'KernelSymbolAdmission.cpp') /link dbghelp.lib
 if($LASTEXITCODE-ne0){throw 'Symbol tool compilation failed'}
}finally{$env:INCLUDE=$oldInclude;$env:LIB=$oldLib}
foreach($name in @('dbghelp.dll','symsrv.dll')){Copy-Item -LiteralPath ('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\'+$name) -Destination $OutputDirectory}
[ordered]@{Compiled=$true;ReadOnly=$true;RuntimeQualified=$false;Inputs=@(Get-ChildItem -LiteralPath $OutputDirectory -File|ForEach-Object{@{Name=$_.Name;Sha256=(Get-FileHash $_.FullName).Hash}})}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'manifest.json')
