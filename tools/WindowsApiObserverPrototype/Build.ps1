param([Parameter(Mandatory)][string]$DetoursSource,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$pinned='e4bfd6b03e50de46b47abfbd1e46b384f0c5f833'
$commit=git -C $DetoursSource rev-parse HEAD
if($LASTEXITCODE-ne0-or$commit-cne$pinned){throw 'Pinned Microsoft Detours v4.0.1 input required'}
git -C $DetoursSource diff --quiet HEAD -- src
if($LASTEXITCODE-ne0){throw 'Detours source differs from pinned input'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'New immutable build directory required'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='C:\Program Files (x86)\Windows Kits\10'
$env:INCLUDE="$vc/include;$sdk/Include/10.0.22621.0/um;$sdk/Include/10.0.22621.0/shared;$sdk/Include/10.0.22621.0/ucrt;$DetoursSource/src"
$env:LIB="$vc/lib/x64;$sdk/Lib/10.0.22621.0/um/x64;$sdk/Lib/10.0.22621.0/ucrt/x64;$DetoursSource/lib.X64"
$compiler="$vc/bin/Hostx64/x64/cl.exe"
Push-Location $OutputDirectory
try {
 & $compiler /nologo /W4 /WX /EHsc /MT /std:c++17 /D_WIN32_WINNT=0x0603 /LD "$PSScriptRoot/Observer.cpp" /Fe:Observer64.dll /link "/DEF:$PSScriptRoot/Observer.def" detours.lib advapi32.lib
 if($LASTEXITCODE-ne0){throw 'Observer compile/link failed'}
 & $compiler /nologo /W4 /WX /EHsc /MT /std:c++17 /D_WIN32_WINNT=0x0603 "$PSScriptRoot/Launch.cpp" /Fe:Launch64.exe /link detours.lib
 if($LASTEXITCODE-ne0){throw 'Launcher compile/link failed'}
 & "$vc/bin/Hostx64/x64/ml64.exe" /nologo /c /FoDirectCall.obj "$PSScriptRoot/DirectCall.asm"
 if($LASTEXITCODE-ne0){throw 'Owned negative fixture assembler failed'}
 & $compiler /nologo /W4 /WX /EHsc /MT /std:c++17 /D_WIN32_WINNT=0x0603 "$PSScriptRoot/Bypass.cpp" DirectCall.obj /Fe:Bypass64.exe
 if($LASTEXITCODE-ne0){throw 'Owned negative fixture compile/link failed'}
 $inputs=@('Observer.cpp','Launch.cpp','Observer.def','Build.ps1','Bypass.cpp','DirectCall.asm')|ForEach-Object {[ordered]@{Name=$_;Sha256=(Get-FileHash "$PSScriptRoot/$_").Hash}}
 Copy-Item -LiteralPath (Join-Path $DetoursSource 'LICENSE.md') -Destination 'DETOURS-LICENSE.md'
 [ordered]@{PrototypeOnly=$true;DetoursCommit=$pinned;DetoursLibrarySha256=(Get-FileHash (Join-Path $DetoursSource 'lib.X64/detours.lib')).Hash;Compiler=$compiler;Sdk='10.0.22621.0';Inputs=$inputs;Outputs=@(Get-ChildItem *.dll,*.exe|ForEach-Object {[ordered]@{Name=$_.Name;Sha256=(Get-FileHash $_.FullName).Hash}})}|ConvertTo-Json -Depth 5|Set-Content BUILD-MANIFEST.json
} finally {Pop-Location}
