param([ValidatePattern('^r[0-9]+$')][string]$Revision='r4',[string]$ArtifactRoot='D:\Codex\RansomFree\windows-token-20260930')
$ErrorActionPreference='Stop'
$taskCompiler='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$taskSdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$taskOut=Join-Path $ArtifactRoot ('windows-creation-stop-model-'+$Revision)
New-Item -ItemType Directory -Path $taskOut -ErrorAction Stop | Out-Null
$taskSource=Join-Path $PSScriptRoot 'CreationFaultStateModel.c'
$taskHeader=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src\seQuester.WindowsKernel\CreationFaultDiagnostic.h'))
Copy-Item -LiteralPath $taskSource,$taskHeader -Destination $taskOut
& (Join-Path $taskCompiler 'bin\Hostx64\x64\cl.exe') /nologo /std:c11 /W4 /WX /Od /GS- /Zl /DSQ_CF_MODEL_DLL=1 /c ('/I'+(Join-Path $taskCompiler 'include')) ('/I'+(Join-Path $taskSdk 'Include\10.0.26100.0\ucrt')) ('/Fo'+(Join-Path $taskOut 'CreationFaultStateModel.obj')) $taskSource
if($LASTEXITCODE -ne 0) {throw 'CF state model compile failed'}
& (Join-Path $taskCompiler 'bin\Hostx64\x64\link.exe') /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 ('/OUT:'+(Join-Path $taskOut 'CreationFaultStateModel.dll')) (Join-Path $taskOut 'CreationFaultStateModel.obj')
if($LASTEXITCODE -ne 0) {throw 'CF state model link failed'}
$taskDll=Join-Path $taskOut 'CreationFaultStateModel.dll'
$taskType='CreationModel'+$Revision
Add-Type -TypeDefinition ('using System.Runtime.InteropServices; public static class '+$taskType+' { [DllImport(@"'+$taskDll+'", CallingConvention=CallingConvention.Cdecl)] public static extern int RunModel(out uint count); }')
$taskArguments=[object[]]@([uint32]0)
$taskResult=([type]$taskType).GetMethod('RunModel').Invoke($null,$taskArguments)
[pscustomobject]@{Passed=($taskResult -eq 0);Checks=$taskArguments[0];Cases=6;SourceSha256=(Get-FileHash -LiteralPath $taskSource).Hash;HeaderSha256=(Get-FileHash -LiteralPath $taskHeader).Hash;DllSha256=(Get-FileHash -LiteralPath $taskDll).Hash;Scope='Actual CF scalar functions; stubbed OS primitives, no native scheduling claim'} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $taskOut 'RESULTS.json')
if($taskResult -ne 0) {throw 'CF state model failed'}
