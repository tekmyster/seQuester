param([ValidatePattern('^r[0-9]+$')][string]$Revision='r1',[string]$ArtifactRoot='D:\Codex\RansomFree\windows-token-20260930')
$ErrorActionPreference='Stop'
$taskCompiler='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$taskOut=Join-Path $ArtifactRoot ('windows-callback-removal-model-'+$Revision)
New-Item -ItemType Directory -Path $taskOut -ErrorAction Stop|Out-Null
$taskSource=Join-Path $PSScriptRoot 'CallbackRemovalStateModel.c'
$taskHeader=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\src\RansomFree.WindowsKernel\ImageDiagnostic.h'))
$taskText=[IO.File]::ReadAllText($taskHeader);$taskStart=$taskText.IndexOf('static NTSTATUS DiagUnregisterCore(VOID)');$taskEnd=$taskText.IndexOf('static NTSTATUS DiagUnregister(VOID)',$taskStart)
if($taskStart-lt0-or$taskEnd-le$taskStart){throw 'Exact removal function boundaries unavailable'}
$taskInclude=Join-Path $taskOut 'CallbackRemovalCore.inc'
[IO.File]::WriteAllText($taskInclude,$taskText.Substring($taskStart,$taskEnd-$taskStart))
Copy-Item -LiteralPath $taskSource,$taskHeader -Destination $taskOut
& (Join-Path $taskCompiler 'bin\Hostx64\x64\cl.exe') /nologo /std:c11 /W4 /WX /Od /GS- /Zl /c ('/I'+$taskOut) ('/Fo'+(Join-Path $taskOut 'CallbackRemovalStateModel.obj')) $taskSource
if($LASTEXITCODE-ne0){throw 'Removal model compile failed'}
$taskDll=Join-Path $taskOut 'CallbackRemovalStateModel.dll'
& (Join-Path $taskCompiler 'bin\Hostx64\x64\link.exe') /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 ('/OUT:'+$taskDll) (Join-Path $taskOut 'CallbackRemovalStateModel.obj')
if($LASTEXITCODE-ne0){throw 'Removal model link failed'}
$taskType='RemovalModel'+$Revision
Add-Type -TypeDefinition ('using System.Runtime.InteropServices; public static class '+$taskType+' { [DllImport(@"'+$taskDll+'", CallingConvention=CallingConvention.Cdecl)] public static extern int RunModel(out uint count); }')
$taskArguments=[object[]]@([uint32]0);$taskResult=([type]$taskType).GetMethod('RunModel').Invoke($null,$taskArguments)
[pscustomobject]@{Passed=($taskResult-eq0);Checks=$taskArguments[0];SourceSha256=(Get-FileHash $taskSource).Hash;HeaderSha256=(Get-FileHash $taskHeader).Hash;FunctionSha256=(Get-FileHash $taskInclude).Hash;DllSha256=(Get-FileHash $taskDll).Hash;Scope='Exact actual removal function, stubbed OS statuses; no native callback synchronization claim'}|ConvertTo-Json|Tee-Object -FilePath (Join-Path $taskOut 'RESULTS.json')
if($taskResult-ne0){throw 'Removal model failed'}
