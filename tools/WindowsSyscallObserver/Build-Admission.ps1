param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable admission output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$inputFile=Join-Path $PSScriptRoot 'Admission.cpp'
$frozen=Join-Path $OutputDirectory 'Admission.cpp'
Copy-Item -LiteralPath $inputFile -Destination $frozen
$hash=(Get-FileHash $inputFile).Hash
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$savedInclude=$env:INCLUDE;$savedLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT ('/Fo'+$OutputDirectory+'\Admission.obj') ('/Fe'+$OutputDirectory+'\Admission.exe') $frozen
 if($LASTEXITCODE-ne0){throw 'Admission compile failed'}
}finally{$env:INCLUDE=$savedInclude;$env:LIB=$savedLib}
if((Get-FileHash $inputFile).Hash-cne$hash-or(Get-FileHash $frozen).Hash-cne$hash){throw 'Admission source changed'}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');SourceSha256=$hash;BinarySha256=(Get-FileHash (Join-Path $OutputDirectory 'Admission.exe')).Hash;Compiled=$true;ReadOnly=$true;RuntimeQualified=$false}|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'manifest.json')
