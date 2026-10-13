param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable ABI output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$files=@('Bridge.asm','BridgeAbiTest.asm','BridgeAbiTest.cpp','Build-TestBridgeAbi.ps1');$inputs=@()
foreach($name in $files){
 $from=Join-Path $PSScriptRoot $name;$to=Join-Path $OutputDirectory $name
 Copy-Item -LiteralPath $from -Destination $to
 $inputs+=@{Name=$name;Sha256=(Get-FileHash $to).Hash}
}
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
& ($vc+'\bin\Hostx64\x64\ml64.exe') /nologo /c /W3 /WX /DSQ_ABI_TEST ('/Fo'+$OutputDirectory+'\Bridge.obj') ($OutputDirectory+'\Bridge.asm')
if($LASTEXITCODE-ne0){throw 'ABI bridge assembly failed'}
& ($vc+'\bin\Hostx64\x64\ml64.exe') /nologo /c /W3 /WX ('/Fo'+$OutputDirectory+'\Fixture.obj') ($OutputDirectory+'\BridgeAbiTest.asm')
if($LASTEXITCODE-ne0){throw 'ABI fixture assembly failed'}
$savedInclude=$env:INCLUDE;$savedLib=$env:LIB
try{
 $env:INCLUDE=$vc+'\include;'+$sdk+'\Include\10.0.26100.0\ucrt;'+$sdk+'\Include\10.0.26100.0\um;'+$sdk+'\Include\10.0.26100.0\shared'
 $env:LIB=$vc+'\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64'
 & ($vc+'\bin\Hostx64\x64\cl.exe') /nologo /W4 /WX /EHsc /MT ('/Fo'+$OutputDirectory+'\Test.obj') ('/Fe'+$OutputDirectory+'\BridgeAbiTest.exe') ($OutputDirectory+'\BridgeAbiTest.cpp') ($OutputDirectory+'\Bridge.obj') ($OutputDirectory+'\Fixture.obj')
 if($LASTEXITCODE-ne0){throw 'ABI test link failed'}
 & ($OutputDirectory+'\BridgeAbiTest.exe')|Set-Content ($OutputDirectory+'\acceptance.json')
 if($LASTEXITCODE-ne0){throw 'ABI forwarding/status/nonvolatile test failed'}
}finally{$env:INCLUDE=$savedInclude;$env:LIB=$savedLib}
foreach($row in $inputs){if((Get-FileHash (Join-Path $PSScriptRoot $row.Name)).Hash-cne$row.Sha256){throw 'ABI source changed during qualification'}}
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');Source=$inputs;BinarySha256=(Get-FileHash ($OutputDirectory+'\BridgeAbiTest.exe')).Hash;Compiled=$true;UserModeAbiPassed=$true;VmExitQualified=$false;FilesystemCaptureQualified=$false}|ConvertTo-Json -Depth 5|Set-Content ($OutputDirectory+'\manifest.json')
Get-Content ($OutputDirectory+'\acceptance.json')
