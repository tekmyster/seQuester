[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DesktopDll,
    [Parameter(Mandatory)][string]$AgentDll,
    [string]$WorkRoot='D:/Codex/RansomFree/W-SQ06/tests',
    [string]$Bash='C:/Program Files/Git/bin/bash.exe'
)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$root=Join-Path $WorkRoot ([Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$checks=0
function Put($Path,$Bytes){[void][IO.Directory]::CreateDirectory((Split-Path $Path));[IO.File]::WriteAllBytes($Path,$Bytes)}
function CopyFixture($From,$To){Put $To ([IO.File]::ReadAllBytes($From))}
function Snapshot {(@(Get-ChildItem $root -Recurse -File | Sort-Object FullName | ForEach-Object { $_.FullName+':'+(Get-FileHash $_.FullName).Hash }) -join "`n")}
function Check($Name,[scriptblock]$Action,[bool]$Pass=$true){
    $before=Snapshot; $failed=$false; $detail=''
    try{& $Action | Out-Null}catch{$failed=$true;$detail=$_.Exception.Message}
    if($failed -eq $Pass){throw "Unexpected result $Name : $detail"}
    if((Snapshot) -cne $before){throw "Verifier mutated fixture: $Name"}
    $script:checks++; Write-Output "PASS $Name; byte-identical fixture/prior state. $detail"
}
function Bad($Name,$Path,[byte[]]$Bytes,[scriptblock]$Action){
    $saved=[IO.File]::ReadAllBytes($Path)
    try{if($null -eq $Bytes){Remove-Item -LiteralPath $Path}else{Put $Path $Bytes};Check $Name $Action $false}finally{Put $Path $saved}
}
foreach($platform in @('linux','macos')){
    $payload=Join-Path $root $platform
    $desktop=if($platform -eq 'linux'){Join-Path $payload 'desktop'}else{Join-Path $payload 'Native/Ransom Free Endpoint.app/Contents/MacOS'}
    Put (Join-Path $desktop 'RansomFree.UnixDesktop') ([Text.Encoding]::UTF8.GetBytes('synthetic host; never executed'))
    CopyFixture $DesktopDll (Join-Path $desktop 'RansomFree.UnixDesktop.dll')
    CopyFixture (Join-Path $repo 'Assets/Branding/sequester-256.png') (Join-Path $desktop 'Branding/sequester-256.png')
    CopyFixture (Join-Path $repo "packaging/$($platform.Replace('macos','macos'))-client/install.sh") (Join-Path $payload 'install.sh')
    if($platform -eq 'linux'){
        CopyFixture (Join-Path $repo 'packaging/linux-client/ransomfree-client-tray.desktop') (Join-Path $payload 'ransomfree-client-tray.desktop')
    }else{
        $contents=Split-Path $desktop
        CopyFixture (Join-Path $repo 'Assets/Branding/sequester.icns') (Join-Path $contents 'Resources/sequester.icns')
        CopyFixture (Join-Path $repo 'packaging/macos-client/bundle/Info.plist') (Join-Path $contents 'Info.plist')
        CopyFixture (Join-Path $repo 'packaging/macos-client/bundle/Info.plist') (Join-Path $payload 'bundle/Info.plist')
        CopyFixture $AgentDll (Join-Path $payload 'app/RansomFree.MacAgent.dll')
        Put (Join-Path $payload 'RELEASE_ID') ([Text.Encoding]::UTF8.GetBytes('ransomfree-client-0.9.0-dev.fixture-osx-x64'))
    }
    Put (Join-Path $payload 'prior-install/config.json') ([Text.Encoding]::UTF8.GetBytes('{"preserve":true}'))
    $verify={& (Join-Path $PSScriptRoot 'verify-package-identity.ps1') -Payload $payload -Platform $platform}
    Check "$platform matching identity" $verify
    Bad "$platform missing PNG" (Join-Path $desktop 'Branding/sequester-256.png') $null $verify
    Bad "$platform tampered PNG" (Join-Path $desktop 'Branding/sequester-256.png') ([byte[]]@(1,2)) $verify
    Bad "$platform mismatched desktop" (Join-Path $desktop 'RansomFree.UnixDesktop.dll') ([IO.File]::ReadAllBytes($AgentDll)) $verify
    # Execute only the actual read-only preflight, never the installer.
    $scriptText=[IO.File]::ReadAllText((Join-Path $payload 'install.sh')).Replace("`r`n","`n")
    $match=[regex]::Match($scriptText,'(?s)# BEGIN desktop identity preflight.*?# END desktop identity preflight')
    if(!$match.Success -or $scriptText.IndexOf($match.Value) -gt $scriptText.IndexOf('chmod 0755')){throw 'Preflight must precede first mutation.'}
    $harness=Join-Path $root ($platform+'-preflight.sh')
    $mock=''
    if($platform -eq 'macos'){
        # Git Bash has no Apple tools. Mock only PlistBuddy/shasum; verify real
        # plist XML independently above. Native macOS tooling remains pending.
        $mock=@'
shasum() { shift 3; sha256sum -- "$@"; }
function /usr/libexec/PlistBuddy() {
  case "$2" in
    'Print :CFBundleIdentifier') echo com.ransomfree.endpoint-menu;;
    'Print :CFBundleName') echo "${MOCK_NAME:-seQuester Endpoint}";;
    'Print :CFBundleExecutable') echo RansomFree.UnixDesktop;;
    'Print :CFBundleIconFile') echo sequester.icns;;
    'Print :CFBundleShortVersionString'|'Print :CFBundleVersion') echo 0.9.2;;
    *) return 1;;
  esac
}
'@
    }
    [IO.File]::WriteAllText($harness,"set -euo pipefail`nbase=`$1`n"+$mock+"`n"+$match.Value+"`n",[Text.UTF8Encoding]::new($false))
    $preflight={& $Bash $harness $payload.Replace('\','/') 2>&1 | Out-Null; if($LASTEXITCODE -ne 0){throw "Preflight exit $LASTEXITCODE"}}
    Check "$platform actual preflight success" $preflight
    $icon=if($platform -eq 'linux'){Join-Path $desktop 'Branding/sequester-256.png'}else{Join-Path $contents 'Resources/sequester.icns'}
    Bad "$platform preflight missing icon" $icon $null $preflight
    Bad "$platform preflight tampered icon" $icon ([byte[]]@(1,2)) $preflight
    Bad "$platform preflight missing host" (Join-Path $desktop 'RansomFree.UnixDesktop') $null $preflight
    if($platform -eq 'macos'){
        $guard={& (Join-Path $PSScriptRoot 'verify-unix-release-guard.ps1') -Payload $payload -Bash $Bash}
        Check 'independent agent 0.9.0 and desktop 0.9.2' $guard
        Bad 'mismatched agent assembly' (Join-Path $payload 'app/RansomFree.MacAgent.dll') ([IO.File]::ReadAllBytes($DesktopDll)) $guard
        Bad 'mismatched desktop assembly via guard' (Join-Path $desktop 'RansomFree.UnixDesktop.dll') ([IO.File]::ReadAllBytes($AgentDll)) $guard
        Bad 'missing macOS bundle icon via guard' $icon $null $guard
        $plistPath=Join-Path $contents 'Info.plist'
        Bad 'wrong actual plist version' $plistPath ([Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($plistPath).Replace('0.9.2','0.9.0'))) $guard
        Bad 'preflight missing plist' $plistPath $null $preflight
        try{$env:MOCK_NAME='Wrong product';Check 'macOS preflight wrong plist value (mock Apple utility)' $preflight $false}finally{Remove-Item Env:MOCK_NAME}
    }
}
Write-Output "PASS $checks checks; fixture retained at $root. Synthetic hosts, mocked Apple utilities; no native installation/startup acceptance."
$global:LASTEXITCODE=0
