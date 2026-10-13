[CmdletBinding()]
param(
    [string]$RepoRoot=(Split-Path $PSScriptRoot -Parent),
    [string]$Payload,
    [ValidateSet('linux','macos')][string]$Platform='linux'
)
# Read-only prerequisite check. Call before installation/cutover; never repairs a payload.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function RequireFile([string]$Path) {
    if(!(Test-Path -LiteralPath $Path -PathType Leaf)){throw "Package identity: required file missing: $Path"}
    $item=Get-Item -LiteralPath $Path
    if($item.Length -eq 0){throw "Package identity: empty file: $Path"}
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "Package identity: linked file rejected: $Path"}
    for($p=$item.Directory; $null -ne $p; $p=$p.Parent){
        if(($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "Package identity: linked path rejected: $Path"}
    }
}
function RequireValue($Actual,[string]$Expected,[string]$Label) {
    if($Actual -cne $Expected){throw "Package identity: $Label expected '$Expected', found '$Actual'."}
}
function CheckIcon([string]$Path,[string]$Hash) {
    RequireFile $Path
    RequireValue (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash $Hash 'canonical icon SHA256'
}
function CheckPlist([string]$Path,[string]$Version) {
    RequireFile $Path
    [xml]$xml=[IO.File]::ReadAllText($Path)
    foreach($pair in @(@('CFBundleIdentifier','com.ransomfree.endpoint-menu'),@('CFBundleName','seQuester Endpoint'),@('CFBundleExecutable','RansomFree.UnixDesktop'),@('CFBundleIconFile','sequester.icns'),@('CFBundleShortVersionString',$Version),@('CFBundleVersion',$Version))){
        $nodes=$xml.SelectNodes("/plist/dict/key[text()='$($pair[0])']")
        if($nodes.Count -ne 1 -or $nodes[0].NextSibling.Name -cne 'string'){throw "Package identity: invalid plist key $($pair[0])."}
        RequireValue $nodes[0].NextSibling.InnerText $pair[1] $pair[0]
    }
}
function CheckLauncher([string]$Path) {
    RequireFile $Path
    $lines=[IO.File]::ReadAllLines($Path)
    foreach($line in @('Name=seQuester Endpoint','Exec=/opt/ransomfree-client/current/desktop/RansomFree.UnixDesktop','Icon=/opt/ransomfree-client/current/desktop/Branding/sequester-256.png')){
        $key=$line.Split('=')[0]+'='
        $values=@($lines | Where-Object { $_.StartsWith($key,[StringComparison]::Ordinal) })
        if($values.Count -ne 1){throw "Package identity: missing/duplicate launcher $key"}
        RequireValue $values[0] $line 'Linux launcher'
    }
}
$png='EF71B9131B454D20EFEF21DAC8FC3CC1B81E7834240EC41DC5AB65AF2076D139'
$icns='C79D10FC312CBE22989CECABC126F8560E7C6C6EBB0DC4F8935B6958B80EB2B6'
$project=Join-Path $RepoRoot 'src/RansomFree.UnixDesktop/RansomFree.UnixDesktop.csproj'
RequireFile $project
[xml]$xml=[IO.File]::ReadAllText($project)
$version=[string]$xml.Project.PropertyGroup.Version
if($version -notmatch '^\d+\.\d+\.\d+$'){throw 'Package identity: invalid desktop candidate version.'}
CheckLauncher (Join-Path $RepoRoot 'packaging/linux-client/ransomfree-client-tray.desktop')
CheckPlist (Join-Path $RepoRoot 'packaging/macos-client/bundle/Info.plist') $version
CheckIcon (Join-Path $RepoRoot 'Assets/Branding/sequester-256.png') $png
CheckIcon (Join-Path $RepoRoot 'Assets/Branding/sequester.icns') $icns
if($Payload){
    if($Platform -eq 'linux'){
        $desktop=Join-Path $Payload 'desktop'
        CheckLauncher (Join-Path $Payload 'ransomfree-client-tray.desktop')
    }else{
        $contents=Join-Path $Payload 'Native/Ransom Free Endpoint.app/Contents'
        $desktop=Join-Path $contents 'MacOS'
        CheckPlist (Join-Path $contents 'Info.plist') $version
        CheckIcon (Join-Path $contents 'Resources/sequester.icns') $icns
    }
    RequireFile (Join-Path $desktop 'RansomFree.UnixDesktop')
    CheckIcon (Join-Path $desktop 'Branding/sequester-256.png') $png
    $dll=Join-Path $desktop 'RansomFree.UnixDesktop.dll'
    RequireFile $dll
    RequireValue ([Reflection.AssemblyName]::GetAssemblyName($dll).Version.ToString()) ($version+'.0') 'desktop assembly version'
    RequireValue ([Diagnostics.FileVersionInfo]::GetVersionInfo($dll).FileVersion) ($version+'.0') 'desktop file version'
}
Write-Output "PASS: seQuester Endpoint desktop identity $version and declared canonical resource paths; read-only check. Native startup remains pending."
