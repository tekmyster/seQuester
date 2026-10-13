[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Payload,
    [string]$Bash='C:\Program Files\Git\bin\bash.exe'
)
$ErrorActionPreference='Stop'
$release=[IO.File]::ReadAllText((Join-Path $Payload 'RELEASE_ID')).Trim()
$installer=[IO.File]::ReadAllText((Join-Path $Payload 'install.sh'))
$match=[regex]::Match($installer,'(?m)^\[\[ \$release =~ (\S+) \]\] \|\| exit 2\r?$')
if(!$match.Success){throw 'Installer release guard not found; review changed syntax.'}
$pattern=$match.Groups[1].Value
# Run only the literal [[ comparison, never source or execute the installer.
# The extracted pattern and untrusted release candidates are positional data, not shell code.
& $Bash -c '[[ $1 =~ $2 ]]' -- $release $pattern
if($LASTEXITCODE -ne 0){throw 'Installer rejects its own RELEASE_ID.'}
$versionMatch=[regex]::Match($release,'^ransomfree-client-(\d+\.\d+\.\d+)-dev\.')
if(!$versionMatch.Success){throw 'Invalid release version.'}
$releaseVersion=$versionMatch.Groups[1].Value
$invalid=@('',('../'+$release),($release+'/../escape'),$release.Replace($releaseVersion,'0.0.0'),$release.Replace($releaseVersion,'999.999.999'),$release.Replace('-linux-','-osx-').Replace('-osx-','-windows-'))
foreach($candidate in $invalid){& $Bash -c '[[ $1 =~ $2 ]]' -- $candidate $pattern; if($LASTEXITCODE -eq 0){throw 'Installer accepts an invalid release identifier.'}}
if($release.Contains('-osx-')){
    # Agent and desktop have independent release lines. Check the actual agent
    # assembly against RELEASE_ID, then the desktop bundle/resources separately.
    $agent=Join-Path $Payload 'app/RansomFree.MacAgent.dll'
    if([Diagnostics.FileVersionInfo]::GetVersionInfo($agent).FileVersion -ne ($releaseVersion+'.0')){throw 'macOS agent assembly and release versions disagree.'}
    & (Join-Path $PSScriptRoot 'verify-package-identity.ps1') -Payload $Payload -Platform macos
    if((Get-FileHash -LiteralPath (Join-Path $Payload 'bundle/Info.plist')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $Payload 'Native/Ransom Free Endpoint.app/Contents/Info.plist')).Hash){throw 'Staged and bundled desktop plist identities disagree.'}
}
$global:LASTEXITCODE=0
Write-Output "PASS: actual installer release guard accepts $release and rejects six invalid candidates. No installer executed."
