[CmdletBinding()]
param(
    [string]$Dotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe',
    [string]$WorkRoot='D:\Codex\RansomFree'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$env:TEMP=Join-Path $WorkRoot 'temp'; $env:TMP=$env:TEMP
$env:NUGET_PACKAGES=Join-Path $WorkRoot 'nuget-packages'
$env:NUGET_HTTP_CACHE_PATH=Join-Path $WorkRoot 'nuget-http-cache'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'; $env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
[void][IO.Directory]::CreateDirectory($env:TEMP)
$project=Join-Path $repo 'src\RansomFree.Server\RansomFree.Server.csproj'
[xml]$projectXml=Get-Content -LiteralPath $project -Raw
$versionNodes=@($projectXml.SelectNodes('/Project/PropertyGroup/Version'))
$fileVersionNodes=@($projectXml.SelectNodes('/Project/PropertyGroup/FileVersion'))
$informationalVersionNodes=@($projectXml.SelectNodes('/Project/PropertyGroup/InformationalVersion'))
if($versionNodes.Count -ne 1 -or $fileVersionNodes.Count -ne 1 -or $informationalVersionNodes.Count -ne 1){throw 'Server project must define one Version, FileVersion and InformationalVersion.'}
$version=$versionNodes[0].InnerText.Trim()
$fileVersion=$fileVersionNodes[0].InnerText.Trim()
$informationalVersion=$informationalVersionNodes[0].InnerText.Trim()
if($version -notmatch '^\d+\.\d+\.\d+$'){throw 'Server project Version must be a three-part numeric version.'}
if($fileVersion -cne ($version+'.0')){throw 'Server project FileVersion must match Version with a .0 suffix.'}
if($informationalVersion -notmatch ('^'+[Regex]::Escape($version)+'(?:[-+][0-9A-Za-z.-]+)+$')){throw 'Server project InformationalVersion must identify the same Version.'}
$release='ransomfree-management-'+$informationalVersion+'.'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'-win-x64'
$output=Join-Path $WorkRoot ('packages\windows-management\'+$release)
if(Test-Path -LiteralPath $output){throw 'Immutable destination exists.'}
$payload=Join-Path $output 'payload'; [void][IO.Directory]::CreateDirectory($payload)
& $Dotnet publish $project -c Release -r win-x64 --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') -o (Join-Path $payload 'app') -p:RestoreLockedMode=true -p:DebugType=None -p:DebugSymbols=false
if($LASTEXITCODE -ne 0){throw 'Publish failed; partial output preserved.'}
$serverExe=Join-Path $payload 'app\RansomFree.Server.exe'
$publishedIdentity=[Diagnostics.FileVersionInfo]::GetVersionInfo($serverExe)
if($publishedIdentity.FileVersion -cne $fileVersion){throw 'Published server FileVersion disagrees with the project.'}
if($publishedIdentity.ProductVersion -notmatch ('^'+[Regex]::Escape($informationalVersion)+'\+[0-9a-f]{40}$')){throw 'Published server ProductVersion is not a commit-bound project InformationalVersion.'}
$docs=Join-Path $payload 'docs'; [void][IO.Directory]::CreateDirectory($docs)
foreach($name in @('README.md','SQL_SERVER_SETUP.md','SSO_SETUP.md','DIRECTORY_SETUP.md','CALLBACK_SETUP.md')){Copy-Item -LiteralPath (Join-Path $repo "src\RansomFree.Server\$name") -Destination $docs}
Copy-Item -LiteralPath (Join-Path $repo 'packaging\linux-client\AUDIT.md') -Destination (Join-Path $docs 'LINUX_ATTRIBUTION.md')
$utf8=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $payload 'RELEASE_ID'),$release+"`n",$utf8)
$report="Unsigned $informationalVersion development build; no deployment or functional tests. Locked self-contained win-x64 publish only. Server-first upgrade required for Unix client attribution-v1. Existing data/configuration/keys are not included or modified. Configure using accompanying documentation; production startup gate remains in place. Native/UI/LDAP/Entra/MFA/Wazuh/queue/upgrade acceptance is pending.`n"
[IO.File]::WriteAllText((Join-Path $payload 'VERIFICATION-REPORT.txt'),$report,$utf8)
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File | Sort-Object FullName | ForEach-Object{[ordered]@{Path=$_.FullName.Substring($payload.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
$manifest=[ordered]@{Release=$release;Product='Quiver seQuester Management Server';Version=$version;InformationalVersion=$informationalVersion;Runtime='win-x64';AttributionVersion=1;Signed=$false;RuntimeAcceptance='NOT RUN';Files=$files}
[IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),($manifest|ConvertTo-Json -Depth 6)+"`n",$utf8)
foreach($file in $files){if((Get-FileHash -LiteralPath (Join-Path $payload $file.Path) -Algorithm SHA256).Hash -cne $file.Sha256){throw 'Payload hash mismatch.'}}
$archive=Join-Path $output ($release+'.zip')
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($payload,$archive)
$expected=@{}; foreach($file in Get-ChildItem -LiteralPath $payload -Recurse -File){$expected[$file.FullName.Substring($payload.Length+1).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
$zip=[IO.Compression.ZipFile]::OpenRead($archive); $seen=@{}
try{foreach($entry in $zip.Entries){$name=$entry.FullName.Replace('\','/');if(!$expected.ContainsKey($name) -or $seen.ContainsKey($name)){throw 'Archive inventory mismatch.'};$stream=$entry.Open();try{$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream));if($hash -cne $expected[$name]){throw 'Archive content mismatch.'}}finally{$stream.Dispose()};$seen[$name]=$true}}finally{$zip.Dispose()}
if($seen.Count -ne $expected.Count){throw 'Archive incomplete.'}
$hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($archive+'.sha256'),$hash+'  '+[IO.Path]::GetFileName($archive)+"`n",$utf8)
Write-Output "Built and archive hashes verified; not deployed: $archive"
