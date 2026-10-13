[CmdletBinding()]
param([string]$WorkRoot='D:\Codex\RansomFree',[string]$Dotnet='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
& (Join-Path $PSScriptRoot 'verify-brand-assets.ps1') -AssetRoot (Join-Path $repo 'Assets\Branding') | Out-Null
$env:TEMP=Join-Path $WorkRoot 'temp';$env:TMP=$env:TEMP;$env:NUGET_PACKAGES=Join-Path $WorkRoot 'nuget-packages';$env:NUGET_HTTP_CACHE_PATH=Join-Path $WorkRoot 'nuget-http-cache'
$root=Join-Path $WorkRoot ('packages\desktop-ux\sequester-desktop-ux.'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
if(Test-Path -LiteralPath $root){throw 'Immutable destination exists.'}
[void][IO.Directory]::CreateDirectory($root)
$results=@()
foreach($directory in @('win-x64','win-x64-readonly','linux-x64','linux-arm64','osx-x64','osx-arm64')){
    $runtime=if($directory -eq 'win-x64-readonly'){'win-x64'}else{$directory}
    $project=switch($directory){'win-x64'{'RansomFree.csproj'} 'win-x64-readonly'{'src\RansomFree.Tray\RansomFree.Tray.csproj'} default{'src\RansomFree.UnixDesktop\RansomFree.UnixDesktop.csproj'}}
    $role=switch($directory){'win-x64'{'Windows portable monitor / administrative managed tray'} 'win-x64-readonly'{'Windows read-only managed tray / explicit lab observer'} default{'Read-only Unix desktop; endpoint service not included'}}
    $version=([xml](Get-Content (Join-Path $repo $project) -Raw)).Project.PropertyGroup.Version
    $output=Join-Path $root $directory
    & $Dotnet publish (Join-Path $repo $project) -c Release -r $runtime --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') -o $output -p:DebugType=None -p:DebugSymbols=false
    if($LASTEXITCODE -ne 0){throw 'Desktop cross-publish failed; partial evidence preserved.'}
    & (Join-Path $PSScriptRoot 'verify-brand-assets.ps1') -AssetRoot (Join-Path $output 'Branding') | Out-Null
    $files=@(Get-ChildItem -LiteralPath $output -Recurse -File|Sort-Object FullName|ForEach-Object{[ordered]@{Path=$_.FullName.Substring($output.Length+1).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    $results+=[ordered]@{Directory=$directory;Runtime=$runtime;Version=$version;Role=$role;NativeAcceptance='PENDING';Files=$files}
}
Copy-Item -LiteralPath (Join-Path $repo 'UI_COPY_STANDARD.md') -Destination $root
$report=[ordered]@{Root=$root;Product='Quiver seQuester';Signed=$false;Deployed=$false;WindowsGuiVersion=([xml](Get-Content (Join-Path $repo 'RansomFree.csproj') -Raw)).Project.PropertyGroup.Version;UnixDesktopVersion=([xml](Get-Content (Join-Path $repo 'src\RansomFree.UnixDesktop\RansomFree.UnixDesktop.csproj') -Raw)).Project.PropertyGroup.Version;Installer=$false;Builds=$results}
[IO.File]::WriteAllText((Join-Path $root 'publish-manifest.json'),($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
[pscustomobject]@{Root=$root;Builds=$results.Count;Signed=$false;Deployed=$false;NativeAcceptance='PENDING';ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $root 'publish-manifest.json') -Algorithm SHA256).Hash}|ConvertTo-Json
