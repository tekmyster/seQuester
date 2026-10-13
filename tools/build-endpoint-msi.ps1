[CmdletBinding()]
param(
    [string]$Dotnet = 'C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe',
    [string]$Wix = 'D:\Codex\RansomFree\tools\wix4\wix.exe',
    [string]$WorkRoot = 'D:\Codex\RansomFree'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
[xml]$productDefinition = Get-Content -LiteralPath (Join-Path $repo 'packaging\windows\Product.wxs') -Raw
if ($productDefinition.Wix.Package.Version -eq '0.6.3' -or $productDefinition.Wix.Package.ProductCode -eq '1F26AA94-2E07-4648-A0FD-1458E12EB321') {
    throw 'Unreleased payload changed. Finalize the new package version/ProductCode and matching deployment scripts after acceptance; do not reuse the 0.6.3 package identity.'
}
$packageVersion=[string]$productDefinition.Wix.Package.Version
$productCode='{'+([string]$productDefinition.Wix.Package.ProductCode).ToUpperInvariant()+'}'
foreach ($script in @('Install-Endpoint.ps1','Detect-Endpoint.ps1','Uninstall-Endpoint.ps1','Configure-Endpoint.ps1')) {
    $sourceText=Get-Content -LiteralPath (Join-Path $repo ('packaging\windows\'+$script)) -Raw
    if ($sourceText.Contains('0.6.3') -or $sourceText.Contains('1F26AA94-2E07-4648-A0FD-1458E12EB321')) { throw 'Deployment scripts still carry the superseded package identity. Finalize release identities together.' }
}
[xml]$agentDefinition=Get-Content -LiteralPath (Join-Path $repo 'src\seQuester.Agent\seQuester.Agent.csproj') -Raw
$agentVersionNode=$agentDefinition.SelectSingleNode('/Project/PropertyGroup/Version')
if ($null -eq $agentVersionNode) { throw 'Agent version is missing.' }
$applicationVersion=$agentVersionNode.InnerText+'-dev'
$env:TEMP = Join-Path $WorkRoot 'temp'
$env:TMP = $env:TEMP
$env:DOTNET_ROOT = Split-Path $Dotnet -Parent
$env:DOTNET_ROLL_FORWARD = 'Major'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$output = Join-Path $WorkRoot ('packages\windows\'+$packageVersion+'-unsigned-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($output) | Out-Null
[IO.Directory]::CreateDirectory($env:TEMP) | Out-Null
if (!(Test-Path -LiteralPath $Wix)) { throw 'Install the pinned wix 4.0.6 tool into WorkRoot\tools\wix4 first. See packaging/windows/README.md.' }
foreach ($project in @('Agent','Tray','DecoyHost')) {
    & $Dotnet publish (Join-Path $repo "src\seQuester.$project\seQuester.$project.csproj") --configuration Release --runtime win-x64 --self-contained true --artifacts-path (Join-Path $WorkRoot 'artifacts') --output (Join-Path $output $project) -p:PublishSingleFile=false -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) { throw "Publish failed: $project" }
}
$ns = 'http://wixtoolset.org/schemas/v4/wxs'
$doc = New-Object System.Xml.XmlDocument
$root = $doc.CreateElement('Wix',$ns); [void]$doc.AppendChild($root)
function Element($parent, $name, $attributes) {
    $node = $doc.CreateElement($name,$ns)
    foreach ($key in $attributes.Keys) { $node.SetAttribute($key,[string]$attributes[$key]) }
    [void]$parent.AppendChild($node)
    return $node
}
function StableId([string]$value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return 'F' + ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))).Replace('-','').Substring(0,40)) }
    finally { $sha.Dispose() }
}
foreach ($project in @('Agent','Tray','DecoyHost')) {
    $fragment = Element $root 'Fragment' @{}
    $group = Element $fragment 'ComponentGroup' @{Id=$project+'Payload'}
    $directory = Element $fragment 'DirectoryRef' @{Id=$project+'Folder'}
    $dirs = @{''=$directory}
    $source = Join-Path $output $project
    foreach ($file in Get-ChildItem -LiteralPath $source -File -Recurse | Sort-Object FullName) {
        $relative = $file.FullName.Substring($source.Length+1)
        if ($relative -eq 'RansomFree.Agent.exe' -or $file.Extension -eq '.pdb') { continue }
        $parent = $directory; $key = ''
        $parts = $relative.Split('\')
        for ($i=0; $i -lt $parts.Length-1; $i++) {
            $key += '\' + $parts[$i]
            if (!$dirs.ContainsKey($key)) { $dirs[$key] = Element $parent 'Directory' @{Id=(StableId ($project+$key));Name=$parts[$i]} }
            $parent = $dirs[$key]
        }
        $id = StableId ($project+'\'+$relative)
        $component = Element $parent 'Component' @{Id=('C'+$id);Guid='*';Bitness='always64'}
        [void](Element $component 'File' @{Id=$id;Source=$file.FullName;KeyPath='yes'})
        [void](Element $group 'ComponentRef' @{Id=('C'+$id)})
    }
}
$payload = Join-Path $output 'Payload.wxs'; $doc.Save($payload)
$msi = Join-Path $output ('RansomFree.Endpoint.'+$packageVersion+'.win-x64.unsigned.msi')
& $Wix build (Join-Path $repo 'packaging\windows\Product.wxs') $payload -arch x64 -d "AgentSource=$(Join-Path $output 'Agent')" -d "BrandSource=$(Join-Path $repo 'Assets\Branding')" -intermediateFolder (Join-Path $output 'wix-temp') -out $msi
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed.' }
foreach ($name in @('Configure-Endpoint.ps1','Install-Endpoint.ps1','Uninstall-Endpoint.ps1','Detect-Endpoint.ps1','deployment.example.json','README.md')) {
    Copy-Item -LiteralPath (Join-Path $repo "packaging\windows\$name") -Destination $output
}
$manifest = [ordered]@{PackageVersion=$packageVersion;ApplicationVersion=$applicationVersion;Architecture='win-x64';Signed=$false;FunctionalTests='Deferred';SessionCompanion=$true;SessionCompanionEnabledByDefault=$false;ProductCode=$productCode;UpgradeCode='{AE418339-410C-4D8E-83C3-A7C5AA77DC58}';BuiltUtc=[DateTime]::UtcNow.ToString('o');Files=@(Get-ChildItem -LiteralPath $output -File | Where-Object Extension -ne '.wixpdb' | ForEach-Object { @{Name=$_.Name;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash;Bytes=$_.Length} })}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding UTF8
$bundleFiles = @(Get-ChildItem -LiteralPath $output -File | Where-Object Extension -ne '.wixpdb' | Select-Object -ExpandProperty FullName)
Compress-Archive -LiteralPath $bundleFiles -DestinationPath (Join-Path $output ('RansomFree.Endpoint.'+$packageVersion+'.deployment.zip')) -CompressionLevel Optimal
Write-Output "Unsigned, not installed or runtime-tested: $msi"
