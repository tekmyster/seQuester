[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Dotnet,
    [switch]$CheckOnly
)

# Local engineering verification, never a production approval or installer.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dotnetPath = (Resolve-Path -LiteralPath $Dotnet).Path
if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) { throw 'Dotnet must identify an executable file.' }
foreach ($project in @('src/RansomFree.Server/RansomFree.Server.csproj','src/RansomFree.Agent/RansomFree.Agent.csproj','tests/RansomFree.Server.Tests/RansomFree.Server.Tests.csproj')) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $project) -PathType Leaf)) { throw "Required project missing: $project" }
}
if ($CheckOnly) { Write-Output 'Input checks passed. No build or runtime checks were performed.'; return }

$runDirectory = Join-Path $projectRoot ('dist-release-qa-' + [guid]::NewGuid().ToString('N'))
$resolvedRun = [IO.Path]::GetFullPath($runDirectory)
if (-not $resolvedRun.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence directory escaped the project.' }
if (Test-Path -LiteralPath $resolvedRun) { throw 'Evidence directory already exists; refusing overwrite.' }
New-Item -ItemType Directory -Path $resolvedRun | Out-Null
$results = [Collections.Generic.List[object]]::new()
$manifest = [ordered]@{
    CreatedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    Status = 'Running'
    ProductionApproved = $false
    Checks = $results
    Artifacts = @()
    Limitations = @(
        'Windows-only runtime checks; Linux output is cross-published, not executed.',
        'Synthetic and loopback tests are not live Wazuh, directory, Entra, or trusted deployment acceptance.',
        'No service installation, signing, firewall changes, or production deployment is performed.',
        'Visual, accessibility, capacity, recovery, and security release gates remain separately required.',
        'Production startup remains refused by the development server.'
    )
}
function Invoke-VerifiedStep([string]$Name,[string[]]$Arguments) {
    $log = Join-Path $resolvedRun ($Name + '.log')
    & $dotnetPath @Arguments 2>&1 | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
    $code = $LASTEXITCODE
    $results.Add([ordered]@{Name=$Name;ExitCode=$code;Passed=($code -eq 0);Log=$log})
    if ($code -ne 0) { throw "Verification step failed: $Name (exit $code). Evidence preserved at $resolvedRun" }
}
$previousDirectory = Get-Location
try {
    Set-Location -LiteralPath $projectRoot
    Invoke-VerifiedStep 'sdk' @('--info')
    Invoke-VerifiedStep 'server-windows' @('publish','src/RansomFree.Server','-c','Release','-r','win-x64','--self-contained','true','-o',(Join-Path $resolvedRun 'server-windows'))
    Invoke-VerifiedStep 'server-linux' @('publish','src/RansomFree.Server','-c','Release','-r','linux-x64','--self-contained','true','-o',(Join-Path $resolvedRun 'server-linux'))
    Invoke-VerifiedStep 'agent-windows' @('publish','src/RansomFree.Agent','-c','Release','-r','win-x64','--self-contained','true','-o',(Join-Path $resolvedRun 'agent-windows'))
    Invoke-VerifiedStep 'integration' @('run','--project','tests/RansomFree.Server.Tests','-c','Release','--',$dotnetPath,(Join-Path $resolvedRun 'server-windows/RansomFree.Server.dll'),(Join-Path $resolvedRun 'agent-windows/RansomFree.Agent.dll'))
    $manifest.Artifacts = @(Get-ChildItem -LiteralPath $resolvedRun -Recurse -File | Where-Object { $_.Extension -in '.exe','.dll','.json','.ttf' } | ForEach-Object {
        [ordered]@{Path=[IO.Path]::GetRelativePath($resolvedRun,$_.FullName);Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    $manifest.Status = 'LocalChecksPassed_NotProductionApproved'
}
catch {
    $manifest.Status = 'Failed'
    throw
}
finally {
    $manifest.CompletedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $resolvedRun 'verification.json') -Encoding utf8
    Set-Location -LiteralPath $previousDirectory.Path
    Write-Output "Verification evidence: $resolvedRun"
}
