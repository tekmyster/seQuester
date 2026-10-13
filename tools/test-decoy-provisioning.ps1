[CmdletBinding()]
param([string]$RepositoryRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$evidence=Join-Path 'D:\Codex\RansomFree\tests' ('decoy-provisioning-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($evidence)
$results=[Collections.Generic.List[string]]::new()
function Check([bool]$condition,[string]$name) {
    if (!$condition) { throw $name }
    $results.Add('PASS: '+$name)
    $results | Set-Content -LiteralPath (Join-Path $evidence 'results.txt')
}
$configure=Join-Path $RepositoryRoot 'packaging\windows\Configure-Endpoint.ps1'
$text=[IO.File]::ReadAllText($configure)
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($configure,[ref]$tokens,[ref]$errors)
Check (!$errors.Count) 'configuration script parses without executing provisioning'
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-DecoySessionCapability'},$true)
Check ($null -ne $function) 'capability guard exists'
. ([scriptblock]::Create($function.Extent.Text))
foreach ($value in @('0.6.4','0.6.4+abc123','0.6.4-dev','0.6.4.0','0.7.0','1.0.0')) {
    Assert-DecoySessionCapability $value
    Check $true ('supported protected-image version accepted: '+$value)
}
foreach ($value in @('0.6.3','0.6.3-dev','0.6.3.99','0.5.99','', 'unknown', '0.6.4;start', '0.6.4 junk')) {
    $refused=$false
    try { Assert-DecoySessionCapability $value } catch { $refused=$true }
    Check $refused ('old or malformed version refused: '+$value)
}
Check ($text.IndexOf('Assert-DecoySessionCapability ([Diagnostics.') -lt $text.IndexOf('$service = Get-Service')) 'capability preflight precedes service/state changes'
Check ($text.Contains('Read-InputFile $DecoySessionPolicyFile $true 131072')) 'policy input is private and bounded'
Check ($text.IndexOf("Invoke-Agent '--verify-maintenance'") -lt $text.IndexOf("Invoke-Agent ('--set-decoy-session-policy")) 'existing password verification precedes policy publication'
Check ($text.IndexOf("Invoke-Agent ('--set-decoy-session-policy") -lt $text.IndexOf('Start-Service -Name')) 'publication precedes optional service startup'
Check ($text.Contains('finally { $password = $null }')) 'password reference cleared on policy failure'
Check ($text.Contains('Check-Acl $companion $false') -and $text.Contains('Check-Acl $agent $false')) 'installed images checked for protected ownership/access'
$installer=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'packaging\windows\Install-Endpoint.ps1'))
$null=[Management.Automation.Language.Parser]::ParseInput($installer,[ref]$tokens,[ref]$errors)
Check (!$errors.Count) 'install wrapper parses without invoking MSI'
Check ($installer.IndexOf('if ($DecoySessionPolicyFile -and') -lt $installer.IndexOf('Start-Process')) 'policy option prerequisites precede MSI invocation'
Check ($installer.Contains('-DecoySessionPolicyFile $DecoySessionPolicyFile')) 'wrapper forwards policy path without secret command arguments'
$markerFunction=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ProvisioningMarker'},$true)
. ([scriptblock]::Create($markerFunction.Extent.Text))
$marker=[pscustomobject]@{SchemaVersion=1;Server='https://manager.example';PackageVersion='0.6.3'}
Assert-ProvisioningMarker $marker 'https://manager.example' '0.6.4'
Check $true 'prior receipt accepted for reviewed forward provisioning without rewriting it'
Assert-ProvisioningMarker $marker 'https://manager.example' '0.6.3'
Check $true 'same-version provisioning receipt accepted for retry'
foreach ($changed in @(
    [pscustomobject]@{SchemaVersion=1;Server='https://manager.example';PackageVersion='0.6.5'},
    [pscustomobject]@{SchemaVersion=1;Server='https://different.example';PackageVersion='0.6.4'},
    [pscustomobject]@{SchemaVersion=2;Server='https://manager.example';PackageVersion='0.6.4'},
    [pscustomobject]@{SchemaVersion=1;Server='https://manager.example';PackageVersion='garbage'},
    [pscustomobject]@{SchemaVersion=1;Server='https://manager.example';PackageVersion='0.6.4';Extra='ignored'})) {
    $refused=$false; try { Assert-ProvisioningMarker $changed 'https://manager.example' '0.6.4' } catch { $refused=$true }
    Check $refused ('conflicting receipt rejected: '+($changed | ConvertTo-Json -Compress))
}
$writer=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-NewJson'},$true)
. ([scriptblock]::Create($writer.Extent.Text))
$oldReceipt=Join-Path $evidence 'deployment-provisioned.json'; Write-NewJson $oldReceipt $marker
$oldHash=(Get-FileHash -LiteralPath $oldReceipt).Hash
$newReceipt=Join-Path $evidence 'deployment-provisioned.0.6.4.json'
$newMarker=[ordered]@{SchemaVersion=1;Server='https://manager.example';PackageVersion='0.6.4'}
Write-NewJson $newReceipt $newMarker
Check ((Get-FileHash -LiteralPath $oldReceipt).Hash -eq $oldHash) 'version-specific receipt preserves original bytes'
$newHash=(Get-FileHash -LiteralPath $newReceipt).Hash
Write-NewJson $newReceipt $newMarker
Check ((Get-FileHash -LiteralPath $newReceipt).Hash -eq $newHash) 'exact receipt retry preserves current bytes'
$refused=$false; try { Write-NewJson $newReceipt $marker } catch { $refused=$true }
Check ($refused -and (Get-FileHash -LiteralPath $newReceipt).Hash -eq $newHash) 'conflicting receipt write preserves current bytes'
$program=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'src\RansomFree.Agent\Program.cs'))
$versions=[regex]::Matches($program,'"([0-9]+\.[0-9]+\.[0-9]+-dev)"')
Check ($versions.Count -eq 3 -and @($versions | Where-Object { $_.Groups[1].Value -cne '0.6.4-dev' }).Count -eq 0) 'all three emitted Agent version literals agree'
foreach ($project in @('Agent','Tray','DecoyHost')) {
    [xml]$definition=Get-Content -LiteralPath (Join-Path $RepositoryRoot "src\RansomFree.$project\RansomFree.$project.csproj") -Raw
    Check ($definition.SelectSingleNode('/Project/PropertyGroup/Version').InnerText -eq '0.6.4') ($project+' candidate version agrees')
}
[xml]$product=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'packaging\windows\Product.wxs') -Raw
Check ($product.Wix.Package.Version -eq '0.6.4' -and $product.Wix.Package.ProductCode -eq '78B1841B-FCE5-4567-9298-DE1380F0BAE1') 'candidate MSI has new coordinated identity'
Check ($product.Wix.Package.UpgradeCode -eq 'AE418339-410C-4D8E-83C3-A7C5AA77DC58') 'upgrade family remains unchanged'
Check ($product.Wix.Package.MajorUpgrade.Schedule -eq 'afterInstallInitialize') 'transactional upgrade/rollback scheduling retained in authoring only'
Check (![string]::IsNullOrWhiteSpace($product.Wix.Package.MajorUpgrade.DowngradeErrorMessage)) 'MSI downgrade refusal remains authored'
Check ($installer.IndexOf('if (Get-Service -Name RansomFreeAgent') -lt $installer.IndexOf('Start-Process')) 'wrapper refuses unaccepted existing-service upgrades before MSI startup'
$remover=[IO.File]::ReadAllText((Join-Path $RepositoryRoot 'packaging\windows\Uninstall-Endpoint.ps1'))
Check ($remover.Contains($product.Wix.Package.Name) -and $remover.Contains($product.Wix.Package.ProductCode)) 'uninstall product identity agrees with package'
Check ($remover.IndexOf("foreach (`$name in @('decoy-session-policy.json'") -lt $remover.IndexOf('Start-Process')) 'uninstall wrapper refuses retained session state before MSI startup'
foreach ($script in @('Install-Endpoint.ps1','Configure-Endpoint.ps1','Detect-Endpoint.ps1','Uninstall-Endpoint.ps1')) {
    $path=Join-Path $RepositoryRoot ('packaging\windows\'+$script)
    $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Check (!$errors.Count) ($script+' final syntax valid')
    $source=[IO.File]::ReadAllText($path)
    Check (!$source.Contains('0.6.3') -and !$source.Contains('1F26AA94-2E07-4648-A0FD-1458E12EB321')) ($script+' carries no obsolete candidate identity')
}
Write-Output ($results.Count.ToString()+' focused checks passed: '+$evidence)
Write-Output 'Static flow/version checks only; no installed-service, ACL takeover or MSI lifecycle acceptance.'
