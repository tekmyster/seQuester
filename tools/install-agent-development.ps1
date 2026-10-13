#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentBuild,
    [Parameter(Mandatory)][string]$TrayBuild,
    [switch]$AllowUnsignedDevelopment,
    [string]$TrayUser
)
$ErrorActionPreference = 'Stop'
if (-not $AllowUnsignedDevelopment) { throw 'This unsigned installer is for development only. Explicit -AllowUnsignedDevelopment is required.' }
$agentSource = (Resolve-Path -LiteralPath $AgentBuild).Path
$traySource = (Resolve-Path -LiteralPath $TrayBuild).Path
foreach ($source in @($agentSource, $traySource)) {
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Build paths must be directories.' }
    if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Build path must not be a link.' }
    if (Get-ChildItem -LiteralPath $source -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Build contains links. Installation refused.' }
}
if (-not (Test-Path -LiteralPath (Join-Path $agentSource 'RansomFree.Agent.exe')) -or -not (Test-Path -LiteralPath (Join-Path $traySource 'RansomFree.exe'))) { throw 'Required published executables are missing.' }
if (Get-Service -Name RansomFreeAgent -ErrorAction SilentlyContinue) { throw 'Service already exists. Use a reviewed upgrade; this installer does not overwrite installations.' }
$installRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RansomFree'))
if (Test-Path -LiteralPath $installRoot) { throw 'Installation directory already exists and is preserved.' }
$agentTarget = Join-Path $installRoot 'Agent'
$trayTarget = Join-Path $installRoot 'Tray'
$null = New-Item -ItemType Directory -Path $agentTarget, $trayTarget
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $installRoot -AclObject $security
Get-ChildItem -LiteralPath $agentSource -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $agentTarget -Recurse }
Get-ChildItem -LiteralPath $traySource -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $trayTarget -Recurse }
$agentExe = Join-Path $agentTarget 'RansomFree.Agent.exe'
$null = New-Service -Name RansomFreeAgent -DisplayName 'Ransom Free Agent (Development)' -BinaryPathName ('"' + $agentExe + '"') -StartupType Manual -Description 'Unsigned development canary monitoring agent. Acceptance testing pending.'
& sc.exe failure RansomFreeAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000
if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed. Service is installed but was not started.' }
if ($TrayUser) {
    $trayExe = Join-Path $trayTarget 'RansomFree.exe'
    $action = New-ScheduledTaskAction -Execute $trayExe -Argument '--managed-tray --tray'
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $TrayUser
    $principal = New-ScheduledTaskPrincipal -UserId $TrayUser -LogonType Interactive -RunLevel Highest
    $null = Register-ScheduledTask -TaskName RansomFreeManagedTray -Action $action -Trigger $trigger -Principal $principal -Description 'Managed Ransom Free tray; local administrator access required.'
}
Write-Output 'Installed unsigned development files and a stopped/manual service. No canaries, firewall rules, enrollment, or service startup were performed. Provision the administration password, enrollment and folder approvals before an authorized test run.'
