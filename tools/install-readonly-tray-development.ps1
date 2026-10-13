#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TrayBuild,[Parameter(Mandatory)][string]$User,[switch]$AllowUnsignedDevelopment)
$ErrorActionPreference='Stop'
if(-not $AllowUnsignedDevelopment){throw 'Unsigned development provisioning requires -AllowUnsignedDevelopment.'}
function Assert-NoLinks([string]$Path){
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Path traverses a link.'};$cursor=[IO.Path]::GetDirectoryName($cursor)}
}
$source=(Resolve-Path -LiteralPath $TrayBuild).Path
Assert-NoLinks $source
if(-not (Test-Path -LiteralPath (Join-Path $source 'RansomFree.Tray.exe'))){throw 'Publish the dedicated RansomFree.Tray project first.'}
if(Get-ChildItem -LiteralPath $source -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Build contains links.'}
if((Get-Service -Name RansomFreeAgent).Status -ne 'Stopped'){throw 'Stop the installed agent through authorized maintenance before provisioning reader access.'}
$readerSid=([Security.Principal.NTAccount]::new($User)).Translate([Security.Principal.SecurityIdentifier])
if($readerSid.Value -notmatch '^S-1-(5-21|12-1)(-[0-9]+){4}$'){throw 'Specify an individual local, domain or Entra user account.'}
$installRoot=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RansomFree'))
$target=Join-Path $installRoot 'ReadOnlyTray'
$agentState=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RansomFree\Agent'
$approvals=Join-Path $agentState 'tray-readers.json'
Assert-NoLinks $installRoot
Assert-NoLinks $agentState
if(-not (Test-Path -LiteralPath (Join-Path $installRoot 'Agent\RansomFree.Agent.exe')) -or -not (Test-Path -LiteralPath $agentState -PathType Container)){throw 'Installed agent and protected, provisioned state are required.'}
if((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath $approvals) -or (Get-ScheduledTask -TaskName RansomFreeReadOnlyTray -ErrorAction SilentlyContinue)){throw 'Existing installation/approvals/task are preserved. Use reviewed maintenance.'}
$stateSecurity=[Security.AccessControl.DirectorySecurity]::new();$stateSecurity.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$stateSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $agentState -AclObject $stateSecurity
$null=New-Item -ItemType Directory -Path $target
$traySecurity=[Security.AccessControl.DirectorySecurity]::new();$traySecurity.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$traySecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
$traySecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($readerSid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $target -AclObject $traySecurity
$rootSecurity=Get-Acl -LiteralPath $installRoot
$rootSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($readerSid,'ReadAndExecute','None','None','Allow'))
Set-Acl -LiteralPath $installRoot -AclObject $rootSecurity
Get-ChildItem -LiteralPath $source -Force | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination $target -Recurse}
$stream=[IO.FileStream]::new($approvals,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($readerSid.Value) -Compress));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$action=New-ScheduledTaskAction -Execute (Join-Path $target 'RansomFree.Tray.exe') -Argument '--tray'
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $User
$principal=New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
$null=Register-ScheduledTask -TaskName RansomFreeReadOnlyTray -Action $action -Trigger $trigger -Principal $principal -Description 'Read-only Ransom Free tray for an approved user; unsigned development build.'
Write-Output 'Read-only tray and explicit reader approval provisioned. Agent remains stopped; no app, task, canary or listener was started. Partial failures preserve created files for reviewed recovery.'
