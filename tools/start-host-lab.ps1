[CmdletBinding()]
param([switch]$StartAgent)
$ErrorActionPreference='Stop'
$labRoot='D:\Codex\RansomFree\lab\host'
$releaseRoot='D:\Codex\RansomFree\lab\release-20260912'
$dotnetPath='C:\Users\dmessana\AppData\Local\RansomFreeBuild\dotnet\dotnet.exe'
$env:TEMP='D:\Codex\RansomFree\temp';$env:TMP=$env:TEMP
foreach($path in @($labRoot,$releaseRoot)) {
    for($ancestor=$path;$ancestor;$ancestor=Split-Path -Parent $ancestor) {
        if((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Lab paths may not traverse links'}
    }
}
New-Item -ItemType Directory -Path $labRoot -Force | Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $labRoot -AclObject $acl
foreach($name in @('server','agent','callbacks','logs')){New-Item -ItemType Directory -Path (Join-Path $labRoot $name) -Force | Out-Null}
function Start-LabProcess($role,$arguments) {
    $pidPath=Join-Path $labRoot ($role+'.json')
    if(Test-Path -LiteralPath $pidPath){$prior=Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json;$existing=Get-Process -Id $prior.Pid -ErrorAction SilentlyContinue;if($existing -and $existing.StartTime.ToUniversalTime().ToString('o') -eq $prior.Started){Write-Output "$role is already running";return}}
    $process=Start-Process -FilePath $dotnetPath -ArgumentList $arguments -WorkingDirectory $labRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $labRoot "logs\$role.out.log") -RedirectStandardError (Join-Path $labRoot "logs\$role.err.log") -PassThru
    @{Pid=$process.Id;Started=$process.StartTime.ToUniversalTime().ToString('o');Role=$role;Arguments=$arguments} | ConvertTo-Json | Set-Content -LiteralPath $pidPath
    Write-Output "$role started (PID $($process.Id))"
}
if($StartAgent){
    if(!(Test-Path -LiteralPath "$labRoot\agent\connection.json") -or !(Test-Path -LiteralPath "$labRoot\agent\settings.json")){throw 'Provision agent enrollment and canaries first'}
    $env:DOTNET_ENVIRONMENT='Development';$env:RF_CONSOLE_LAB_CERTIFICATE=Join-Path $labRoot 'localhost-public.cer'
    Start-LabProcess 'agent' ('"'+$releaseRoot+'\agent\RansomFree.Agent.dll" --console --data "'+$labRoot+'\agent"')
    exit
}
$keyPath=Join-Path $labRoot 'bootstrap.dpapi'
if(!(Test-Path -LiteralPath $keyPath)){
    $secret=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    [IO.File]::WriteAllBytes($keyPath,[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($secret),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
}
$env:RF_ADMIN_KEY=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$env:RF_DATA_DIR=Join-Path $labRoot 'server';$env:RF_CALLBACK_DATA=Join-Path $labRoot 'callbacks'
$env:RF_PASSWORD_POLICY_FILE='D:\Codex\RansomFree\lab\password-policy.json'
$env:ASPNETCORE_ENVIRONMENT='Development';$env:Database__Provider='Sqlite'
$env:Callbacks__Enabled='true';$env:Callbacks__Origin='https://localhost:18444/'
$env:Callbacks__Syslog__Enabled='false';$env:Dns__Enabled='false';$env:Smtp__Enabled='false'
$env:Logging__LogLevel__Default='Warning'
# Reuse the existing localhost certificate without changing Windows trust stores.
$cert=Get-Item 'Cert:\CurrentUser\My\84206B9BE1AF9EE2B346F338EA3FD3021E4900AB'
if(!$cert.HasPrivateKey -or $cert.NotAfter -lt (Get-Date)){throw 'Localhost certificate unavailable/expired'}
$publicCert=Join-Path $labRoot 'localhost-public.cer';[IO.File]::WriteAllBytes($publicCert,$cert.RawData)
$env:Kestrel__Certificates__Default__Subject='localhost';$env:Kestrel__Certificates__Default__Store='My';$env:Kestrel__Certificates__Default__Location='CurrentUser';$env:Kestrel__Certificates__Default__AllowInvalid='true'
$env:RF_ALLOW_LOOPBACK_HTTP='true';$env:ASPNETCORE_URLS='http://127.0.0.1:18080;https://127.0.0.1:18443'
Start-LabProcess 'server' ('"'+$releaseRoot+'\server\RansomFree.Server.dll"')
for($attempt=0;$attempt -lt 30;$attempt++){try{$null=Invoke-RestMethod 'http://127.0.0.1:18080/health/live';break}catch{if($attempt -eq 29){throw 'Management startup failed; inspect lab logs'};Start-Sleep -Milliseconds 500}}
# Server's callback worker provisions the isolated registry/inbox before receiver startup.
if(!(Test-Path -LiteralPath "$labRoot\callbacks\registry\tokens.db")){throw 'Callback registry has not initialized'}
$env:RF_ADMIN_KEY=$null;$env:ASPNETCORE_URLS='https://127.0.0.1:18444;http://127.0.0.1:18081'
Start-LabProcess 'receiver' ('"'+$releaseRoot+'\receiver\RansomFree.Receiver.dll"')
Write-Output 'WebUI: http://127.0.0.1:18080/ (current host only). No reboot autostart configured.'
