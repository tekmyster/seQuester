[CmdletBinding()]
param([Parameter(Mandatory)][Security.SecureString]$Password)
$ErrorActionPreference='Stop'
$labRoot='D:\Codex\RansomFree\lab\host';$targetRoot='D:\Codex\RansomFree\LabTargets';$origin='http://127.0.0.1:18080'
if(Test-Path -LiteralPath "$labRoot\agent\settings.json"){throw 'Lab already provisioned; existing canaries are preserved'}
if(Test-Path -LiteralPath $targetRoot){throw 'Target root already exists; refusing to overwrite'}
$key=[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes("$labRoot\bootstrap.dpapi"),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))
$adminHeaders=@{Authorization="Bearer $key"}
$plain=[Net.NetworkCredential]::new('', $Password).Password
$create=@{userName='tekmyster';password=$plain;role='Administrator'} | ConvertTo-Json
try{$null=Invoke-RestMethod "$origin/api/v1/admin/users" -Method Post -Headers $adminHeaders -ContentType application/json -Body $create}catch{throw 'Lab account creation failed; inspect server logs without disclosing credentials'}
$session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()
$csrf=Invoke-RestMethod "$origin/api/v1/auth/csrf" -WebSession $session
$null=Invoke-RestMethod "$origin/api/v1/auth/login" -Method Post -WebSession $session -Headers @{'X-CSRF'=$csrf.token} -ContentType application/json -Body (@{userName='tekmyster';password=$plain} | ConvertTo-Json)
$plain=$null;$create=$null
$csrf=Invoke-RestMethod "$origin/api/v1/auth/csrf" -WebSession $session
$headers=@{'X-CSRF'=$csrf.token}
$me=Invoke-RestMethod "$origin/api/v1/auth/me" -WebSession $session
Write-Output "Verified sign-in for $($me.userName)"
$code=Invoke-RestMethod "$origin/api/v1/admin/enrollment-codes" -Method Post -Headers $adminHeaders
$endpoint=Invoke-RestMethod "$origin/api/v1/enroll" -Method Post -ContentType application/json -Body (@{code=$code.code;machineName=$env:COMPUTERNAME+' - D drive lab';agentVersion='0.6.0-dev'} | ConvertTo-Json)
$connection=@{Server='https://localhost:18443';EndpointId=$endpoint.endpointId;ProtectedCredential=[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($endpoint.credential),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine))}
$connection | ConvertTo-Json | Set-Content -LiteralPath "$labRoot\agent\connection.json"
$endpoint=$null;$code=$null;$key=$null;$adminHeaders=$null
# Enable a privilege on this provisioning process only; global audit policy is already enabled.
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.ComponentModel;
public static class LabAuditPrivilege {
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Luid; public uint Attributes; }
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privileges state,uint size,IntPtr prior,IntPtr returned);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static void Enable(){IntPtr token;if(!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,0x28,out token))throw new Win32Exception();try{Luid luid;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid))throw new Win32Exception();var p=new Privileges{Count=1,Luid=luid,Attributes=2};if(!AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()!=0)throw new Win32Exception();}finally{CloseHandle(token);}}
}
'@
[LabAuditPrivilege]::Enable()
New-Item -ItemType Directory -Path $targetRoot | Out-Null
$canaries=@();$manifest=@()
foreach($folder in @('Documents','Finance','Backups','IT','Shared')) {
    $directory=Join-Path $targetRoot $folder;New-Item -ItemType Directory -Path $directory | Out-Null
    foreach($spec in @(@{Name='!_Account_Recovery';Type='docx'},@{Name='Financial_Records';Type='xlsx'},@{Name='zz_Confidential_Archive';Type='pdf'},@{Name='Network_Overview';Type='svg'})) {
        $token=Invoke-RestMethod "$origin/api/v1/console/callbacks/tokens" -Method Post -WebSession $session -Headers $headers -ContentType application/json -Body (@{name=$spec.Name;type=$spec.Type} | ConvertTo-Json)
        $path=Join-Path $directory ($spec.Name+'.'+$spec.Type)
        Invoke-WebRequest "$origin/api/v1/console/callbacks/tokens/$($token.id)/download" -Method Post -WebSession $session -Headers $headers -OutFile $path | Out-Null
        $security=Get-Acl -LiteralPath $path -Audit
        $rights=[Security.AccessControl.FileSystemRights]::ReadData -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete
        $security.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),$rights,([Security.AccessControl.AuditFlags]::Success -bor [Security.AccessControl.AuditFlags]::Failure)))
        Set-Acl -LiteralPath $path -AclObject $security
        $canaries+=@{Path=$path;Hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;Tripwire='Local audit + localhost HTTPS callback (reader trust dependent)'}
        $manifest+=@{Path=$path;TokenId=$token.id;Type=$spec.Type;Callback='https://localhost:18444/t/'+$token.id+'/pixel.png'}
        # Journal each owned artifact to preserve evidence on partial failure.
        @{Canaries=@($canaries)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$labRoot\agent\settings.json"
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$labRoot\canary-manifest.json"
    }
}
$null=Invoke-RestMethod "$origin/api/v1/auth/logout" -Method Post -WebSession $session -Headers $headers
Write-Output "Provisioned $($canaries.Count) canaries across five D: lab folders. Automatic response and syslog are disabled."
