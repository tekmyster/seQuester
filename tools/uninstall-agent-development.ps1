#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][Security.SecureString]$AdministrationPassword)
$ErrorActionPreference = 'Stop'
$installRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RansomFree'))
$agentExe = Join-Path $installRoot 'Agent/RansomFree.Agent.exe'
if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) { throw 'The expected installed agent was not found.' }
for ($pathCheck = $installRoot; $pathCheck; $pathCheck = [IO.Path]::GetDirectoryName($pathCheck)) {
    if ((Get-Item -LiteralPath $pathCheck -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation path traverses a link. Maintenance refused.' }
}
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdministrationPassword)
try {
    $start = [Diagnostics.ProcessStartInfo]::new($agentExe, '--verify-maintenance')
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true; $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $process.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)); $process.StandardInput.Close()
        $outputRead = $process.StandardOutput.ReadToEndAsync(); $errorRead = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { throw 'Maintenance verification did not finish. No service was stopped.' }
        if ($process.ExitCode -ne 0) { throw 'Administration verification failed. Installation was preserved.' }
    } finally { $process.Dispose() }
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
$service = Get-Service -Name RansomFreeAgent -ErrorAction Stop
if ($service.Status -ne 'Stopped') { Stop-Service -Name RansomFreeAgent -ErrorAction Stop; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
& sc.exe delete RansomFreeAgent
if ($LASTEXITCODE -ne 0) { throw 'Service removal failed; installation files were preserved.' }
if (Get-ScheduledTask -TaskName RansomFreeManagedTray -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName RansomFreeManagedTray -Confirm:$false }
Write-Output 'Agent service and managed-tray startup registration removed. Installation files, agent settings, logs and all canary files were preserved. Close the tray manually. Revoke endpoint credentials and callback tokens in management as appropriate. Windows administrators can bypass application-level password gates; this is not kernel tamper protection.'
