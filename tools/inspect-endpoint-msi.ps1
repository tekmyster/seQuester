# Read-only package inspection. Never installs, repairs, extracts or removes an MSI.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$directory=[IO.Path]::GetFullPath($PackageDirectory)
$manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw | ConvertFrom-Json
foreach ($file in $manifest.Files) {
    if ($file.Name -ne [IO.Path]::GetFileName($file.Name)) { throw 'Unsafe manifest entry.' }
    $path=Join-Path $directory $file.Name
    if ((Get-Item -LiteralPath $path).Length -ne $file.Bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file.Sha256) { throw 'Manifest hash/size mismatch.' }
}
$msis=@($manifest.Files | Where-Object Name -like '*.msi')
if ($msis.Count -ne 1) { throw 'Expected exactly one MSI.' }
$installer=New-Object -ComObject WindowsInstaller.Installer
$database=$installer.OpenDatabase((Join-Path $directory $msis[0].Name),0)
function Read-Table([string]$name) {
    $view=$database.OpenView('SELECT * FROM '+$name); [void]$view.Execute()
    try {
        while ($record=$view.Fetch()) {
            $count=$record.GetType().InvokeMember('FieldCount','GetProperty',$null,$record,$null)
            $values=for ($i=1;$i -le $count;$i++) { $record.GetType().InvokeMember('StringData','GetProperty',$null,$record,@($i)) }
            Write-Output -NoEnumerate ([string[]]$values)
        }
    } finally { [void]$view.Close() }
}
$properties=@{}
foreach ($row in (Read-Table 'Property')) { $properties[$row[0]]=$row[1] }
if ($properties.ProductCode -cne $manifest.ProductCode -or $properties.ProductVersion -ne $manifest.PackageVersion -or $properties.ALLUSERS -ne '1') { throw 'MSI product identity/scope mismatch.' }
$services=@(Read-Table 'ServiceInstall')
if ($services.Count -ne 1 -or $services[0][1] -ne 'RansomFreeAgent' -or $services[0][4] -ne '3' -or $services[0][8] -ne 'LocalSystem') { throw 'Unexpected service installation contract.' }
$files=@(Read-Table 'File')
$requiredFiles=@('RansomFree.Agent.exe','RansomFree.Tray.exe','e_sqlite3.dll')
if ($manifest.PSObject.Properties['SessionCompanion'] -and $manifest.SessionCompanion) {
    $requiredFiles+='RansomFree.DecoyHost.exe'
    if ($properties.INSTALLDECOYHOST -ne '0') { throw 'Session companion must be opt-in.' }
}
foreach ($required in $requiredFiles) {
    if (!@($files | Where-Object { $_[2].Split('|')[-1] -ceq $required }).Count) { throw "Required MSI payload missing: $required" }
}
$controls=@(Read-Table 'ServiceControl')
if ($controls.Count -ne 1 -or $controls[0][2] -ne '162') { throw 'Unexpected service stop/remove sequence.' }
$tables=@(Read-Table '_Tables')
if (@($tables | Where-Object { $_[0] -eq 'CustomAction' }).Count) { throw 'Unexpected custom actions in standard-table-only package.' }
[pscustomobject]@{PackageVersion=$manifest.PackageVersion;ProductCode=$manifest.ProductCode;Files=$files.Count;Manifest='Hashes verified';Service='LocalSystem / demand start';CustomActions='None';InstallationTest='Not performed'} | ConvertTo-Json
