[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ExpectedHost,
    [Parameter(Mandatory)][string]$Driver,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedDriverSha256,
    [Parameter(Mandatory)][string]$Qualification,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$QualificationSha256,
    [Parameter(Mandatory)][string]$Receipt,
    [ValidatePattern('^[0-9]{6}(\.[0-9]+)?$')][string]$LoadOrderNumber='385200.923',
    [switch]$InspectOnly
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME-cne$ExpectedHost){throw 'Host identity mismatch'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.OSArchitecture-ne'64-bit'-or$os.Version-notin@('6.3.9600','10.0.17763','10.0.19045')){throw 'Windows build is outside the qualified deployment scope'}
if([decimal]$LoadOrderNumber-lt360000-or[decimal]$LoadOrderNumber-ge390000){throw 'Load-order number is outside FSFilter Activity Monitor'}
if((Get-FileHash -LiteralPath $Driver).Hash-ine$ExpectedDriverSha256){throw 'Driver hash mismatch'}
if((Get-FileHash -LiteralPath $Qualification).Hash-ine$QualificationSha256){throw 'Qualification hash mismatch'}
$proof=Get-Content -LiteralPath $Qualification -Raw|ConvertFrom-Json
if(!$proof.Passed-or$proof.DriverSha256-ine$ExpectedDriverSha256-or$proof.OSVersion-cne$os.Version-or$proof.Protocol-ne4){throw 'Driver bytes, protocol or OS do not match native qualification'}
if($proof.EvidenceVersion-ne5-or!$proof.ThreadOwnerVerified){throw 'Qualification must verify extended thread-owner evidence'}
if(!$proof.TransportReconnectVerified){throw 'Qualification must verify health disconnect and pending-operation reconnect'}
$ubr=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
if($proof.UpdateBuildRevision-ne$ubr){throw 'Windows update revision differs from native qualification'}
if(Test-Path -LiteralPath $Receipt){throw 'Receipt exists; no evidence overwrite permitted'}
$agent=Get-CimInstance Win32_Service -Filter "Name='RansomFreeAgent'"
if(!$agent-or$agent.State-ne'Running'-or$agent.StartName-notin@('LocalSystem','NT AUTHORITY\SYSTEM')){throw 'Running SYSTEM sensor required'}
$agentImage=$agent.PathName.Trim('"')
if((Get-Item -LiteralPath $agentImage).VersionInfo.FileVersion-cne'0.6.15.0'){throw 'Extended thread evidence requires the qualified 0.6.15 sensor'}
$key='HKLM:\SYSTEM\CurrentControlSet\Services\SeQuesterActor'
$marker='C:\ProgramData\RansomFree\Agent\windows-kernel.enabled'
$stagingMarker='C:\ProgramData\RansomFree\Agent\windows-kernel-staging.enabled'
if((Test-Path $key)-or(Test-Path $marker)-or(Test-Path $stagingMarker)){throw 'Existing driver or activation marker requires reconciliation; refusing replacement'}
$filters=@(& fltmc.exe filters 2>&1|ForEach-Object{[string]$_})
if($LASTEXITCODE-ne0){throw 'Filter Manager inventory failed'}
if(@($filters|Where-Object{$_-match('(?<![0-9.])'+[regex]::Escape($LoadOrderNumber)+'(?![0-9.])')}).Count){throw 'Load-order number collision'}
$boot=[string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SystemStartOptions
$result=[ordered]@{Schema='sequester.windows-minifilter-install/v1';Host=$ExpectedHost;OSVersion=$os.Version;DriverSha256=$ExpectedDriverSha256;Protocol=4;LoadOrderNumber=$LoadOrderNumber;PermanentNumberAssigned=$false;BootOptionsBefore=$boot;StartedUtc=[datetime]::UtcNow.ToString('o');Decision='PENDING';DriverLoaded=$false;SensorEnabled=$false;NativeLoadError=$null;Rollback='not-required'}
if($InspectOnly){$result.Decision='INSPECTED';$result|ConvertTo-Json -Depth 6;return}
$directory=Join-Path 'C:\Program Files\RansomFree\Kernel' ($ExpectedDriverSha256.ToUpperInvariant())
$image=Join-Path $directory 'SeQuesterActor.sys'
$created=$false;$enabled=$false;$dependencyChanged=$false
$oldDependencies=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RansomFreeAgent').DependOnService)
try{
    if(Test-Path $directory){throw 'Immutable driver release already exists'}
    New-Item -ItemType Directory -Path $directory -Force|Out-Null
    & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'|Out-Null
    if($LASTEXITCODE-ne0){throw 'Driver release ACL failed'}
    Copy-Item -LiteralPath $Driver -Destination $image
    Copy-Item -LiteralPath $Qualification -Destination (Join-Path $directory 'qualification.json')
    if((Get-FileHash $image).Hash-ine$ExpectedDriverSha256){throw 'Installed driver hash differs'}
    & sc.exe create SeQuesterActor type= filesys start= demand error= normal binPath= $image group= 'FSFilter Activity Monitor' depend= FltMgr|Out-Null
    if($LASTEXITCODE-ne0){throw 'Driver service creation failed'}
    $created=$true
    New-Item -Path ($key+'\Instances\seQuester Actor Instance') -Force|Out-Null
    New-ItemProperty -Path ($key+'\Instances') -Name DefaultInstance -Value 'seQuester Actor Instance' -PropertyType String -Force|Out-Null
    New-ItemProperty -Path ($key+'\Instances\seQuester Actor Instance') -Name Altitude -Value $LoadOrderNumber -PropertyType String -Force|Out-Null
    New-ItemProperty -Path ($key+'\Instances\seQuester Actor Instance') -Name Flags -Value 0 -PropertyType DWord -Force|Out-Null
    & sc.exe start SeQuesterActor|Out-Null
    $result.NativeLoadError=$LASTEXITCODE
    if($LASTEXITCODE-ne0){throw ('Windows rejected driver load; native service error '+$result.NativeLoadError)}
    if((Get-Service SeQuesterActor).Status-ne'Running'){throw 'Driver did not reach Running'}
    $result.DriverLoaded=$true
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SqInstallPort {
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)] public static extern int FilterConnectCommunicationPort(string name,uint options,IntPtr context,ushort size,IntPtr security,out SafeFileHandle port);
 [DllImport("fltlib.dll")] public static extern int FilterSendMessage(SafeFileHandle port,byte[] request,uint requestLength,byte[] output,uint outputLength,out uint returned);
}
'@
    $port=$null
    try{
        $hr=[SqInstallPort]::FilterConnectCommunicationPort('\SeQuesterActorPrototype',0,[IntPtr]::Zero,0,[IntPtr]::Zero,[ref]$port)
        [Runtime.InteropServices.Marshal]::ThrowExceptionForHR($hr)
        $request=[byte[]](4,0,0,0,3,0,0,0);$output=New-Object byte[] 48;$returned=[uint32]0
        $hr=[SqInstallPort]::FilterSendMessage($port,$request,8,$output,48,[ref]$returned)
        [Runtime.InteropServices.Marshal]::ThrowExceptionForHR($hr)
        if($returned-ne48-or[BitConverter]::ToUInt32($output,0)-ne4){throw 'Driver health protocol mismatch'}
        $result.ProviderInstance=[BitConverter]::ToUInt64($output,8).ToString('X16')
    }finally{if($port){$port.Dispose()}}
    $dependencies=@($oldDependencies|Where-Object{$_})+@('SeQuesterActor')
    & sc.exe config RansomFreeAgent depend= ($dependencies-join'/')|Out-Null
    if($LASTEXITCODE-ne0){throw 'Sensor dependency configuration failed'}
    $dependencyChanged=$true
    # Native qualification uses early executable acquisition; retain that mode on endpoints.
    [IO.File]::WriteAllText($stagingMarker,($ExpectedDriverSha256.ToUpperInvariant()+"`r`n"))
    $enabled=$true
    [IO.File]::WriteAllText($marker,($ExpectedDriverSha256.ToUpperInvariant()+"`r`n"))
    Restart-Service RansomFreeAgent -ErrorAction Stop
    (Get-Service RansomFreeAgent).WaitForStatus('Running',[timespan]::FromSeconds(30))
    if((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SystemStartOptions-cne$boot){throw 'Boot security options unexpectedly changed'}
    $result.SensorEnabled=$true;$result.Decision='INSTALLED-AWAITING-LIVE-EVENT-ACCEPTANCE'
}catch{
    $result.Decision='FAILED';$result.Error=$_.Exception.Message
    try{
        if($enabled){foreach($ownedMarker in $marker,$stagingMarker){if(Test-Path -LiteralPath $ownedMarker){Remove-Item -LiteralPath $ownedMarker}};Stop-Service RansomFreeAgent -ErrorAction Stop}
        if($dependencyChanged){& sc.exe config RansomFreeAgent depend= $(if($oldDependencies.Count){$oldDependencies-join'/'}else{'/'} )|Out-Null;if($LASTEXITCODE-ne0){throw 'Dependency rollback failed'}}
        if($created){if((Get-Service SeQuesterActor).Status-eq'Running'){Stop-Service SeQuesterActor -ErrorAction Stop};& sc.exe delete SeQuesterActor|Out-Null;if($LASTEXITCODE-ne0){throw 'Driver service rollback failed'}}
        if((Get-Service RansomFreeAgent).Status-ne'Running'){Start-Service RansomFreeAgent -ErrorAction Stop}
        $result.Rollback='sensor-restored; immutable driver release retained'
    }catch{$result.Rollback='FAILED: '+$_.Exception.Message}
}finally{
    $result.CompletedUtc=[datetime]::UtcNow.ToString('o')
    $result|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $Receipt -Encoding UTF8
}
$result|ConvertTo-Json -Depth 6
if($result.Decision-eq'FAILED'){throw ($result.Error+'; receipt '+$Receipt)}
