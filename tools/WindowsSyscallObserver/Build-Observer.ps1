param([Parameter(Mandatory)][string]$OutputDirectory,[Parameter(Mandatory)][string]$BackendDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Immutable observer output already exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$builderHash=(Get-FileHash $PSCommandPath).Hash
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $OutputDirectory 'Build-Observer.ps1')
$module=Join-Path $OutputDirectory 'module'
& (Join-Path $PSScriptRoot 'Build-Capture.ps1') -OutputDirectory $module -BackendDirectory $BackendDirectory
$research=Join-Path $module 'research'
$dependencySources=@()
foreach($subdir in @('HyperPlatform\HyperPlatform','DdiMon','capstone')){
 foreach($file in Get-ChildItem (Join-Path $BackendDirectory $subdir) -Recurse -File|Where-Object{$_.Extension-in@('.cpp','.c','.h','.inc','.asm')-or$_.Name-like'LICENSE*'}){
  $name=[IO.Path]::GetRelativePath($BackendDirectory,$file.FullName)
  # Never put the original demonstration handlers in the compiled candidate.
  if($name-eq'DdiMon\ddi_mon.cpp'){continue}
  $target=Join-Path $research $name
  New-Item -ItemType Directory -Path (Split-Path $target) -Force|Out-Null
  Copy-Item -LiteralPath $file.FullName -Destination $target
  $dependencySources+=@{Name=$name;Sha256=(Get-FileHash $target).Hash}
 }
}
function Patch([string]$relative,[string]$old,[string]$new){
 $path=Join-Path $research $relative;$s=[IO.File]::ReadAllText($path)
 if(([regex]::Matches($s,[regex]::Escape($old))).Count-ne1){throw ('Unique frozen patch anchor changed: '+$relative)}
 [IO.File]::WriteAllText($path,$s.Replace($old,$new),[Text.UTF8Encoding]::new($false))
}
Patch 'DdiMon\shadow_hook.cpp' '#include "shadow_hook.h"' "#include `"shadow_hook.h`"`r`n#include `"Bridge.h`""
Patch 'DdiMon\shadow_hook.cpp' '  // Update guest''s IP' "  SqRootEnter(); // Account BEFORE redirect; covers preemption before guest entry.`r`n  // Update guest's IP"
Patch 'HyperPlatform\HyperPlatform\vmm.cpp' '#include "../../DdiMon/shadow_hook.h"' "#include `"../../DdiMon/shadow_hook.h`"`r`n#include `"Bridge.h`""
$rootReturn=@'
  if (guest_context->gp_regs->cx == SQ_RETURN_HYPERCALL) {
    if (VmmpGetGuestCpl() == 0 && SqRootReturn(guest_context->ip,
        guest_context->gp_regs->dx, guest_context->gp_regs->r8)) {
      guest_context->gp_regs->ax = guest_context->gp_regs->r9;
      guest_context->gp_regs->sp = guest_context->gp_regs->r8;
      UtilVmWrite(VmcsField::kGuestRsp, guest_context->gp_regs->r8);
      UtilVmWrite(VmcsField::kGuestRip, guest_context->gp_regs->dx);
      return;
    }
    VmmpIndicateUnsuccessfulVmcall(guest_context);
    return;
  }

'@
Patch 'HyperPlatform\HyperPlatform\vmm.cpp' '  switch (hypercall_number) {' ($rootReturn+'  switch (hypercall_number) {')
Patch 'HyperPlatform\HyperPlatform\vm.cpp' "  status = DdimonInitialization(shared_data->shared_sh_data);`r`n  if (!NT_SUCCESS(status)) {" "  status = DdimonInitialization(shared_data->shared_sh_data);`r`n  if (!NT_SUCCESS(status)) {`r`n    DdimonTermination(); // Disable and drain before stopping virtualization."
Patch 'HyperPlatform\HyperPlatform\driver.cpp' '#include "../../DdiMon/ddi_mon.h"' "#include `"../../DdiMon/ddi_mon.h`"`r`n#include `"Device.h`""
Patch 'HyperPlatform\HyperPlatform\driver.cpp' '  RTL_OSVERSIONINFOW os_version = {};' '  RTL_OSVERSIONINFOW os_version = {sizeof(os_version)};'
Patch 'HyperPlatform\HyperPlatform\driver.cpp' '  // Virtualize all processors' "  SqSyscallInitialize();`r`n  // Virtualize all processors"
$deviceInit=@'
  status = SqInstallDevice(driver_object);
  if (!NT_SUCCESS(status)) {
    VmTermination();
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

'@
Patch 'HyperPlatform\HyperPlatform\driver.cpp' '  // Register re-initialization for the log functions if needed' ($deviceInit+'  // Register re-initialization for the log functions if needed')
# Reject unrelocated control-flow and RIP-relative operands at runtime before
# allocating/activating a trampoline. Keep the original byte-copy design only
# for first instructions whose position independence was actually checked.
Patch 'DdiMon\shadow_hook.cpp' '  static const auto kLongestInstSize = 15;' "  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {`r`n    cs_close(&handle); KeRestoreFloatingPointState(&float_save); return 0;`r`n  }`r`n  static const auto kLongestInstSize = 15;"
$instructionCheck=@'
  bool safe = instructions[0].detail != nullptr;
  if (safe) {
    const auto& instruction = instructions[0];
    for (auto group : {CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET})
      if (cs_insn_group(handle, &instruction, static_cast<uint8_t>(group))) safe = false;
    for (uint8_t i = 0; i < instruction.detail->x86.op_count; ++i) {
      const auto& operand = instruction.detail->x86.operands[i];
      if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP) safe = false;
    }
    if (BYTE_OFFSET(address) + instruction.size > PAGE_SIZE) safe = false;
  }
  const auto size = safe ? instructions[0].size : 0;
'@
Patch 'DdiMon\shadow_hook.cpp' '  const auto size = instructions[0].size;' $instructionCheck
$vc='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.37.32822'
$wdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\wdk\c'
$sdk='D:\Codex\RansomFree\kernel-attribution-20260924\toolchain\sdk\c'
$objects=Join-Path $OutputDirectory 'objects';New-Item -ItemType Directory -Path $objects|Out-Null
$include=@(('/I'+$wdk+'\Include\10.0.26100.0\km'),('/I'+$sdk+'\Include\10.0.26100.0\shared'),('/I'+$sdk+'\Include\10.0.26100.0\ucrt'),('/I'+$vc+'\include'),('/I'+(Join-Path $module 'source\tools\WindowsSyscallObserver')),('/I'+(Join-Path $module 'source\src\seQuester.WindowsKernel')),('/I'+$research+'\capstone\include'))
$wdkPadding=Join-Path $OutputDirectory 'wdk-padding.h'
$compatibility=@'
// Intentional WDK alignment padding. No suppression on application structures.
#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)
#include <suppress.h>
// Server 2012 R2 does not export ExAllocatePool2. Retain the dependency's exact
// pool type, size and tag through this single downlevel compatibility call.
#pragma warning(push)
#pragma warning(disable:4996)
static __forceinline PVOID SqAllocateLegacy(POOL_TYPE type,SIZE_T size,ULONG tag) {
    return ExAllocatePoolWithTag(type,size,tag);
}
#pragma warning(pop)
#define ExAllocatePoolWithTag SqAllocateLegacy
'@
[IO.File]::WriteAllText($wdkPadding,$compatibility,[Text.UTF8Encoding]::new($false))
$common=@('/nologo','/c','/kernel','/GS','/Zl','/Zi','/Od','/D_AMD64_','/DAMD64','/D_WIN64','/D_WIN32_WINNT=0x0603','/DNTDDI_VERSION=0x06030000','/D_HAS_EXCEPTIONS=0','/DNDEBUG',('/FI'+$wdkPadding))+$include
$compileRows=@()
function Compile([string]$file,[switch]$Dependency){
 $stem=[IO.Path]::GetFileNameWithoutExtension($file)
 $out=Join-Path $objects ($stem+'.obj');$log=Join-Path $objects ($stem+'.compile.log')
 $extra=if($Dependency){@('/W3','/DCAPSTONE_HAS_X86','/DCAPSTONE_X86_ATT_DISABLE','/DCAPSTONE_USE_SYS_DYN_MEM')}else{@('/W4','/WX','/std:c++17','/EHs-c-')}
 & ($vc+'\bin\Hostx64\x64\cl.exe') @common @extra ('/Fo'+$out) ('/Fd'+$objects+'\'+$stem+'.pdb') $file *> $log
 if($LASTEXITCODE-ne0){Get-Content $log -Tail 35;throw ('Observer compile failed: '+$stem)}
 $script:compileRows+=@{File=$file;Object=$out;Log=$log;Dependency=[bool]$Dependency;Sha256=(Get-FileHash $out).Hash}
}
foreach($file in Get-ChildItem ($research+'\capstone\arch\X86') -File -Filter '*.c'){Compile $file.FullName -Dependency}
foreach($name in @('cs.c','MCInst.c','MCInstrDesc.c','MCRegisterInfo.c','SStream.c','utils.c','windows\winkernel_mm.c')){Compile (Join-Path ($research+'\capstone') $name) -Dependency}
foreach($file in Get-ChildItem ($research+'\HyperPlatform\HyperPlatform') -File -Filter '*.cpp'){Compile $file.FullName}
Compile ($research+'\DdiMon\shadow_hook.cpp')
& ($vc+'\bin\Hostx64\x64\ml64.exe') /nologo /c /W3 /WX ('/Fo'+$objects+'\HyperPlatformAsm.obj') ($research+'\HyperPlatform\HyperPlatform\Arch\x64\x64.asm') *> ($objects+'\HyperPlatformAsm.log')
if($LASTEXITCODE-ne0){throw 'HyperPlatform assembly failed'}
$linkObjects=@(Get-ChildItem $objects -File -Filter '*.obj'|ForEach-Object{$_.FullName})+@('Capture.obj','Device.obj','Bridge.obj','BridgeAsm.obj','NtObserver.obj','CodePin.obj'|ForEach-Object{Join-Path $module $_})
& ($vc+'\bin\Hostx64\x64\link.exe') /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /MACHINE:X64 /INTEGRITYCHECK /DEBUG /RELEASE ('/OUT:'+ $OutputDirectory+'\SqSyscallObserverLab.sys') ('/PDB:'+ $OutputDirectory+'\SqSyscallObserverLab.pdb') ('/LIBPATH:'+ $wdk+'\Lib\10.0.26100.0\km\x64') @linkObjects ntoskrnl.lib hal.lib fltMgr.lib ntstrsafe.lib wdmsec.lib BufferOverflowFastFailK.lib *> ($OutputDirectory+'\link.log')
if($LASTEXITCODE-ne0){Get-Content ($OutputDirectory+'\link.log') -Tail 35;throw 'Observer driver link failed'}
if((Get-FileHash $PSCommandPath).Hash-cne$builderHash-or(Get-FileHash (Join-Path $OutputDirectory 'Build-Observer.ps1')).Hash-cne$builderHash){throw 'Observer builder changed during build'}
$patchedHashes=@(Get-ChildItem $research -Recurse -File|Where-Object{$_.Extension-in@('.cpp','.c','.h','.inc','.asm')}|ForEach-Object{@{Name=[IO.Path]::GetRelativePath($research,$_.FullName);Sha256=(Get-FileHash $_.FullName).Hash}})
[ordered]@{Utc=[datetime]::UtcNow.ToString('o');BuilderSha256=$builderHash;DriverSha256=(Get-FileHash ($OutputDirectory+'\SqSyscallObserverLab.sys')).Hash;DependencySources=$dependencySources;PatchedSources=$patchedHashes;Compilation=$compileRows;Compiled=$true;DriverLinked=$true;RuntimeLoadAdmitted=$false;RuntimeQualified=$false;ProductionIntegrated=$false;DynamicUnloadAdmitted=$false;RemainingGates=@('assembly ABI and root return qualification','source image/prologue qualification','VMX/EPT/nested admission','device ACL fresh-session test','denied-handle/token tests','startup failure and callback rundown','overhead and queue/loss tests','authenticated central evidence integration','AMD/Hyper-V compatible backend')}|ConvertTo-Json -Depth 6|Set-Content ($OutputDirectory+'\manifest.json')
