// Read-only admission evidence. Does not install hooks or prove compatibility.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>

int main() {
    int regs[4]{};
    __cpuid(regs, 0);
    unsigned maxBasic = static_cast<unsigned>(regs[0]);
    char vendor[13]{};
    memcpy(vendor, &regs[1], 4); memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    RTL_OSVERSIONINFOW os{}; os.dwOSVersionInfoSize = sizeof(os);
    auto rtlVersion = reinterpret_cast<LONG (WINAPI*)(PRTL_OSVERSIONINFOW)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    LONG versionStatus = rtlVersion ? rtlVersion(&os) : static_cast<LONG>(0xC000007AL);
    int feature[4]{};
    if (maxBasic >= 1) __cpuid(feature, 1);
    bool hypervisor = (static_cast<unsigned>(feature[2]) & 0x80000000U) != 0;
    int hv[4]{}; char hvVendor[13]{};
    if (hypervisor) {
        __cpuid(hv, 0x40000000);
        memcpy(hvVendor, &hv[1], 4); memcpy(hvVendor + 4, &hv[2], 4);
        memcpy(hvVendor + 8, &hv[3], 4);
    }
    // Known vendor strings only: no untrusted CPUID bytes interpolated into JSON.
    const char* cpu = strcmp(vendor, "GenuineIntel") == 0 ? "GenuineIntel" :
        strcmp(vendor, "AuthenticAMD") == 0 ? "AuthenticAMD" : "other";
    const char* hvName = strcmp(hvVendor, "VMwareVMware") == 0 ? "VMware" :
        strcmp(hvVendor, "Microsoft Hv") == 0 ? "Hyper-V" : hypervisor ? "other" : "none";
    int extended[4]{}; __cpuid(extended, static_cast<int>(0x80000000U));
    unsigned maxExtended = static_cast<unsigned>(extended[0]);
    int amdFeature[4]{}; int svm[4]{};
    if (maxExtended >= 0x80000001U) __cpuid(amdFeature, static_cast<int>(0x80000001U));
    bool svmExposed = (amdFeature[2] & (1 << 2)) != 0;
    if (svmExposed && maxExtended >= 0x8000000AU)
        __cpuid(svm, static_cast<int>(0x8000000AU));
    printf("{\"SchemaVersion\":1,\"ReadOnly\":true,\"RuntimeQualified\":false,"
        "\"OsStatus\":\"0x%08lX\",\"OsMajor\":%lu,\"OsMinor\":%lu,\"OsBuild\":%lu,"
        "\"CpuVendor\":\"%s\",\"MaxBasicLeaf\":%u,\"Cpuid1Ecx\":\"0x%08X\","
        "\"VmxExposed\":%s,\"HypervisorPresent\":%s,\"HypervisorVendor\":\"%s\","
        "\"SvmExposed\":%s,\"NptExposed\":%s,\"MaxExtendedLeaf\":\"0x%08X\","
        "\"EptSupported\":null,\"FeatureControlMsr\":null,\"Reason\":"
        "\"user_mode_cannot_read_vmx_capability_msrs\"}\n",
        static_cast<unsigned long>(versionStatus), os.dwMajorVersion, os.dwMinorVersion,
        os.dwBuildNumber, cpu, maxBasic, static_cast<unsigned>(feature[2]),
        (feature[2] & (1 << 5)) ? "true" : "false", hypervisor ? "true" : "false", hvName,
        svmExposed ? "true" : "false", svmExposed && maxExtended >= 0x8000000AU ?
        ((svm[3] & 1) ? "true" : "false") : "null", maxExtended);
    return versionStatus < 0 ? 1 : 0;
}
