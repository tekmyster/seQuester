using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Layouts/constants come from Windows SDK 10.0.22621 WinTrust.h/mscat.h.
// Authenticode is evidence of signing/trust policy, never a benign verdict.
public static class WindowsSignature
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct FileInfo {public uint Size;[MarshalAs(UnmanagedType.LPWStr)]public string Path;public nint Handle,Subject;}
    [StructLayout(LayoutKind.Sequential)]private struct TrustData {public uint Size;public nint Policy,Sip;public uint Ui,Revocation,Choice;public nint Info;public uint Action;public nint State,Url;public uint Flags,Context;public nint SignatureSettings;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct CatalogInfo {public uint Size;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string Path;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct CatalogTrust {public uint Size,Version;[MarshalAs(UnmanagedType.LPWStr)]public string Catalog;[MarshalAs(UnmanagedType.LPWStr)]public string Tag;[MarshalAs(UnmanagedType.LPWStr)]public string Member;public nint File,Hash;public uint HashSize;public nint Context,Admin;}
    [StructLayout(LayoutKind.Sequential)]private struct Signer {public uint Size,VerifyLow,VerifyHigh,CertCount;public nint Certs;public uint Type;public nint SignerInfo;public uint Error,CounterCount;public nint Counters,Chain;}
    [StructLayout(LayoutKind.Sequential)]private struct ProviderCertificate {public uint Size;public nint Certificate;}
    [StructLayout(LayoutKind.Sequential)]private struct CertificateContext {public uint Encoding;public nint Bytes;public uint Length;public nint Info,Store;}
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern int WinVerifyTrust(nint window,ref Guid action,ref TrustData data);
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern nint WTHelperProvDataFromStateData(nint state);
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern nint WTHelperGetProvSignerFromChain(nint data,uint signer,bool counter,uint counterIndex);
    [DllImport("wintrust.dll",ExactSpelling=true)]private static extern nint WTHelperGetProvCertFromChain(nint signer,uint index);
    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool CryptCATAdminAcquireContext2(out nint admin,nint system,string algorithm,nint policy,uint flags);
    [DllImport("wintrust.dll",SetLastError=true)]private static extern bool CryptCATAdminCalcHashFromFileHandle2(nint admin,nint file,ref uint size,byte[]? hash,uint flags);
    [DllImport("wintrust.dll",SetLastError=true)]private static extern nint CryptCATAdminEnumCatalogFromHash(nint admin,byte[] hash,uint length,uint flags,ref nint previous);
    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool CryptCATCatalogInfoFromContext(nint catalog,ref CatalogInfo info,uint flags);
    [DllImport("wintrust.dll")]private static extern bool CryptCATAdminReleaseContext(nint admin,uint flags);
    [DllImport("wintrust.dll")]private static extern bool CryptCATAdminReleaseCatalogContext(nint admin,nint catalog,uint flags);
    private static Guid Action=new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    public static SignatureEvidence Verify(FileStream file,string path)
    {
        if(!OperatingSystem.IsWindows())return new(){Status=EvidenceStatus.Unavailable("authenticode-not-applicable-on-this-platform")};
        try
        {
            var embedded=VerifyInfo(new FileInfo{Size=(uint)Marshal.SizeOf<FileInfo>(),Path=path,Handle=file.SafeFileHandle.DangerousGetHandle()},1,"embedded",null);
            if(embedded.TrustStatus!="0x800B0100")return embedded; // TRUST_E_NOSIGNATURE only; broken signatures are retained.
            SignatureEvidence? catalogFailure=null;
            foreach(var algorithm in new[]{"SHA256","SHA1"})
            {
                if(!CryptCATAdminAcquireContext2(out var admin,0,algorithm,0,0))throw new Win32Exception();
                try
                {
                    uint size=0;file.Position=0;
                    if(!CryptCATAdminCalcHashFromFileHandle2(admin,file.SafeFileHandle.DangerousGetHandle(),ref size,null,0)||size is 0 or >128)throw new Win32Exception();
                    var hash=new byte[size];file.Position=0;
                    if(!CryptCATAdminCalcHashFromFileHandle2(admin,file.SafeFileHandle.DangerousGetHandle(),ref size,hash,0))throw new Win32Exception();
                    nint previous=0;var catalog=CryptCATAdminEnumCatalogFromHash(admin,hash,size,0,ref previous);
                    // Enumerate all matches: trust is not determined by the first catalog's presence.
                    for(var count=0;catalog!=0&&count<32;count++)
                    {
                        var advance=false;
                        try
                        {
                            var info=new CatalogInfo{Size=(uint)Marshal.SizeOf<CatalogInfo>(),Path=""};
                            if(!CryptCATCatalogInfoFromContext(catalog,ref info,0))throw new Win32Exception();
                            var memory=Marshal.AllocHGlobal((int)size);
                            try
                            {
                                Marshal.Copy(hash,0,memory,(int)size);
                                var verified=VerifyInfo(new CatalogTrust{Size=(uint)Marshal.SizeOf<CatalogTrust>(),Catalog=info.Path,Tag=Convert.ToHexString(hash),Member=path,File=file.SafeFileHandle.DangerousGetHandle(),Hash=memory,HashSize=size,Admin=admin},2,"catalog",info.Path);
                                if(verified.Valid==true)return verified;
                                catalogFailure=verified;advance=true;
                            }
                            finally{Marshal.FreeHGlobal(memory);}
                        }
                        finally
                        {
                            // Enum releases the previous context when advancing; do not release twice.
                            if(advance){previous=catalog;catalog=CryptCATAdminEnumCatalogFromHash(admin,hash,size,0,ref previous);}
                            else{CryptCATAdminReleaseCatalogContext(admin,catalog,0);catalog=0;}
                        }
                    }
                    if(catalog!=0)CryptCATAdminReleaseCatalogContext(admin,catalog,0);
                }
                finally{CryptCATAdminReleaseContext(admin,0);}
            }
            return catalogFailure??embedded with{Kind="none",Present=false,Valid=false,Status=EvidenceStatus.Captured("no-embedded-or-installed-catalog-signature")};
        }
        catch(Exception ex)when(ex is Win32Exception or EntryPointNotFoundException or System.Security.Cryptography.CryptographicException)
        {return new(){Status=new("unavailable","windows-signature-verification-failed",ex is Win32Exception w?w.NativeErrorCode.ToString():ex.GetType().Name)};}
    }
    private static SignatureEvidence VerifyInfo<T>(T info,uint choice,string kind,string? catalog)where T:struct
    {
        var memory=Marshal.AllocHGlobal(Marshal.SizeOf<T>());Marshal.StructureToPtr(info,memory,false);
        var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),Ui=2,Choice=choice,Info=memory,Action=1,Flags=0x1000|0x80|0x2000};
        try
        {
            var code=WinVerifyTrust(-1,ref Action,ref data);
            var result=new SignatureEvidence{Kind=kind,Present=code==unchecked((int)0x800B0100)?false:null,Valid=code==0,TrustStatus=$"0x{unchecked((uint)code):X8}",CatalogPath=catalog,Status=EvidenceStatus.Captured("WinVerifyTrust-cache-only-revocation; not-a-safety-verdict")};
            var provider=WTHelperProvDataFromStateData(data.State);var pointer=provider!=0?WTHelperGetProvSignerFromChain(provider,0,false,0):0;
            if(pointer==0)return result;
            var signer=Marshal.PtrToStructure<Signer>(pointer);
            result=result with{Present=true,ChainStatus=$"0x{signer.Error:X8}",TimestampPresent=signer.CounterCount>0,TimestampStatus=signer.CounterCount==0?"no-countersigner-reported":null};
            if(signer.CounterCount>0)
            {
                var timestamp=WTHelperGetProvSignerFromChain(provider,0,true,0);
                if(timestamp!=0){var counter=Marshal.PtrToStructure<Signer>(timestamp);result=result with{TimestampValid=counter.Error==0,TimestampStatus=$"0x{counter.Error:X8}"};}
            }
            var certificate=WTHelperGetProvCertFromChain(pointer,0);
            if(certificate==0)return result;
            var context=Marshal.PtrToStructure<CertificateContext>(Marshal.PtrToStructure<ProviderCertificate>(certificate).Certificate);
            if(context.Length is 0 or >1048576)return result;
            var bytes=new byte[context.Length];Marshal.Copy(context.Bytes,bytes,0,bytes.Length);
            using var cert=X509CertificateLoader.LoadCertificate(bytes);
            return result with{Signer=Limit(cert.Subject),Publisher=Limit(cert.GetNameInfo(X509NameType.SimpleName,false)),Issuer=Limit(cert.Issuer),Thumbprint=cert.Thumbprint,NotBeforeUtc=cert.NotBefore.ToUniversalTime(),NotAfterUtc=cert.NotAfter.ToUniversalTime()};
        }
        finally
        {
            data.Action=2;WinVerifyTrust(-1,ref Action,ref data);Marshal.DestroyStructure<T>(memory);Marshal.FreeHGlobal(memory);
        }
    }
    private static string Limit(string value)=>value.Length<=512?value:value[..512];
}
