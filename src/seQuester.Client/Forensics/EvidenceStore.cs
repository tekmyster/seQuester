using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

public sealed class EvidenceStore(string directory)
{
    private readonly object gate=new();
    public PreservationEvidence Preserve(ActorLease actor,AgentEvent value,string? expectedHash,ForensicPolicy policy)
    {
        var result=new PreservationEvidence{SourceEventId=value.EventId,ProcessInstanceId=actor.Process.InstanceId,OriginalPath=value.Process};
        if(actor.Image==null||expectedHash==null)return result with{Status=EvidenceStatus.Unavailable("actor-image-or-verified-hash-unavailable")};
        lock(gate)
        {
            try
            {
                var root=Path.GetFullPath(Path.Combine(directory,"evidence","actors"));
                EnsurePrivate(root);
                var size=actor.DescriptorFile.Size??throw new IOException("Image size unavailable.");
                var total=Directory.EnumerateFiles(root,"*",SearchOption.TopDirectoryOnly).Sum(p=>new FileInfo(p).Length);
                if(size<0||size>(long)policy.MaximumActorMiB*1024*1024)return result with{Status=new("failed","actor-exceeds-preservation-size-limit")};
                if(total+size+65536>(long)policy.EvidenceStoreMiB*1024*1024)return result with{Status=new("failed","evidence-store-quota-exceeded")};
                if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(actor.Image)))return result with{Status=new("failed","actor-changed-before-preservation")};
                var id=Guid.NewGuid().ToString("N");var artifact=id+".bin";var manifest=id+".json";
                result=result with{EvidenceId=id,ArtifactRelativePath="evidence/actors/"+artifact,ManifestRelativePath="evidence/actors/"+manifest,PreservedUtc=DateTimeOffset.UtcNow};
                var destination=Path.Combine(root,artifact);
                using(var output=CreatePrivate(destination))
                {
                    actor.Image.Position=0;var remaining=size;var buffer=new byte[65536];
                    while(remaining>0){var n=actor.Image.Read(buffer,0,(int)Math.Min(buffer.Length,remaining));if(n==0)throw new IOException("Actor image shortened while copying.");output.Write(buffer,0,n);remaining-=n;}
                    if(actor.Image.ReadByte()!=-1)throw new IOException("Actor image grew while copying.");output.Flush(true);
                }
                using(var preserved=File.OpenRead(destination))
                {
                    var copied=Convert.ToHexString(SHA256.HashData(preserved));var matches=expectedHash.Equals(copied,StringComparison.OrdinalIgnoreCase);
                    var unchanged=NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(actor.Image));
                    result=result with{Sha256=copied,Size=preserved.Length,HashMatched=matches,Status=matches&&unchanged?EvidenceStatus.Captured("actor-copy-hash-verified"):new("failed",matches?"actor-changed-during-preservation":"preserved-hash-mismatch")};
                }
                var manifestData=new Dictionary<string,object?>{{"SchemaVersion",1},{"Preservation",result},{"ActorFile",actor.File},{"Process",actor.Process},{"EventObservedUtc",value.ObservedUtc},{"ExpectedSha256",expectedHash}};
                if(actor.Acquisition!=null)manifestData.Add("ActorAcquisition",actor.Acquisition);
                if(actor.LinuxAcquisition!=null)manifestData.Add("LinuxActorAcquisition",actor.LinuxAcquisition);
                if(actor.LinuxNativeWork!=null)manifestData.Add("LinuxNativeWork",actor.LinuxNativeWork);
                var bytes=JsonSerializer.SerializeToUtf8Bytes(manifestData);
                using(var metadata=CreatePrivate(Path.Combine(root,manifest))){metadata.Write(bytes);metadata.Flush(true);}
                EvidenceDurability.DirectoryCommitted(root);
                return result with{ManifestSha256=Convert.ToHexString(SHA256.HashData(bytes))};
            }
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.SecurityException)
            {return result with{Status=new("failed","actor-preservation-failed",ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name)};}
        }
    }
    private static FileStream CreatePrivate(string path)
    {
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        return new FileStream(path,options);
    }
    internal static void EnsurePrivate(string root)
    {
        // Parent is already a service-owned private state directory. Refuse all link/junction ancestors.
        for(string? p=root;p!=null;p=Path.GetDirectoryName(p))
            if((Directory.Exists(p)||File.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Evidence path contains a link.");
        if(OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(root);
            var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[]{new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),WindowsIdentity.GetCurrent().User!}.Distinct())
                acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            var info=new DirectoryInfo(root);var existing=info.GetAccessControl(AccessControlSections.Access);
            static string Rules(DirectorySecurity security)
            {
                if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
                var values=new List<string>();
                foreach(FileSystemAccessRule r in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                    values.Add($"{r.IdentityReference.Value}:{r.AccessControlType}:{(int)r.FileSystemRights}:{(int)r.InheritanceFlags}:{(int)r.PropagationFlags}:{r.IsInherited}");
                values.Sort(StringComparer.Ordinal);return string.Join(";",values);
            }
            // Reapplying an identical inheritable DACL can change children's NTFS
            // change times. Recovery must not mutate its own immutable snapshots.
            if(!existing.AreAccessRulesProtected||!existing.AreAccessRulesCanonical||Rules(existing)!=Rules(acl))info.SetAccessControl(acl);
        }
        else
        {
            var missing=new List<string>();
            for(string? p=root;p!=null&&!Directory.Exists(p);p=Path.GetDirectoryName(p))missing.Add(p);
            Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            foreach(var p in missing)EvidenceDurability.DirectoryCommitted(Path.GetDirectoryName(p)!);
            File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        }
    }
}
