using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client;
using RansomFree.Client.Forensics;

// Real owned processes and FILE_OBJECT matches; faults affect collection only.
static class AcquisitionFaultChecks
{
    static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
    static void P32(byte[] b,int o,uint n)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o),n);
    static void P64(byte[] b,int o,ulong n)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o),n);
    static byte[] M(uint command,int size=8){var b=new byte[size];P32(b,0,4);P32(b,4,command);return b;}
    static byte[] Send(SafeFileHandle p,byte[] q,int length)
    {var b=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(p,q,(uint)q.Length,b,(uint)length,out var n));if(n!=length)throw new IOException("Qualification reply length mismatch");return b;}
    static byte[]? Head(SafeFileHandle p)
    {
        var q=M(2);var b=new byte[3800];var hr=Native.FilterSendMessage(p,q,8,b,3800,out var n);
        if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))return null;
        Marshal.ThrowExceptionForHR(hr);if(n!=3800)throw new IOException("Operation reply size differs");return b;
    }
    static void Ack(SafeFileHandle p,byte[] raw){var b=M(4,24);raw.AsSpan(8,16).CopyTo(b.AsSpan(8));Send(p,b,0);}
    static void Drain(SafeFileHandle p){for(int i=0;i<512;i++){var raw=Head(p);if(raw==null)return;Ack(p,raw);}throw new IOException("Queue drain bound exceeded");}
    static byte[] Arm(string provider,ulong epoch,uint stage,byte[] nonce)
    {var q=M(41,64);Convert.FromHexString(provider).CopyTo(q,8);P64(q,24,epoch);nonce.CopyTo(q,32);P32(q,48,stage);P32(q,52,stage==5||stage>=7?0xC0000185u:0xC000009Au);P32(q,56,1);P32(q,60,5000);return q;}
    static object ProbeNegativePool(SafeFileHandle p,string root,string provider,ulong epoch)
    {
        var image=Environment.ProcessPath??throw new IOException("Apphost required");var executable=Path.Combine(root,"same-name-negative-objects.exe");File.Copy(image,executable);
        var handles=new List<SafeFileHandle>();var before=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);
        try
        {
            for(int i=0;i<129;i++)
            {
                Send(p,Arm(provider,epoch,7,Guid.NewGuid().ToByteArray()),0);
                var handle=CreateFileW(executable,0xA0000000,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
                if(handle.IsInvalid){var error=Marshal.GetLastWin32Error();handle.Dispose();throw new System.ComponentModel.Win32Exception(error,"Owned same-name executable open failed");}handles.Add(handle);
                var h=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);
                if(h.Live!=Math.Min(i+1,128)||h.ReferencesTaken-before.ReferencesTaken!=(ulong)Math.Min(i+1,128)||h.GapCount-before.GapCount!=(i==128?1UL:0UL))throw new IOException("Same-name separate objects or negative pool capacity accounting differs");
            }
            var full=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);
            var path=Path.Combine(root,"overflow-honeypot.txt");File.WriteAllText(path,"owned overflow actor read");OperationBindingChecks.Scope(p,path);Drain(p);
            var suffix=Guid.NewGuid().ToString("N");var rn="Local\\SqGapReady"+suffix;var gn="Local\\SqGapGo"+suffix;var fn="Local\\SqGapRelease"+suffix;
            using var ready=new EventWaitHandle(false,EventResetMode.ManualReset,rn);using var go=new EventWaitHandle(false,EventResetMode.ManualReset,gn);using var release=new EventWaitHandle(false,EventResetMode.ManualReset,fn);
            var psi=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};foreach(var arg in new[]{"--acquisition-child",path,rn,gn,fn})psi.ArgumentList.Add(arg);
            var nonce=Guid.NewGuid().ToByteArray();Send(p,Arm(provider,epoch,7,nonce),0);
            using var actor=Process.Start(psi)??throw new IOException("Overflow actor failed");var held=actor.Handle;var truth=new Child("negative-pool-overflow",actor.Id,actor.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
            try
            {
                if(!ready.WaitOne(15000))throw new TimeoutException("Overflow actor read missing");
                byte[]? raw=null;for(int i=0;i<512;i++){var e=Head(p)??throw new IOException("Overflow actor observation absent");if(U64(e,48)==(ulong)truth.ProcessId&&U64(e,40)==(ulong)truth.CreatedFileTime&&U32(e,76)==3){raw=e;break;}Ack(p,e);}
                var observed=raw??throw new IOException("Overflow operation search exceeded bound");var q=WindowsAcquisitionOutcomeProtocol.Request(provider,epoch,U64(observed,8),U64(observed,16));var bytes=Send(p,q,128);
                var outcome=WindowsAcquisitionOutcomeProtocol.Decode(bytes,provider,epoch,U64(observed,8),U64(observed,16));
                if(outcome.State!=WindowsAcquisitionState.NoExactAssociation||outcome.Flags!=0||outcome.Stage!=0||U32(observed,88)!=0)throw new IOException("Health-only negative gap became fabricated process-specific acquisition failure");
                var fault=Send(p,M(42),96);if(!fault.AsSpan(32,16).SequenceEqual(nonce)||U32(fault,60)!=1||U32(fault,56)!=0)throw new IOException("Overflow qualification fault not consumed");
                var during=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);if(during.GapCount<=full.GapCount||during.Live!=128)throw new IOException("Overflow gap not visible or pool retired before owned operation");
                File.WriteAllBytes(Path.Combine(root,"overflow.operation.bin"),observed);File.WriteAllBytes(Path.Combine(root,"overflow.outcome.bin"),bytes);Ack(p,observed);
                return new{Actor=truth,Before=before,Full=full,During=during,Outcome=outcome,SameNameDistinctLiveObjects=128,OverflowOpens=1,GapWasNotAttributedToActor=true,CallerIoStatus="0x00000000"};
            }
            finally{release.Set();go.Set();if(!actor.WaitForExit(15000)){actor.Kill();actor.WaitForExit();}Drain(p);}
        }
        finally{foreach(var handle in handles)handle.Dispose();}
    }
    static object ProbeOrdering(SafeFileHandle p,string root,string provider,ulong epoch)
    {
        var path=Path.Combine(root,"unfaulted-ordering.txt");File.WriteAllText(path,"controlled unmodified read");OperationBindingChecks.Scope(p,path);Drain(p);
        var suffix=Guid.NewGuid().ToString("N");var rn="Local\\SqOrderReady"+suffix;var gn="Local\\SqOrderGo"+suffix;var fn="Local\\SqOrderRelease"+suffix;
        using var ready=new EventWaitHandle(false,EventResetMode.ManualReset,rn);using var go=new EventWaitHandle(false,EventResetMode.ManualReset,gn);using var release=new EventWaitHandle(false,EventResetMode.ManualReset,fn);
        var image=Environment.ProcessPath??throw new IOException("Apphost required");var psi=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};foreach(var arg in new[]{"--acquisition-child",path,rn,gn,fn})psi.ArgumentList.Add(arg);
        using var actor=Process.Start(psi)??throw new IOException("Ordering actor failed");var held=actor.Handle;var truth=new Child("unfaulted-ordering",actor.Id,actor.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
        try
        {
            if(!ready.WaitOne(15000))throw new TimeoutException("Ordering actor read missing");
            byte[]? raw=null;for(int i=0;i<512;i++){var e=Head(p)??throw new IOException("Ordering read absent");if(U64(e,48)==(ulong)truth.ProcessId&&U64(e,40)==(ulong)truth.CreatedFileTime&&U32(e,76)==3){raw=e;break;}Ack(p,e);}
            var observed=raw??throw new IOException("Ordering queue search bound exceeded");
            var q=WindowsAcquisitionOutcomeProtocol.Request(provider,epoch,U64(observed,8),U64(observed,16));var bytes=Send(p,q,128);var outcome=WindowsAcquisitionOutcomeProtocol.Decode(bytes,provider,epoch,U64(observed,8),U64(observed,16));
            if(outcome.State!=WindowsAcquisitionState.BlobPinned||outcome.Flags!=0||U32(observed,88)!=0)throw new IOException("Unfaulted ordering probe lacks actual successful pinned read");
            File.WriteAllBytes(Path.Combine(root,"ordering.operation.bin"),observed);File.WriteAllBytes(Path.Combine(root,"ordering.outcome.bin"),bytes);
            var orderingKey=M(44,64);Convert.FromHexString(provider).CopyTo(orderingKey,8);P64(orderingKey,24,epoch);P64(orderingKey,32,outcome.OriginCandidate);P64(orderingKey,40,outcome.ProcessGeneration);P64(orderingKey,48,(ulong)truth.ProcessId);P64(orderingKey,56,(ulong)truth.CreatedFileTime);
            var h=Send(p,orderingKey,128);File.WriteAllBytes(Path.Combine(root,"ordering.health.bin"),h);
            if(U32(h,0)!=1||U32(h,4)!=128||!h.AsSpan(8,16).SequenceEqual(Convert.FromHexString(provider))||U64(h,24)!=epoch||U64(h,32)==0||U64(h,40)+U64(h,48)!=U64(h,32)||U64(h,56)!=outcome.OriginCandidate||U64(h,64)!=outcome.ProcessGeneration||U64(h,72)!=(ulong)truth.ProcessId||U64(h,80)!=(ulong)truth.CreatedFileTime||U64(h,88)==0||U64(h,96)<U64(h,88)||U64(h,104)==0||U64(h,120)!=0||U32(h,112) is <2 or >6||U32(h,116)>1)throw new IOException("Natural ordering sample lacks exact owned process/candidate evidence");
            var key=M(18,40);observed.AsSpan(8,16).CopyTo(key.AsSpan(8));Convert.FromHexString(provider).CopyTo(key,24);var binding=Send(p,key,88);var copy=ApcPinChecks.CopyLive(p,binding,truth,root,image);
            if(!Send(p,q,128).SequenceEqual(bytes))throw new IOException("Actor ACK changed ordering operation evidence");
            Ack(p,observed);
            return new{Actor=truth,Outcome=outcome,Copy=copy,Binds=U64(h,32),PendingBinds=U64(h,40),ReadyBinds=U64(h,48),BindPhase=U32(h,112),PostActiveAtBind=U32(h,116),BeginQpc=U64(h,88),BindQpc=U64(h,96),TerminalQpc=U64(h,104),Result=U32(h,116)==0?"SYNC_V1_BIND_DURING_POSTCREATE_NOT_OBSERVED":"NATURAL_NONTERMINAL_BIND_OBSERVED; operation-time pending/failure coverage still separate",Scope="Exact owned provider/epoch/candidate/generation/PID/start query; no delay, pause, pended I/O or synthetic process callback in post-CREATE"};
        }
        finally{release.Set();go.Set();if(!actor.WaitForExit(15000)){actor.Kill();actor.WaitForExit();}Drain(p);}
    }
    internal static void Run(string directory)
    {
        var root=Path.GetFullPath(directory);if(Directory.Exists(root))throw new IOException("Fresh qualification root required");Directory.CreateDirectory(root);
        if(WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new IOException("Controlled SYSTEM execution required");
        Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var p));
        using(p)
        {
            bool started=false;var rows=new List<object>();
            try
            {
                Send(p,M(6),0);started=true;var bindingBefore=OperationBindingChecks.Health(p);var provider=bindingBefore.Provider;
                var caps=Send(p,M(35),48);var epoch=U64(caps,24);if(WindowsAcquisitionOutcomeProtocol.Capabilities(caps,provider,epoch))throw new IOException("Unqualified capability enabled");
                var negativeBefore=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);
                var ordering=ProbeOrdering(p,root,provider,epoch);
                foreach(uint stage in new uint[]{7,8,9,1,2,3,4,6,5})
                {
                    var path=Path.Combine(root,"stage-"+stage+".txt");File.WriteAllText(path,"controlled honeypot read");OperationBindingChecks.Scope(p,path);Drain(p);
                    var nonce=Guid.NewGuid().ToByteArray();var request=M(41,64);Convert.FromHexString(provider).CopyTo(request,8);P64(request,24,epoch);nonce.CopyTo(request,32);P32(request,48,stage);var status=stage==5||stage>=7?0xC0000185u:0xC000009Au;P32(request,52,status);P32(request,56,1);P32(request,60,5000);
                    var suffix=Guid.NewGuid().ToString("N");var rn="Local\\SqFaultReady"+suffix;var gn="Local\\SqFaultGo"+suffix;var fn="Local\\SqFaultRelease"+suffix;
                    using var ready=new EventWaitHandle(false,EventResetMode.ManualReset,rn);using var go=new EventWaitHandle(false,EventResetMode.ManualReset,gn);using var release=new EventWaitHandle(false,EventResetMode.ManualReset,fn);
                    var image=Environment.ProcessPath??throw new IOException("Apphost required");var psi=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};foreach(var arg in new[]{"--acquisition-child",path,rn,gn,fn})psi.ArgumentList.Add(arg);
                    Process? actor=null;
                    try
                    {
                        Send(p,request,0);actor=Process.Start(psi)??throw new IOException("Owned actor failed");var held=actor.Handle;var truth=new Child("acquisition-fault-stage-"+stage,actor.Id,actor.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
                        if(!ready.WaitOne(15000))throw new TimeoutException("Owned actor did not complete read");
                        byte[]? found=null;for(int i=0;i<512;i++){var raw=Head(p)??throw new IOException("Controlled actor read absent");if(U64(raw,48)==(ulong)truth.ProcessId&&U64(raw,40)==(ulong)truth.CreatedFileTime&&U32(raw,76)==3){found=raw;break;}Ack(p,raw);}
                        var e=found??throw new IOException("Bounded read search exceeded");
                        var observation=WindowsKernelDecoder.Decode(e,"owned-qualification",x=>x,false);
                        if(observation.Attribution!.OsStatus!="0x00000000"||observation.Attribution.WindowsKernel!.ThreadEffective is not {Captured:31,Sid:"S-1-5-18"}||observation.Attribution.WindowsKernel.RequestorPrimary is not {Captured:31,Sid:"S-1-5-18"})throw new IOException("Collection fault changed successful caller I/O or actor security truth");
                        var q=WindowsAcquisitionOutcomeProtocol.Request(provider,epoch,U64(e,8),U64(e,16));var rawOutcome=Send(p,q,128);
                        File.WriteAllBytes(Path.Combine(root,"stage-"+stage+".operation.bin"),e);File.WriteAllBytes(Path.Combine(root,"stage-"+stage+".outcome.bin"),rawOutcome);
                        File.WriteAllText(Path.Combine(root,"stage-"+stage+".truth.json"),JsonSerializer.Serialize(truth));
                        var outcome=WindowsAcquisitionOutcomeProtocol.Decode(rawOutcome,provider,epoch,U64(e,8),U64(e,16));
                        if(outcome.State!=WindowsAcquisitionState.ExactPrebindRefusal||outcome.Stage!=(WindowsAcquisitionStage)stage||outcome.NativeStatus!=status||outcome.Flags!=8||outcome.NegativeAssociation==0||outcome.ProcessGeneration==0||outcome.OriginGeneration!=0||(stage>=7&&outcome.OriginCandidate!=0)||(stage is >=3 and <=6&&outcome.OriginCandidate==0))throw new IOException("Injected refusal lacks exact real process binding, fixed stage/status or explicit fault provenance");
                        var key=M(18,40);e.AsSpan(8,16).CopyTo(key.AsSpan(8));Convert.FromHexString(provider).CopyTo(key,24);var binding=Send(p,key,88);
                        if(U32(binding,8)!=0||U64(binding,32)!=0||U64(binding,40)!=0)throw new IOException("Negative association became an executable byte selector");
                        var fault=Send(p,M(42),96);if(U32(fault,0)!=1||U32(fault,4)!=96||!fault.AsSpan(32,16).SequenceEqual(nonce)||U32(fault,48)!=stage||U32(fault,52)!=status||U32(fault,56)!=0||U32(fault,60)!=1)throw new IOException("One-shot fault health does not match owned scenario");
                        rows.Add(new{Stage=stage,Actor=truth,Outcome=outcome,CallerIoStatus=observation.Attribution.OsStatus,FaultInjected=true,NoByteSelector=true,NoActorHashClaim=true,RawOperationSha256=Convert.ToHexString(SHA256.HashData(e)),FaultHealth=Convert.ToHexString(fault)});Ack(p,e);
                    }
                    finally
                    {
                        release.Set();go.Set();if(actor!=null){if(!actor.WaitForExit(15000)){actor.Kill();actor.WaitForExit();}if(actor.ExitCode!=0)throw new IOException("Owned actor did not finish successfully");actor.Dispose();}
                    }
                    Drain(p);
                }
                var pool=ProbeNegativePool(p,root,provider,epoch);
                OperationBindingChecks.Scope(p,null);Send(p,M(9),0);started=false;
                var after=OperationBindingChecks.Health(p);var negativeAfter=WindowsAcquisitionOutcomeProtocol.NegativeHealth(Send(p,M(37),88),provider,epoch);var faultAfter=Send(p,M(42),96);
                if(after.Live!=0||after.ReferencesTaken!=after.ReferencesReleased||after.OperationPins!=after.OperationPinsReleased||negativeAfter.Live!=0||negativeAfter.ReferencesTaken!=negativeAfter.ReferencesReleased||negativeAfter.GapCount<negativeBefore.GapCount+2||U32(faultAfter,56)!=0)throw new IOException("Fault qualification leaked references, lost expected overflow gaps or armed rule after STOP");
                File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Schema="sequester.windows-acquisition-native-fault-qualification/v1",Passed=true,Host=Environment.MachineName,Cases=rows,Ordering=ordering,NegativePool=pool,Before=bindingBefore,After=after,NegativeBefore=negativeBefore,NegativeAfter=negativeAfter,CapabilityAdvertised=false,Scope="Real owned processes and exact process-create file-object matches; collection-only injected failures explicitly flagged; caller I/O unchanged; no native state2/3 or APC callback coverage claim"},new JsonSerializerOptions{WriteIndented=true}));
            }
            finally{OperationBindingChecks.Scope(p,null);if(started)Send(p,M(9),0);}
        }
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
}
