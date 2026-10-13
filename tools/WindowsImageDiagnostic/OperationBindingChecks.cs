using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

record BoundActorCopy(Child Child,string Operation,ulong Generation,ulong Candidate,string Provider,string Path,string ExpectedSha256,string PreservedSha256,uint Bytes,int RejectedKeys,int LinkedOperations);
record BindingCheck(bool Passed,BoundActorCopy[] Copies,int UnavailableParentOperations,int RejectedCompanionKeys,int RawOperations);
record BindingHealth(string Provider,uint ProviderStatus,uint Capacity,ulong Generations,ulong ReferencesTaken,ulong ReferencesReleased,ulong CapacityMisses,uint Live,uint Stopped,ulong OperationPins,ulong OperationPinsReleased);
static class OperationBindingChecks
{
 static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
 static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
 static void Put(byte[] b,int o,ulong value)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o),value);
 static void Put32(byte[] b,int o,uint value)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o),value);
 static byte[] Message(uint command,int size=8){var b=new byte[size];Put32(b,0,4);Put32(b,4,command);return b;}
 static byte[] Send(SafeFileHandle port,byte[] input,int length){var b=length==0?null:new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,(uint)input.Length,b,(uint)length,out var n));if(n!=length)throw new IOException("Binding reply length mismatch");return b??[];}
 static int Rejected(SafeFileHandle port,byte[] input,int length){var b=length==0?null:new byte[length];var hr=Native.FilterSendMessage(port,input,(uint)input.Length,b,(uint)length,out _);if(hr!=unchecked((int)0x80070490))throw new IOException($"Mismatched binding key was not rejected: {hr:X8}");return 1;}
 internal static BindingHealth Health(SafeFileHandle port){var b=Send(port,Message(20),88);if(U32(b,0)!=1||U32(b,4)!=88)throw new IOException("Binding health schema mismatch");return new(Convert.ToHexString(b.AsSpan(8,16)),U32(b,24),U32(b,28),U64(b,32),U64(b,40),U64(b,48),U64(b,56),U32(b,64),U32(b,68),U64(b,72),U64(b,80));}
 internal static int Child(string[] args){switch(args[1]){case "read":File.ReadAllBytes(args[2]);break;case "write":File.AppendAllText(args[2],"controlled fixture write");break;case "rename":File.Move(args[2],args[2]+".renamed");break;default:return 4;}return 0;}
 internal static void Scope(SafeFileHandle port,string? path)
 {
  var b=Message(5,path==null?12:1548);Put32(b,8,path==null?0u:1u);
  if(path!=null){var full=Path.GetFullPath(path);var device=new StringBuilder(32768);if(QueryDosDevice(full[..2],device,device.Capacity)==0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());var native=device+full[2..];if(native.Length>=767)throw new IOException("Fixture path too long");Encoding.Unicode.GetBytes(native).CopyTo(b,12);}
  Send(port,b,0);
 }
 static byte[] Request(byte[] binding,uint operation,uint offset=0,uint length=0)
 {
  var b=Message(19,72);binding.AsSpan(16,16).CopyTo(b.AsSpan(8));
  Put(b,24,U64(binding,32));Put(b,32,U64(binding,40));Put(b,40,U64(binding,48));Put(b,48,U64(binding,56));
  Put32(b,56,offset);Put32(b,60,length);Put32(b,64,operation);Put32(b,68,1);return b;
 }
 static string Sid(byte[] e,int token)
 {
  uint n=U32(e,token+24);if(n is <8 or >68||e[token+72]!=1||n!=8+4*e[token+73])throw new IOException("Invalid operation SID");
  ulong authority=0;for(int i=2;i<8;i++)authority=(authority<<8)|e[token+72+i];var s="S-1-"+authority;for(int i=0;i<e[token+73];i++)s+="-"+U32(e,token+80+4*i);return s;
 }
 internal static BindingCheck Run(SafeFileHandle port,string root,Action drain)
 {
  var image=Environment.ProcessPath??throw new IOException("No fixture apphost");var expected=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(image)));
  var copies=new List<BoundActorCopy>();int unavailable=0,rejectedCompanions=0,total=0;var provider=Convert.FromHexString(Health(port).Provider);
  using var events=new FileStream(Path.Combine(root,"bound-operations.bin"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
  using var bindings=new FileStream(Path.Combine(root,"bound-companions.bin"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
  foreach(var operation in new[]{"read","write","rename"})
  {
   var path=Path.Combine(root,"binding-honeypot-"+operation+".txt");File.WriteAllText(path,"controlled binding fixture");
   Scope(port,path);
   try{
    File.ReadAllBytes(path); // Reader existed before collection; its absent generation must stay explicit.
    var psi=new ProcessStartInfo(image){UseShellExecute=false,CreateNoWindow=true};psi.ArgumentList.Add("--touch-child");psi.ArgumentList.Add(operation);psi.ArgumentList.Add(path);
    using var child=Process.Start(psi)??throw new IOException("Binding actor did not start");var owned=child.Handle;
    var c=new Child("operation-binding-"+operation,child.Id,child.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
    if(!child.WaitForExit(15000)||child.ExitCode!=0)throw new IOException("Binding actor failed");
    Scope(port,null);drain();byte[]? actorBinding=null;int linked=0;bool actionSeen=false;
    for(int i=0;i<512;i++){
     var e=new byte[3800];var input=Message(2);var hr=Native.FilterSendMessage(port,input,8,e,3800,out var n);
     if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;
     Marshal.ThrowExceptionForHR(hr);if(n!=3800||U32(e,0)!=4||U32(e,4)!=3800)throw new IOException("Unexpected operation schema");
     var key=Message(18,40);e.AsSpan(8,16).CopyTo(key.AsSpan(8));provider.CopyTo(key,24);var wrong=(byte[])key.Clone();Put(wrong,16,U64(wrong,16)^0x8000000000000000);rejectedCompanions+=Rejected(port,wrong,88);
     wrong=(byte[])key.Clone();wrong[24]^=0x80;rejectedCompanions+=Rejected(port,wrong,88);
     var b=Send(port,key,88);if(U32(b,0) is not (1 or 2)||U32(b,4)!=88||U64(b,72)!=U64(e,8)||U64(b,80)!=U64(e,16))throw new IOException("Companion operation link differs");
     events.Write(e);bindings.Write(b);total++;
     if(U64(e,48)==(ulong)c.ProcessId&&U64(e,40)==(ulong)c.CreatedFileTime){
      if(U32(b,8)!=1||U32(b,12)!=0||U64(b,32)==0||U64(b,40)==0||U64(b,48)!=(ulong)c.ProcessId||U64(b,56)!=(ulong)c.CreatedFileTime)throw new IOException("Exited actor lacks exact operation binding");
      if(actorBinding!=null&&!actorBinding.AsSpan(16,48).SequenceEqual(b.AsSpan(16,48)))throw new IOException("One actor changed generation");actorBinding=b;linked++;
      // Controlled guest task is SYSTEM without impersonation. The separate
      // twenty-case kernel fixture establishes impersonation/denial behavior.
      if(U32(e,3464)!=31||U32(e,3608)!=31||Sid(e,3464)!="S-1-5-18"||Sid(e,3608)!="S-1-5-18"||U64(e,56)==0)throw new IOException("Operation-time identity differs from controlled SYSTEM actor");
      actionSeen|=operation switch{"read"=>U32(e,76)==3,"write"=>U32(e,76)==4,"rename"=>U32(e,76)==6&&U32(e,84) is 10 or 65,_=>false};
     }else if(U64(e,48)==(ulong)Environment.ProcessId){
      if(U32(b,8)!=0||U64(b,32)!=0||U64(b,40)!=0||U32(b,12)!=0xC0000225)throw new IOException("Missing parent generation was fabricated");unavailable++;
     }
     var ack=Message(4,24);e.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(port,ack,0);rejectedCompanions+=Rejected(port,key,88);drain();
    }
    if(actorBinding==null||linked==0||!actionSeen)throw new IOException("Required honeypot operation missing");
    int rejected=0;
    foreach(int offset in new[]{8,24,32,40,48}){var bad=Request(actorBinding,13);bad[offset]^=0x80;rejected+=Rejected(port,bad,144);}
    var metadata=Send(port,Request(actorBinding,13),144);var length=U32(metadata,8);
    void CheckReply(byte[] b,uint offset,uint count){if(U32(b,0)!=3||U32(b,4)!=144||U32(b,8)!=length||U32(b,12)!=offset||U32(b,16)!=count||U64(b,32)!=U64(actorBinding,40)||U64(b,40)!=(ulong)c.ProcessId||U64(b,48)!=(ulong)c.CreatedFileTime||!b.AsSpan(120,16).SequenceEqual(actorBinding.AsSpan(16,16))||U64(b,136)!=U64(actorBinding,32))throw new IOException("Full-key byte reply differs");}
    CheckReply(metadata,0,0);if(length==0||length>8*1024*1024||(U32(metadata,20)&15)!=15)throw new IOException("Incomplete exited-actor metadata");
    var file=Path.Combine(root,"bound-actor-"+U64(actorBinding,32)+".bin");
    using(var output=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None)){for(uint offset=0;offset<length;){uint count=Math.Min(65536,length-offset);var b=Send(port,Request(actorBinding,10,offset,count),checked((int)(144+count)));CheckReply(b,offset,count);output.Write(b,144,(int)count);offset+=count;}output.Flush(true);}
    var hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));if(hash!=expected)throw new IOException("Bound actor bytes differ");Send(port,Request(actorBinding,11),0);
    copies.Add(new(c,operation,U64(actorBinding,32),U64(actorBinding,40),Convert.ToHexString(actorBinding.AsSpan(16,16)),file,expected,hash,length,rejected,linked));drain();
   }finally{Scope(port,null);}
  }
  events.Flush(true);bindings.Flush(true);
  var result=new BindingCheck(copies.Count==3&&copies.Select(c=>c.Generation).Distinct().Count()==3&&unavailable>=3,copies.ToArray(),unavailable,rejectedCompanions,total);
  File.WriteAllText(Path.Combine(root,"binding-result.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));return result;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint QueryDosDevice(string device,StringBuilder output,int length);
}
