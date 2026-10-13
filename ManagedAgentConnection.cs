using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree;

internal static class ManagedAgentConnection
{
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder name,ref int size);
    [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    public static async Task<AgentConsoleReply> SendAsync(AgentConsoleRequest request,CancellationToken ct=default,bool readOnly=false)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(12));
        if(readOnly&&request is not {Operation:"status",Password:null,EventId:null})throw new InvalidOperationException("Read-only tray cannot send administration requests.");
        using var pipe=new NamedPipeClientStream(".",readOnly?"RansomFree.Agent.ReadOnly.v1":"RansomFree.Agent.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(2500,timeout.Token);
        if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out var pid))throw new IOException("Cannot verify the local agent service.");
        using var process=OpenProcess(0x1000,false,pid);if(process.IsInvalid)throw new IOException("Cannot verify the local agent process.");
        var name=new StringBuilder(32768);var capacity=name.Capacity;
        var expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"RansomFree","Agent","RansomFree.Agent.exe");
        if(!QueryFullProcessImageName(process,0,name,ref capacity) || !name.ToString().Equals(expected,StringComparison.OrdinalIgnoreCase))throw new IOException("Agent is not running from the approved installation path.");
        InstalledAgentIdentity.Verify(pid,expected);
        if(!readOnly)
        {
            if(!OpenProcessToken(process,8,out var token))throw new IOException("Cannot verify the agent service account.");
            using(token)using(var identity=new WindowsIdentity(token.DangerousGetHandle()))if(!identity.IsSystem)throw new IOException("Agent must run as the installed LocalSystem service.");
        }
        // No request or password is sent until both the server process and service identity are checked.
        var bytes=JsonSerializer.SerializeToUtf8Bytes(request);if(bytes.Length>4096)throw new ArgumentException("Agent request exceeds its limit.");
        var size=new byte[4];BinaryPrimitives.WriteInt32LittleEndian(size,bytes.Length);
        try{await pipe.WriteAsync(size,timeout.Token);await pipe.WriteAsync(bytes,timeout.Token);await pipe.FlushAsync(timeout.Token);}finally{Array.Clear(bytes);}
        await pipe.ReadExactlyAsync(size,timeout.Token);var length=BinaryPrimitives.ReadInt32LittleEndian(size);if(length is <2 or >1048576)throw new InvalidDataException("Agent reply exceeds its limit.");
        var response=new byte[length];await pipe.ReadExactlyAsync(response,timeout.Token);
        return JsonSerializer.Deserialize<AgentConsoleReply>(response)??throw new InvalidDataException("Invalid agent reply.");
    }
}
