using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client.Forensics;

internal static class OrdinaryCommandsProof
{
    internal sealed record Reply(uint Command,string Request,int Capacity,string HResult,uint? Returned,string ReturnedStatus,uint ObservedReturnedRaw);
    internal static Reply[] Verify(SafeFileHandle port,byte[] binding,string journalPath)
    {
        using var process=Process.GetCurrentProcess();var rows=new List<Reply>();
        using var journal=new FileStream(journalPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
        foreach(var (command,size) in new[]{(29u,80),(30u,80),(31u,80),(32u,128),(33u,64)})
        {
            // Structurally valid laboratory request. An ordinary staging build
            // must have no dispatch for these commands, including read queries.
            var request=WindowsStagedActorProtocol.Message(command,64);binding.AsSpan(8,16).CopyTo(request.AsSpan(8));
            WindowsStagedActorProtocol.Put(request,24,(ulong)process.Id);WindowsStagedActorProtocol.Put(request,32,(ulong)process.StartTime.ToUniversalTime().ToFileTimeUtc());
            if(command==29){WindowsStagedActorProtocol.Put32(request,48,1);WindowsStagedActorProtocol.Put32(request,52,1);}
            uint returned=0xDEC0DE01;
            var hr=FilterSendMessage(port,request,64,new byte[size],(uint)size,ref returned);
            // Microsoft defines lpBytesReturned only on SUCCESS. The original
            // negative-call zero-byte assertion read an undefined output.
            // Preserve the raw caller slot for diagnostics, never as evidence
            // that an error returned a valid reply or zero reply bytes.
            // https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtersendmessage
            var row=new Reply(command,Convert.ToHexString(request),size,"0x"+hr.ToString("X8"),hr>=0?returned:null,hr>=0?"defined-on-success":"undefined-on-failed-call",returned);
            rows.Add(row);journal.Write(JsonSerializer.SerializeToUtf8Bytes(row));journal.WriteByte((byte)'\n');journal.Flush(true);
            if(hr!=unchecked((int)0x80070057))throw new IOException($"Ordinary build laboratory command {command} returned HRESULT 0x{hr:X8}; byte-count status {row.ReturnedStatus}");
        }
        return rows.ToArray();
    }
    [DllImport("fltlib.dll")]private static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,ref uint returned);
}
