using System.Buffers.Binary;

static class TableCodecChecks
{
    internal static void Run()
    {
        var passed=0;
        void Check(bool condition,string name){if(!condition)throw new IOException(name);passed++;}
        void Reject(Action action,string name){try{action();}catch(IOException){passed++;return;}throw new IOException(name);}
        static byte[] Frame(uint slots,uint version)
        {
            var bytes=new byte[8+64*slots];
            BinaryPrimitives.WriteUInt32LittleEndian(bytes,version);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4),(uint)bytes.Length);
            var last=8+64*((int)slots-1);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(last),99);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(last+8),42);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(last+32),1);
            return bytes;
        }
        foreach(var slots in new[]{64u,128u})
        {
            var frame=Frame(slots,slots==64?2u:3u);
            var decoded=Staging.DecodeTable(frame,slots);
            Check(decoded.Length==1&&decoded[0].Id==99&&decoded[0].Pid==42&&decoded[0].Ready==1,"Last metadata slot must be retained");
            Reject(()=>Staging.DecodeTable(frame[..^1],slots),"Truncated table accepted");
            Reject(()=>Staging.DecodeTable([..frame,0],slots),"Oversized table accepted");
            var changed=(byte[])frame.Clone();BinaryPrimitives.WriteUInt32LittleEndian(changed,99);
            Reject(()=>Staging.DecodeTable(changed,slots),"Unknown table schema accepted");
            changed=(byte[])frame.Clone();BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(4),0);
            Reject(()=>Staging.DecodeTable(changed,slots),"Inconsistent declared size accepted");
        }
        Reject(()=>Staging.DecodeTable(Frame(64,2),128),"Legacy table silently accepted as larger table");
        Reject(()=>Staging.DecodeTable(Frame(128,3),64),"Larger table silently truncated to legacy capacity");
        Reject(()=>Staging.ByteLimit(65),"Unqualified capacity accepted");
        Check(Staging.ByteLimit(64)==32UL*1024*1024&&Staging.ByteLimit(128)==64UL*1024*1024,"Profile byte budgets changed");
        Reject(()=>Staging.ValidateTableEpoch("epoch-a","epoch-b",128,128,0,0),"Reloaded provider table accepted");
        Reject(()=>Staging.ValidateTableEpoch("epoch-a","epoch-a",64,128,0,0),"Changed metadata capacity accepted");
        Reject(()=>Staging.ValidateTableEpoch("epoch-a","epoch-a",128,128,0,1),"Concurrent STOP table accepted");
        Console.WriteLine($"PASS {passed} diagnostic table checks; legacy and extended capacities validated.");
    }
}
