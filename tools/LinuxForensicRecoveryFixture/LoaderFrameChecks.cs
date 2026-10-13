using System.Text;
using System.Text.Json;
using RansomFree.Client;

static class LoaderFrameChecks
{
    internal static async Task Run()
    {
        var checks=0;void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        async Task Reject(LinuxLoaderFrameReader reader,string label)
        {try{await reader.ReadAsync();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted "+label);}
        foreach(var chunk in new[]{1,2,7,4096,65537})
        {
            var first=Encoding.UTF8.GetBytes("{\"path\":\"/lambda-\u03bb-\U0001f512\",\"n\":18446744073709551615}");var second=new byte[]{0xff,0x00,0x0d};
            var bytes=first.Concat(new byte[]{10}).Concat(second).Concat(new byte[]{10}).ToArray();var stream=new Fragmented(bytes,chunk);var reader=new LinuxLoaderFrameReader(stream);
            Check((await reader.ReadAsync())!.SequenceEqual(first),"exact multibyte JSON bytes survive fragmented read: "+chunk);
            Check((await reader.ReadAsync())!.SequenceEqual(second),"malformed/CR bytes are retained for validation, never decoded or normalized: "+chunk);
            Check(await reader.ReadAsync()==null&&await reader.ReadAsync()==null,"clean EOF after complete frames remains explicit: "+chunk);
        }
        var limit=new byte[65536];Array.Fill(limit,(byte)'x');
        var exactReader=new LinuxLoaderFrameReader(new MemoryStream(limit.Concat(new byte[]{10}).ToArray()));Check((await exactReader.ReadAsync())!.SequenceEqual(limit),"maximum raw frame accepted exactly at byte bound");
        var tooLarge=new LinuxLoaderFrameReader(new MemoryStream(limit.Concat(new byte[]{(byte)'x',10}).ToArray()));await Reject(tooLarge,"oversized frame refused before unbounded buffering");await Reject(tooLarge,"oversized stream cannot silently resume at a later frame");
        var partial=new LinuxLoaderFrameReader(new MemoryStream(Encoding.ASCII.GetBytes("{\"partial\":true}")));await Reject(partial,"EOF without native newline is explicit partial frame");await Reject(partial,"partial-frame failure is sticky");
        Check(tooLarge.TakeFaultedRemainder().SequenceEqual(limit.Concat(new byte[]{(byte)'x'})),"oversized rejected prefix retained exactly including read-ahead byte");
        Check(partial.TakeFaultedRemainder().SequenceEqual(Encoding.ASCII.GetBytes("{\"partial\":true}")),"EOF failure exposes exact bytes already removed from pipe");
        try{partial.TakeFaultedRemainder();throw new Exception("Failure prefix taken twice");}catch(InvalidOperationException){Check(true,"failure prefix ownership transfers only once");}
        try{exactReader.TakeFaultedRemainder();throw new Exception("Live reader bytes stolen");}catch(InvalidOperationException){Check(true,"live framing buffer cannot be stolen");}
        var empty=new LinuxLoaderFrameReader(new MemoryStream(new byte[]{10,10}));Check((await empty.ReadAsync())!.Length==0&&(await empty.ReadAsync())!.Length==0,"empty frames are delivered distinctly for protocol rejection");
        using var cancellation=new CancellationTokenSource();cancellation.Cancel();var cancelled=new LinuxLoaderFrameReader(new Fragmented(new byte[]{1,10},1));
        try{await cancelled.ReadAsync(cancellation.Token);throw new Exception("Cancelled read unexpectedly returned");}catch(OperationCanceledException){Check(true,"managed read cancellation is visible");}
        await Reject(cancelled,"cancelled byte stream does not imply resumable native continuity");
        var waiting=new WaitStream();var concurrent=new LinuxLoaderFrameReader(waiting);var pending=concurrent.ReadAsync().AsTask();
        try{await concurrent.ReadAsync();throw new Exception("Concurrent reader unexpectedly returned");}catch(InvalidOperationException){Check(true,"concurrent readers cannot steal each other's bytes");}
        waiting.Data.TrySetResult(new byte[]{7,10});Check((await pending)!.SequenceEqual(new byte[]{7}),"rejected concurrent call leaves rightful read intact");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Bounded byte-frame reader only; no native/controller cancellation or deployment"}));
    }
    private sealed class Fragmented(byte[] bytes,int chunk):MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {cancellationToken.ThrowIfCancellationRequested();return base.ReadAsync(buffer[..Math.Min(buffer.Length,chunk)],cancellationToken);}
    }
    private sealed class WaitStream:Stream
    {
        internal TaskCompletionSource<byte[]> Data=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {var bytes=await Data.Task.WaitAsync(cancellationToken);bytes.CopyTo(buffer);return bytes.Length;}
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override void Flush()=>throw new NotSupportedException();public override int Read(byte[] b,int o,int c)=>throw new NotSupportedException();public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();public override void SetLength(long n)=>throw new NotSupportedException();public override void Write(byte[] b,int o,int c)=>throw new NotSupportedException();
    }
}
