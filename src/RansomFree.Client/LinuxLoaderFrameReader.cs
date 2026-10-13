namespace RansomFree.Client;

// One owned stdout reader; no text decoding or newline normalization before
// hashing/admission. This class neither owns nor closes the loader/controller.
internal sealed class LinuxLoaderFrameReader
{
    private readonly Stream stream;
    private readonly byte[] buffer;
    private readonly int maximum;
    private int buffered,reading;
    private bool ended,faulted,remainderTaken;
    internal byte[] TakeFaultedRemainder()
    {
        if(Volatile.Read(ref reading)!=0||!faulted||remainderTaken)throw new InvalidOperationException("One completed framing failure required before taking its buffered bytes");
        remainderTaken=true;var result=buffer.AsSpan(0,buffered).ToArray();buffered=0;return result;
    }
    internal LinuxLoaderFrameReader(Stream stream,int maximum=65536)
    {
        if(!stream.CanRead||maximum is <1 or >65536)throw new ArgumentException("Readable loader stream and bounded frame size required");
        this.stream=stream;this.maximum=maximum;buffer=new byte[maximum+1];
    }
    internal async ValueTask<byte[]?> ReadAsync(CancellationToken waitCancellation=default)
    {
        if(Interlocked.Exchange(ref reading,1)!=0)throw new InvalidOperationException("Only one reader may consume owned loader stdout");
        try
        {
            if(faulted)throw new InvalidOperationException("LOADER_FRAME_CONTINUITY_UNKNOWN: reader cannot resume after failure");
            if(ended)return null;
            while(true)
            {
                var newline=Array.IndexOf(buffer,(byte)'\n',0,buffered);
                if(newline>=0)
                {
                    var result=buffer.AsSpan(0,newline).ToArray();var left=buffered-newline-1;
                    if(left>0)Buffer.BlockCopy(buffer,newline+1,buffer,0,left);buffered=left;return result;
                }
                if(buffered>maximum)throw new InvalidDataException("LOADER_FRAME_TOO_LARGE: at least "+buffered+" bytes before newline");
                var count=await stream.ReadAsync(buffer.AsMemory(buffered,buffer.Length-buffered),waitCancellation).ConfigureAwait(false);
                if(count==0)
                {
                    if(buffered!=0)throw new EndOfStreamException("LOADER_PARTIAL_FRAME: EOF after "+buffered+" bytes without newline");
                    ended=true;return null;
                }
                buffered+=count;
            }
        }
        catch
        {
            // Cancellation only stops this managed wait. It is not evidence of
            // native cancellation/close, nor permission to resume a byte stream
            // whose failed read did not report an exact consumed byte count.
            faulted=true;throw;
        }
        finally{Volatile.Write(ref reading,0);}
    }
}
