namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    // Short-lived same-process exclusion for expensive private-file work.
    // Durable snapshot intents govern recovery; this object is never restored.
    private readonly Dictionary<string,PrivateWork> privateWork=new(StringComparer.Ordinal);
    private sealed class PrivateWork:IDisposable
    {
        private readonly LinuxForensicJournal journal;
        private readonly string id;
        private bool disposed;
        internal PrivateWork(LinuxForensicJournal journal,string id){this.journal=journal;this.id=id;}
        public void Dispose()
        {
            lock(journal.gate)
            {
                if(disposed)return;
                if(!journal.privateWork.TryGetValue(id,out var current)||!ReferenceEquals(current,this))throw new InvalidOperationException("Private operation owner changed");
                disposed=true;journal.privateWork.Remove(id);
            }
        }
    }
    private PrivateWork BeginPrivateWorkLocked(string id)
    {
        if(privateWork.ContainsKey(id))throw new InvalidOperationException("Private event work is already in progress");
        var operation=new PrivateWork(this,id);privateWork.Add(id,operation);return operation;
    }
}
