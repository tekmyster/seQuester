namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxProtectedDirectory
{
    [ThreadStatic] private static MountValidationPass? mountValidation;
    internal sealed class MountValidationPass:IDisposable
    {
        private readonly Func<string> read;
        private string? inventory;
        private readonly MountValidationPass? parent;
        private readonly int thread=Environment.CurrentManagedThreadId;
        private readonly Dictionary<(ulong Mount,uint Major,uint Minor),string?> observed=new();
        private readonly Dictionary<DirectMountKey,string> directObserved=new();
        private bool completed,disposed;
        internal MountValidationPass(Func<string> read,bool eager=true)
        {
            this.read=read;inventory=eager?read():null;parent=mountValidation;mountValidation=this;
        }
        private void RequireOwned()
        {
            if(disposed||Environment.CurrentManagedThreadId!=thread||!ReferenceEquals(mountValidation,this))
                throw new InvalidOperationException("Synchronous mount validation pass ownership changed");
        }
        internal string? Observe(ulong mount,uint major,uint minor)
        {
            RequireOwned();if(completed)throw new InvalidOperationException("Mount validation pass already completed");
            var key=(mount,major,minor);
            if(!observed.TryGetValue(key,out var type)){inventory??=read();type=ReadMountType(inventory,mount,major,minor);observed.Add(key,type);}
            return type;
        }
        internal string? ObserveDirect(DirectMountKey key)
        {
            RequireOwned();if(completed)throw new InvalidOperationException("Mount validation pass already completed");
            if(directObserved.TryGetValue(key,out var type))return type;
            type=ReadDirectMount(key);if(type!=null)directObserved.Add(key,type);return type;
        }
        internal void Complete()
        {
            RequireOwned();if(completed)throw new InvalidOperationException("Mount validation pass already completed");
            var current=inventory==null?null:read();
            foreach(var (key,type) in observed)
                if(ReadMountType(current!,key.Mount,key.Major,key.Minor)!=type)
                    throw new IOException("Observed mount changed during filesystem validation");
            foreach(var (key,type) in directObserved)
                if(ReadDirectMount(key)!=type)throw new IOException("Directly observed mount changed during filesystem validation");
            completed=true;
        }
        public void Dispose()
        {
            if(disposed)return;RequireOwned();mountValidation=parent;disposed=true;
        }
    }
    internal static MountValidationPass BeginMountValidation()
        =>new(()=>{using var input=File.OpenRead("/proc/self/mountinfo");return ReadMountInventory(input);},eager:false);
}
