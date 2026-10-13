namespace RansomFree.LinuxAgent;

// Pure, bounded reconciliation logic. No shell, global deletion or implicit
// normalization of unknown rules. Shared directly with the fixture harness.
internal sealed record ManagedAuditRule(string Arch,string Path)
{
    // Preserve the reviewed all-syscall authority explicitly. libaudit 4.x
    // otherwise infers a narrower permission-specific mask, unlike 3.x.
    public string[] Arguments=>["-a","always,exit","-F","arch="+Arch,"-S","all","-F","path="+Path,"-F","perm=rwa","-k",AuditRulePlan.Key];
}
internal sealed record AuditRuleSnapshot(ManagedAuditRule[] Owned,string[] Unrelated);
internal sealed record AuditRuleResult(int Expected,int AlreadyPresent,int Added,int UnrelatedPreserved);
internal static class AuditRulePlan
{
    public const string Key="sequester_canary";
    public static bool SafePath(string path)=>path.StartsWith('/')&&path.Length<=2048&&path.Length>1&&!path.EndsWith('/')&&path.All(c=>char.IsAsciiLetterOrDigit(c)||c is '/' or '_' or '-' or '.')&&path.Split('/').Skip(1).All(p=>p.Length>0&&p is not "." and not "..");
    public static ManagedAuditRule Parse(string line)
    {
        if(line.Length>4096)throw new InvalidDataException("Rule too long.");
        var tokens=line.Split(' ',StringSplitOptions.RemoveEmptyEntries);
        if(tokens.Length<10||tokens.Length%2!=0||tokens[0]!="-a"||tokens[1] is not ("always,exit" or "exit,always"))throw new InvalidDataException("Unsupported managed rule.");
        var fields=new Dictionary<string,string>(StringComparer.Ordinal);
        for(var i=2;i<tokens.Length;i+=2)
        {
            string name,value;
            if(tokens[i]=="-S"){name="syscalls";value=tokens[i+1];}
            else if(tokens[i]=="-k"){name="key";value=tokens[i+1];}
            else if(tokens[i]=="-F")
            {
                var split=tokens[i+1].IndexOf('=');if(split<1)throw new InvalidDataException("Unsupported managed field.");
                name=tokens[i+1][..split];value=tokens[i+1][(split+1)..];
            }
            else throw new InvalidDataException("Unsupported managed option.");
            if(name is not ("arch" or "path" or "perm" or "key" or "syscalls")||!fields.TryAdd(name,value))throw new InvalidDataException("Unknown or duplicate managed field.");
        }
        if(fields.GetValueOrDefault("syscalls","all")!="all")throw new InvalidDataException("Explicit all-syscall authority required; expanded live masks need administrator review before reconciliation.");
        if(fields.GetValueOrDefault("arch") is not ("b64" or "b32")||fields.GetValueOrDefault("key")!=Key||fields.GetValueOrDefault("perm")!="rwa"||!SafePath(fields.GetValueOrDefault("path","")))throw new InvalidDataException("Unsupported managed rule semantics.");
        return new(fields["arch"],fields["path"]);
    }
    static string[] Lines(string text)
    {
        if(text.Length>4*1024*1024)throw new InvalidDataException("Rule inventory too large.");
        var lines=text.Split('\n').Select(s=>s.Trim()).Where(s=>s.Length>0).ToArray();
        if(lines.Length>20000||lines.Any(s=>s.Length>16384))throw new InvalidDataException("Rule inventory exceeds bounds.");
        return lines;
    }
    public static ManagedAuditRule[] Desired(string text)
    {
        var lines=Lines(text).Where(s=>!s.StartsWith('#')).ToArray();
        if(lines.Length is <1 or >2000)throw new InvalidDataException("Require 1–2000 reviewed rules.");
        var rules=lines.Select(Parse).ToArray();
        if(rules.Distinct().Count()!=rules.Length)throw new InvalidDataException("Duplicate desired rules.");
        return rules;
    }
    public static AuditRuleSnapshot Snapshot(string text)
    {
        var lines=Lines(text);
        if(lines.Length==1&&lines[0]=="No rules")return new([],[]);
        if(lines.Any(s=>s=="No rules"||!s.StartsWith('-')))throw new InvalidDataException("Unexpected auditctl inventory output.");
        // Reserved-key ambiguity is a refusal, not permission to rewrite it.
        var owned=lines.Where(s=>s.Contains(Key,StringComparison.Ordinal)).Select(Parse).ToArray();
        if(owned.Distinct().Count()!=owned.Length)throw new InvalidDataException("Duplicate live managed rules.");
        return new(owned,lines.Where(s=>!s.Contains(Key,StringComparison.Ordinal)).ToArray());
    }
    public static async Task<AuditRuleResult> Reconcile(ManagedAuditRule[] desired,Func<Task<string>> list,Func<ManagedAuditRule,Task> add,Action<int>? progress=null)
    {
        if(desired.Length is <1 or >2000||desired.Distinct().Count()!=desired.Length)throw new InvalidDataException("Invalid desired rule set.");
        var wanted=desired.ToHashSet();var baseline=Snapshot(await list());
        if(baseline.Owned.Any(rule=>!wanted.Contains(rule)))throw new InvalidDataException("Unexpected reserved-key live rule; administrator review required.");
        var expected=baseline.Owned.ToHashSet();var added=0;
        void Verify(AuditRuleSnapshot actual)
        {
            if(!actual.Unrelated.SequenceEqual(baseline.Unrelated,StringComparer.Ordinal)||!actual.Owned.ToHashSet().SetEquals(expected))throw new IOException("Concurrent or unexpected audit rule change; stopped without clearing rules.");
        }
        foreach(var rule in desired.Where(rule=>!expected.Contains(rule)).ToArray())
        {
            Verify(Snapshot(await list()));
            // Stop at the first error. Already added exact rules remain tracked;
            // a later explicit run computes missing rules anew, never blind -R.
            await add(rule);expected.Add(rule);
            Verify(Snapshot(await list()));added++;progress?.Invoke(added);
        }
        Verify(Snapshot(await list()));
        return new(desired.Length,baseline.Owned.Length,added,baseline.Unrelated.Length);
    }
}
