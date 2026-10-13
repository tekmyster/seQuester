namespace RansomFree.Contracts;
public sealed record LocalHistoryKey(string Id,DateTimeOffset Time,string Operation,string Path,string? User,string? Process,int? Pid);
public static class LocalHistoryOrder
{
    public static readonly string[] Fields=["time","operation","path","user","process","pid"];
    public static int Compare(LocalHistoryKey a,LocalHistoryKey b,string field,bool descending)
    {
        object? Key(LocalHistoryKey e)=>field switch{"time"=>e.Time.UtcTicks,"operation"=>e.Operation,"path"=>e.Path,"user"=>string.IsNullOrEmpty(e.User)?null:e.User,"process"=>string.IsNullOrEmpty(e.Process)?null:e.Process,"pid"=>e.Pid,_=>throw new ArgumentException("Unsupported local sort field.")};
        var x=Key(a);var y=Key(b);int order;
        if(x==null)order=y==null?0:1;else if(y==null)order=-1;else{order=x is string sx&&y is string sy?StringComparer.Ordinal.Compare(sx,sy):Convert.ToInt64(x).CompareTo(Convert.ToInt64(y));if(descending)order=-order;}
        return order!=0?order:StringComparer.Ordinal.Compare(a.Id,b.Id);
    }
}
