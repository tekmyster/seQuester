using System.Diagnostics;
using System.Text.Json;
using RansomFree.Server;
using Microsoft.AspNetCore.DataProtection;

if(args.Length!=1)throw new ArgumentException("Owned shadow database directory required");
var root=Path.GetFullPath(args[0]);
if(!Path.GetFileName(root).StartsWith("history-runtime-shadow-",StringComparison.Ordinal)||!File.Exists(Path.Combine(root,"OWNED-SHADOW.json")))throw new IOException("Only the isolated QA copy is permitted");
Environment.SetEnvironmentVariable("RF_HISTORY_DIAGNOSTICS","1");
var clock=Stopwatch.StartNew();Console.WriteLine("RUNTIME_PROBE constructor-start");
var store=new Store(root);Console.WriteLine($"RUNTIME_PROBE constructor-complete {clock.ElapsedMilliseconds}ms");
var queries=new[]{
    new EventHistoryQuery{Endpoint="420f9eceef2540c88b158cfaf4c8730f",Sort="sequence",Limit=1},
    new EventHistoryQuery{Endpoint="6968ef5bf7354785803bee43b31d5b54",Sort="sequence",Limit=1},
    new EventHistoryQuery{Endpoint="420f9eceef2540c88b158cfaf4c8730f",Sort="sequence",Limit=500,PathContains="smb-boundary-df435a2b8a694361ae0aa5b67494a3de"}};
var results=new List<object>();
foreach(var query in queries){
    clock.Restart();Console.WriteLine($"RUNTIME_PROBE query-start {query.Endpoint} limit={query.Limit}");
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(60));
    var page=await store.History(query,cancellationToken:timeout.Token);
    Console.WriteLine($"RUNTIME_PROBE store-complete {clock.ElapsedMilliseconds}ms");
    var names=store.EndpointNames(page.Items.Select(i=>i.EndpointId));
    var classifications=page.Items.Select(i=>store.ClassifyTrust(i).ToString()).ToArray();
    Console.WriteLine($"RUNTIME_PROBE trust-complete {clock.ElapsedMilliseconds}ms");
    results.Add(new{query.Endpoint,query.Limit,page.Total,Items=page.Items.Count,page.Snapshot,HasNext=page.Next!=null,Milliseconds=clock.ElapsedMilliseconds,Classifications=classifications});
}
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Scope="Actual managed history engine against an isolated database copy; no live writer or HTTP/identity acceptance",Queries=results}));
if(Directory.Exists(Path.Combine(root,"identity-keys"))){
    clock.Restart();Console.WriteLine("RUNTIME_PROBE protection-start");
    var provider=DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root,"identity-keys")),builder=>builder.SetApplicationName("RansomFree.Management"));
    var protector=provider.CreateProtector("seQuester.EventHistory.Cursor.v1");
    var encrypted=protector.Protect("isolated history cursor qualification");
    if(protector.Unprotect(encrypted)!="isolated history cursor qualification")throw new IOException("Copied-key roundtrip failed");
    Console.WriteLine($"RUNTIME_PROBE protection-complete {clock.ElapsedMilliseconds}ms");
    foreach(var query in queries.Take(2)){
        clock.Restart();Console.WriteLine("RUNTIME_PROBE api-start");
        var context=new Microsoft.AspNetCore.Http.DefaultHttpContext();
        var result=await EventHistoryApi.Read(context,store,provider,query,"isolated-qa-copy");
        Console.WriteLine($"RUNTIME_PROBE api-complete {clock.ElapsedMilliseconds}ms");
        var value=((Microsoft.AspNetCore.Http.IValueHttpResult)result).Value!;
        var bytes=JsonSerializer.SerializeToUtf8Bytes(value,value.GetType(),new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Console.WriteLine($"RUNTIME_PROBE serialize-complete {clock.ElapsedMilliseconds}ms bytes={bytes.Length}");
    }
    File.WriteAllText(Path.Combine(root,"PROTECTION-RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Scope="Copied identity-key protection and event history API method/serialization, isolated QA copy; no live authentication acceptance"}));
}
