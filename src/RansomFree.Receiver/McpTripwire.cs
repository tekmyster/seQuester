using System.Text.Json;
using RansomFree.Callbacks;

internal static class McpTripwire
{
    public static void MapMcpTripwire(this WebApplication app)
    {
        app.MapGet("/t/{id}/mcp",()=>Results.StatusCode(405));
        app.MapPost("/t/{id}/mcp",async(string id,HttpContext context,CallbackStorage store)=>
        {
            // CLI configuration tripwire only. Browser origins are deliberately unsupported.
            if(context.Request.Headers.ContainsKey("Origin"))return Results.StatusCode(403);
            if(store.Get(id) is not {Revoked:false,Type:"mcp"})return Results.NotFound();
            var protocol=context.Request.Headers["MCP-Protocol-Version"].ToString();
            if(protocol.Length>0 && protocol is not ("2025-03-26" or "2025-06-18"))return Results.BadRequest();
            if(!context.Request.HasJsonContentType())return Results.StatusCode(415);
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);timeout.CancelAfter(TimeSpan.FromSeconds(5));
            using var buffer=new MemoryStream();var chunk=new byte[1024];
            while(true){var count=await context.Request.Body.ReadAsync(chunk,timeout.Token);if(count==0)break;if(buffer.Length+count>8192)return Results.StatusCode(413);buffer.Write(chunk,0,count);}
            JsonDocument message;
            try{message=JsonDocument.Parse(buffer.ToArray(),new JsonDocumentOptions{MaxDepth=16});}catch(JsonException){return Results.BadRequest();}
            using(message)
            {
                var root=message.RootElement;
                if(root.ValueKind!=JsonValueKind.Object || !root.TryGetProperty("jsonrpc",out var rpc) || rpc.ValueKind!=JsonValueKind.String || rpc.GetString()!="2.0" || !root.TryGetProperty("method",out var method) || method.ValueKind!=JsonValueKind.String)return Results.BadRequest();
                var name=method.GetString()!;if(name.Length>100)return Results.BadRequest();
                // Only a method name is retained. Client parameters, roots, prompts and credentials are not logged.
                if(!store.Record(id,"HTTPS",context.Connection.RemoteIpAddress?.ToString()??"unknown","MCP "+name))return Results.NotFound();
                if(!root.TryGetProperty("id",out var requestId))return Results.StatusCode(202);
                if(requestId.ValueKind is not (JsonValueKind.String or JsonValueKind.Number))return Results.BadRequest();
                var result=name switch
                {
                    "initialize"=>(object)new{protocolVersion="2025-06-18",capabilities=new{tools=new{}},serverInfo=new{name="RansomFree reference endpoint",version="0.6.0-dev"}},
                    "tools/list"=>new{tools=Array.Empty<object>()},
                    "ping"=>new{},
                    _=>null
                };
                return result!=null?Results.Json(new{jsonrpc="2.0",id=requestId.Clone(),result}):Results.Json(new{jsonrpc="2.0",id=requestId.Clone(),error=new{code=-32601,message="Method not available"}});
            }
        });
    }
}
