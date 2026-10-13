using System.Security.Claims;
using RansomFree.Contracts;
namespace RansomFree.Server;

public static class EvidenceTransferApi
{
    public static void MapEvidenceTransfer(this WebApplication app,Func<HttpContext,string?> authenticate,Func<HttpContext,bool> admin)
    {
        async Task<IResult> Execute(HttpContext c,Func<string,EvidenceReceiver,Task<EvidenceUploadReceipt>> action)
        {
            var endpoint=authenticate(c);if(endpoint==null)return Results.Unauthorized();
            try{return Results.Ok(await action(endpoint,c.RequestServices.GetRequiredService<EvidenceReceiver>()));}
            catch(EvidenceUploadException ex){if(ex.Status is 409 or 422 or 507)c.RequestServices.GetRequiredService<Store>().CallbackAudit("Actor evidence transfer rejected",endpoint,ex.Message);return Results.Json(new{error=ex.Message},statusCode:ex.Status);}
        }
        app.MapPost("/api/v1/agent/evidence/start",(HttpContext c,EvidenceUploadStart request)=>Execute(c,(id,receiver)=>receiver.Start(id,request,c.RequestAborted)));
        app.MapPost("/api/v1/agent/evidence/{id}/status",(HttpContext c,string id)=>Execute(c,(endpoint,receiver)=>receiver.Status(endpoint,id,c.RequestAborted)));
        app.MapPost("/api/v1/agent/evidence/{id}/finish",(HttpContext c,string id)=>Execute(c,(endpoint,receiver)=>receiver.Finish(endpoint,id,c.RequestAborted)));
        app.MapPut("/api/v1/agent/evidence/{id}/chunks/{offset:long}",(HttpContext c,string id,long offset)=>Execute(c,async(endpoint,receiver)=>
        {
            if(c.Request.ContentType!="application/octet-stream"||c.Request.ContentLength is not (>0 and <=EvidenceTransferLimits.ChunkBytes))throw new EvidenceUploadException(400,"bounded-binary-chunk-required");
            var bytes=new byte[(int)c.Request.ContentLength.Value];await c.Request.Body.ReadExactlyAsync(bytes,c.RequestAborted);
            return await receiver.Chunk(endpoint,id,offset,bytes,c.RequestAborted);
        }));
        async Task<IResult> Receipt(HttpContext c,string endpoint,string id)
        {try{return Results.Ok(await c.RequestServices.GetRequiredService<EvidenceReceiver>().Status(endpoint,id,c.RequestAborted));}catch(EvidenceUploadException ex){return Results.Json(new{error=ex.Message},statusCode:ex.Status);}}
        async Task<IResult> Download(HttpContext c,string endpoint,string id,string kind)
        {
            if(kind is not ("artifact" or "manifest"))return Results.NotFound();
            try
            {
                var file=c.RequestServices.GetRequiredService<EvidenceReceiver>().Download(endpoint,id,kind=="manifest");
                try
                {
                    var admitted=await c.RequestServices.GetRequiredService<SqliteWriteAdmission>().Execute(c,()=>
                    {
                        c.RequestServices.GetRequiredService<Store>().CallbackAudit("Actor evidence downloaded",c.User.FindFirstValue(ClaimTypes.NameIdentifier)??"bootstrap-admin",endpoint+":"+id+":"+kind);
                        return Task.CompletedTask;
                    });
                    if(!admitted){file.Dispose();return Results.Empty;}
                }catch{file.Dispose();throw;}
                return Results.File(file,"application/octet-stream",id+(kind=="manifest"?".json":".bin"),enableRangeProcessing:false);
            }catch(EvidenceUploadException ex){return Results.Json(new{error=ex.Message},statusCode:ex.Status);}
        }
        var read=app.MapGroup("/api/v1/console/actor-evidence").RequireAuthorization(p=>p.RequireRole("Administrator","Operator"));
        read.MapGet("/{endpoint}/{id}",Receipt);read.MapGet("/{endpoint}/{id}/{kind}",Download);
        app.MapGet("/api/v1/admin/actor-evidence/{endpoint}/{id}",(HttpContext c,string endpoint,string id)=>admin(c)?Receipt(c,endpoint,id):Task.FromResult<IResult>(Results.Unauthorized()));
        app.MapGet("/api/v1/admin/actor-evidence/{endpoint}/{id}/{kind}",(HttpContext c,string endpoint,string id,string kind)=>admin(c)?Download(c,endpoint,id,kind):Task.FromResult<IResult>(Results.Unauthorized()));
    }
}
