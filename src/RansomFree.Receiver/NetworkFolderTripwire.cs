using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using RansomFree.Callbacks;

internal static class NetworkFolderTripwire
{
    private static readonly XNamespace Dav="DAV:";
    private const string Content="Operations archive\r\nInventory is being reconciled.\r\n";
    public static void MapNetworkFolderTripwire(this WebApplication app)
    {
        app.Map("/dav/{id}/{**path}",async(string id,string? path,HttpContext context,CallbackStorage store)=>
        {
            if(store.Get(id) is not {Type:"network-folder",Revoked:false})return Results.NotFound();
            context.Response.Headers["DAV"]="1";
            context.Response.Headers.Allow="OPTIONS, PROPFIND, GET, HEAD";
            if(context.Request.Method=="OPTIONS")return Results.Ok();
            if(!Authenticated(context,id))
            {context.Response.Headers.WWWAuthenticate="Basic realm=\"Archive\", charset=\"UTF-8\"";return Results.Unauthorized();}
            if(!store.Record(id,"HTTPS",context.Connection.RemoteIpAddress?.ToString()??"unknown","Network folder credential presented"))return Results.NotFound();
            // Only synthetic in-memory resources exist. No filesystem mapping or outbound calls.
            var root=string.IsNullOrEmpty(path);if(!root && path!="inventory.txt")return Results.NotFound();
            if(context.Request.Method is "GET" or "HEAD")
            {
                if(root)return Results.StatusCode(403);
                context.Response.ContentLength=Encoding.UTF8.GetByteCount(Content);
                return context.Request.Method=="HEAD"?Results.StatusCode(200):Results.Text(Content,"text/plain",Encoding.UTF8);
            }
            if(context.Request.Method!="PROPFIND")return Results.StatusCode(405);
            var depth=context.Request.Headers["Depth"].ToString();
            if(depth is not ("0" or "1"))return Results.Content("<d:error xmlns:d=\"DAV:\"><d:propfind-finite-depth/></d:error>","application/xml",statusCode:403);
            XElement? requested=null;var namesOnly=false;
            if(context.Request.ContentLength!=0 && (context.Request.ContentLength!=null || context.Request.Headers.ContainsKey("Transfer-Encoding")))
            {
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);timeout.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    using var memory=new MemoryStream();var buffer=new byte[1024];int read;
                    while((read=await context.Request.Body.ReadAsync(buffer,timeout.Token))>0)
                    {if(memory.Length+read>8192)return Results.StatusCode(413);memory.Write(buffer,0,read);}
                    if(memory.Length>0)
                    {
                        memory.Position=0;using var reader=XmlReader.Create(memory,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=8192});
                        var document=XDocument.Load(reader);var element=document.Root;
                        if(element?.Name!=Dav+"propfind" || element.Descendants().Count()>64)return Results.BadRequest();
                        var selectors=element.Elements().Where(e=>e.Name==Dav+"prop"||e.Name==Dav+"allprop"||e.Name==Dav+"propname").ToArray();
                        if(selectors.Length!=1)return Results.BadRequest();requested=selectors[0].Name==Dav+"prop"?selectors[0]:null;namesOnly=selectors[0].Name==Dav+"propname";
                    }
                }
                catch(XmlException){return Results.BadRequest();}
                catch(OperationCanceledException) when(!context.RequestAborted.IsCancellationRequested){return Results.StatusCode(408);}
            }
            var basePath="/dav/"+id+"/";var responses=new List<XElement>{Resource(root?basePath:basePath+"inventory.txt",root,requested,namesOnly)};
            if(root&&depth=="1")responses.Add(Resource(basePath+"inventory.txt",false,requested,namesOnly));
            return Results.Content(new XElement(Dav+"multistatus",new XAttribute(XNamespace.Xmlns+"d",Dav),responses).ToString(SaveOptions.DisableFormatting),"application/xml",Encoding.UTF8,207);
        });
    }
    private static bool Authenticated(HttpContext context,string id)
    {
        var headers=context.Request.Headers.Authorization;if(headers.Count!=1 || headers[0] is not {} value || value.Length>256 || !value.StartsWith("Basic ",StringComparison.OrdinalIgnoreCase))return false;
        byte[] supplied;try{supplied=Convert.FromBase64String(value[6..]);}catch(FormatException){return false;}
        try{return CryptographicOperations.FixedTimeEquals(supplied,Encoding.UTF8.GetBytes("archive:rf_canary_"+id));}finally{CryptographicOperations.ZeroMemory(supplied);}
    }
    private static XElement Resource(string href,bool collection,XElement? requested,bool namesOnly)
    {
        var properties=new Dictionary<XName,XElement>
        {
            [Dav+"displayname"]=new(Dav+"displayname",collection?"Operations archive":"inventory.txt"),
            [Dav+"resourcetype"]=new(Dav+"resourcetype",collection?new XElement(Dav+"collection"):null),
            [Dav+"getcontentlength"]=new(Dav+"getcontentlength",collection?0:Encoding.UTF8.GetByteCount(Content)),
            [Dav+"getcontenttype"]=new(Dav+"getcontenttype",collection?"httpd/unix-directory":"text/plain"),
            [Dav+"getlastmodified"]=new(Dav+"getlastmodified","Sat, 12 Sep 2026 00:00:00 GMT")
        };
        var ok=new XElement(Dav+"prop");var missing=new XElement(Dav+"prop");
        foreach(var key in requested?.Elements().Select(e=>e.Name).Distinct()??properties.Keys)
            if(properties.TryGetValue(key,out var property))ok.Add(namesOnly?new XElement(key):new XElement(property));else missing.Add(new XElement(key));
        var response=new XElement(Dav+"response",new XElement(Dav+"href",href));
        if(ok.HasElements)response.Add(new XElement(Dav+"propstat",ok,new XElement(Dav+"status","HTTP/1.1 200 OK")));
        if(missing.HasElements)response.Add(new XElement(Dav+"propstat",missing,new XElement(Dav+"status","HTTP/1.1 404 Not Found")));
        return response;
    }
}
