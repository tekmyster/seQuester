using System.Security.Cryptography;
using System.Text;
using RansomFree.Callbacks;

internal static class KubernetesTripwire
{
    public static void MapKubernetesTripwire(this WebApplication app)
    {
        // A denial-only API surface. Never forwards a request or reads/stores its body,
        // query, resource names, authorization value or impersonation headers.
        app.Map("/kubernetes/{id}/{**path}",(string id,HttpContext context,CallbackStorage store)=>
        {
            if(store.Get(id) is not {Type:"kubeconfig",Revoked:false})return Denied(401);
            var authorization=context.Request.Headers.Authorization;
            var expected="Bearer rf_canary_"+id;
            if(authorization.Count!=1 || authorization[0] is not {} value || value.Length!=expected.Length ||
                !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(value),Encoding.ASCII.GetBytes(expected)))return Denied(401);
            if(!store.Record(id,"HTTPS",context.Connection.RemoteIpAddress?.ToString()??"unknown","Kubeconfig credential presented"))return Denied(401);
            return Denied(403);
        });
    }
    private static IResult Denied(int code)=>Results.Json(new{kind="Status",apiVersion="v1",status="Failure",message=code==403?"Access forbidden":"Unauthorized",reason=code==403?"Forbidden":"Unauthorized",code},statusCode:code);
}
