using System.Text.Json;
using RansomFree.Callbacks;

namespace RansomFree.Server;

internal static class KubeconfigToken
{
    // JSON is valid YAML. No exec plugin, insecure TLS switch, local paths or real credentials.
    public static byte[] Render(CallbackToken token,Uri origin)
    {
        if(!CallbackStorage.ValidId(token.Id) || origin.Scheme!="https")throw new ArgumentException("Invalid token configuration.");
        return JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string,object>
        {
            ["apiVersion"]="v1",["kind"]="Config",
            ["clusters"]=new[]{new{name="operations",cluster=new{server=new Uri(origin,"kubernetes/"+token.Id).AbsoluteUri}}},
            ["users"]=new[]{new{name="operations-reader",user=new{token="rf_canary_"+token.Id}}},
            ["contexts"]=new[]{new{name="operations",context=new{cluster="operations",user="operations-reader"}}},
            ["current-context"]="operations"
        },new JsonSerializerOptions{WriteIndented=true});
    }
}
