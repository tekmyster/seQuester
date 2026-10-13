using System.Net;
using RansomFree.Persistence;
namespace RansomFree.Server;
public sealed partial class Store
{
    public IReadOnlyDictionary<string,(string Os,string? Ip)> HistoryContacts(IEnumerable<string> endpointIds)
    {
        var ids=endpointIds.Where(id=>Guid.TryParseExact(id,"N",out _)).Distinct(StringComparer.Ordinal).ToArray();
        var result=new Dictionary<string,(string,string?)>(StringComparer.Ordinal);if(ids.Length==0)return result;
        var platform=HasPlatformStorage();var args=ids.Select((id,index)=>("$id"+index,(object)id)).ToArray();
        using var c=Open();using var command=Command(c,null,"SELECT e.id,"+(platform?"COALESCE(p.os,'unknown')":"'unknown'")+",n.address FROM endpoints e LEFT JOIN endpoint_contact n ON n.endpoint=e.id "+(platform?"LEFT JOIN endpoint_platform p ON p.endpoint=e.id ":"")+"WHERE e.id IN ("+string.Join(',',args.Select(x=>x.Item1))+")",args);
        using var reader=command.ExecuteReader();while(reader.Read())result[reader.GetString(0)]=(reader.GetString(1),reader.IsDBNull(2)?null:reader.GetString(2));return result;
    }
    // Server-observed connection address; never accept a client-provided forwarding header.
    public void RecordContact(string endpoint,IPAddress? address)
    {
        if(address==null)return;
        if(sqlServer)SqlServerSchema.Require(connectionString,"endpoint-contact",1);
        var text=(address.IsIPv4MappedToIPv6?address.MapToIPv4():address).ToString();
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        WriteContact(c,t,endpoint,text);
        t.Commit();
    }
    private static void WriteContact(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction t,string endpoint,IPAddress? address)
    {
        if(address!=null)WriteContact(c,t,endpoint,(address.IsIPv4MappedToIPv6?address.MapToIPv4():address).ToString());
    }
    private static void WriteContact(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction t,string endpoint,string text)
    {
        using var update=Command(c,t,"UPDATE endpoint_contact SET address=$address,observed=$now WHERE endpoint=$id",("$id",endpoint),("$address",text),("$now",Now()));
        if(update.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO endpoint_contact(endpoint,address,observed) VALUES($id,$address,$now)",("$id",endpoint),("$address",text),("$now",Now()));insert.ExecuteNonQuery();}
    }
}
