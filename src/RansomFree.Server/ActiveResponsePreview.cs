using RansomFree.Contracts;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;

namespace RansomFree.Server;

public sealed record PreviewActiveResponseBody(long EventSequence,string[] Actions,string AccountPrincipal="effective-user");
public sealed partial class Store
{
    public ActiveResponsePreview? PreviewActiveResponse(PreviewActiveResponseBody body)
    {
        var request=new ActiveResponsePolicy{Actions=body.Actions,AccountPrincipal=body.AccountPrincipal};if(body.EventSequence<=0||!request.IsValid())throw new ArgumentException("Choose supported actions and user context.");
        using var c=Open();using var command=Command(c,null,"SELECT e.endpoint,e.payload FROM events e JOIN endpoints p ON p.id=e.endpoint WHERE e.sequence=$sequence AND p.revoked=0",("$sequence",body.EventSequence));using var row=command.ExecuteReader();
        if(!row.Read())return null;var sensor=row.GetString(0);var evidence=JsonSerializer.Deserialize<AgentEvent>(row.GetString(1))!;row.Close();
        var configured=Assigned(sensor).Settings.ActiveResponse??new ActiveResponsePolicy();var policy=configured with{Actions=body.Actions,AccountPrincipal=body.AccountPrincipal};
        // Completion is used only for preservation verification, never to replace
        // the original operation's process/thread identity with later metadata.
        if(evidence.Forensics is {} original)
        {
            var json=sqlServer?"JSON_VALUE":"json_extract";
            using var completions=Command(c,null,$"SELECT payload FROM events WHERE endpoint=$endpoint AND {json}(payload,'$.Source')='Forensic enrichment' AND {json}(payload,'$.Forensics.RelatedEventId')=$event ORDER BY sequence DESC LIMIT 100",("$endpoint",sensor),("$event",evidence.EventId));using var rows=completions.ExecuteReader();
            while(rows.Read())
            {
                var enriched=JsonSerializer.Deserialize<AgentEvent>(rows.GetString(0));
                if(enriched!=null){evidence=ActiveResponseEvidence.AttachPreservation(evidence,enriched);if(evidence.Forensics?.Preservation.Status.State=="captured")break;}
            }
        }
        var preview=ActiveResponseEvidence.Preview(sensor,evidence,policy,DateTimeOffset.UtcNow);
        if(body.Actions.Any(action=>action!="end-process")||configured.Mode=="automatic"||evidence.Source!="Windows minifilter")preview=preview with{Reasons=[..preview.Reasons,"RESPONSE_ADAPTER_NOT_QUALIFIED"]};
        if(configured.Mode!="observe"&&body.Actions.Any(action=>!configured.Actions.Contains(action)))preview=preview with{Reasons=[..preview.Reasons,"RESPONSE_ACTION_NOT_ENABLED"]};
        if(configured.Mode!="observe"&&body.AccountPrincipal!=configured.AccountPrincipal)preview=preview with{Reasons=[..preview.Reasons,"RESPONSE_PRINCIPAL_NOT_ENABLED"]};
        return preview;
    }
}
public static partial class HumanIdentity
{
    public static void MapActiveResponsePreview(this WebApplication app)
    {
        app.MapPost("/api/v1/console/responses/preview",async(HttpContext context,IAntiforgery csrf,PreviewActiveResponseBody body,Store store)=>
        {
            if(!await Csrf(context,csrf))return Results.BadRequest();
            try{return store.PreviewActiveResponse(body) is {} preview?Results.Ok(preview):Results.NotFound();}
            catch(ArgumentException){return Results.BadRequest(new{error="Choose supported response actions and user context."});}
        }).RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
    }
}
