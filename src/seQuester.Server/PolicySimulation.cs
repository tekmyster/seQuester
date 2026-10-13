using Microsoft.AspNetCore.Antiforgery;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed record TrustSimulationRequest(TrustRule[] Rules,TrustContext Context);
public static class PolicySimulation
{
    public static void MapPolicySimulation(this WebApplication app)
    {
        var read=app.MapGroup("/api/v1/console").RequireAuthorization(p=>p.RequireRole("Reader","Operator","Administrator"));
        read.MapGet("/decoy-deployment-types",()=>Results.Ok(new{Version=1,EnabledByDefault=false,Types=DecoyDeploymentCatalog.Types}));
        var simulation=app.MapGroup("/api/v1/console/simulation").RequireAuthorization(p=>p.RequireRole("Administrator"));
        async Task<bool> Csrf(HttpContext c,IAntiforgery csrf){try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}}
        simulation.MapPost("/trust",async(HttpContext c,IAntiforgery csrf,TrustSimulationRequest body)=>
        {
            if(!await Csrf(c,csrf)||body.Rules==null||body.Context==null)return Results.BadRequest();
            try
            {
                // Synthetic scenario only. No self-supplied privileged approval, policy publication,
                // endpoint mutation or decision applied to live telemetry by this API.
                var result=TrustEvaluation.Evaluate(body.Rules,body.Context,DateTimeOffset.UtcNow);
                return Results.Ok(new{Mode="Simulation only",Applied=false,Decision=result});
            }
            catch(ArgumentException){return Results.BadRequest(new{error="Invalid simulation rules or event."});}
        });
        simulation.MapPost("/decoy-deployment",async(HttpContext c,IAntiforgery csrf,DecoyDeploymentRequest body)=>
        {
            if(!await Csrf(c,csrf))return Results.BadRequest();
            try{return Results.Ok(new{Mode="Preview only",Applied=false,Preview=DecoyDeploymentPlanner.Preview(body)});}
            catch(ArgumentException){return Results.BadRequest(new{error="Invalid decoy deployment request."});}
        });
    }
}
