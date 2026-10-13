namespace RansomFree;

internal static class CanaryEvidence
{
    public static (int DeployedItems,bool IntegrityHealthy)? Summarize(IEnumerable<string?> states)
    {
        var values=states.ToArray();
        if(values.Any(s=>s is not ("Healthy" or "Content changed / possible encryption" or "Audit rule missing" or "Missing")))return null;
        return (values.Count(s=>s is "Healthy" or "Content changed / possible encryption" or "Audit rule missing"),values.All(s=>s=="Healthy"));
    }
}
