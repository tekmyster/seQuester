namespace RansomFree.WindowsDecoys;
public static class DecoyReconciliation
{
    // Fresh native reads only. Does not invoke Repair, Create, SetActive, or trust an action receipt.
    public static VirtualDecoyObservation Observe(string stateDirectory,string root,VirtualDecoyPlan plan)
    {
        if(!File.Exists(Path.Combine(stateDirectory,"virtual-decoys.db")))throw new InvalidDataException("Existing native inventory required; nothing adopted.");
        return new VirtualDecoys(stateDirectory,root).Observe(plan);
    }
}
