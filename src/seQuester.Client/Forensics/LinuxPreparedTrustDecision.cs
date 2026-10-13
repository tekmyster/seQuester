using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// No emission or persistence here. Begin has already allocated the original
// collector/process sequence once. Only Trust and Detection may be added.
internal static class LinuxPreparedTrustDecision
{
    internal sealed record Result(AgentEvent Event,string Reason);
    internal static Result Apply(AgentEvent provisional,ActorLease actor,Func<AgentEvent,ActorLease,EventTrust?> evaluate)
    {
        if(provisional.Trust!=null||provisional.Forensics is not {} f||f.RelatedEventId!=null||provisional.Source!="Linux kernel")
            throw new InvalidDataException("Uncommitted Linux original required for trust preparation");
        var frozen=JsonSerializer.SerializeToUtf8Bytes(provisional);
        var inputBytes=JsonSerializer.SerializeToUtf8Bytes(LinuxKernelTrustBinding.PolicyInput(provisional));
        var input=JsonSerializer.Deserialize<AgentEvent>(inputBytes)!;
        try
        {
            var decision=evaluate(input,actor);
            // A callback cannot change its inputs or a shared array inside the
            // original. The recovery fallback uses bytes frozen before it ran.
            if(!inputBytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(input))||
                !frozen.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(provisional)))
                throw new InvalidDataException("Linux policy input changed during preparation");
            if(decision==null)
            {
                var unavailable=JsonSerializer.Deserialize<AgentEvent>(frozen)!;
                return new(unavailable with{Forensics=unavailable.Forensics! with{Detection=unavailable.Forensics.Detection with{
                    ReasonCodes=[..unavailable.Forensics.Detection.ReasonCodes,"LINUX_TRUST_NOT_AVAILABLE"]}}},"LINUX_TRUST_NOT_AVAILABLE");
            }
            var trust=JsonSerializer.Deserialize<EventTrust>(JsonSerializer.SerializeToUtf8Bytes(decision))!;
            if(trust.Version is not (3 or 4)||!trust.IsValid()||(trust.Version==3?trust.LinuxKernelBinding?.Matches(input)!=true:trust.LinuxNativeHashBinding?.Matches(input)!=true))
                throw new InvalidDataException("Linux policy result is inconsistent with its original input");
            var retained=JsonSerializer.Deserialize<AgentEvent>(frozen)!;
            var final=retained with{Trust=trust,Forensics=retained.Forensics! with{Detection=ForensicCollector.DetectionFor(trust)}};
            if(!LinuxKernelTrustBinding.InputDigest(final).Equals(LinuxKernelTrustBinding.InputDigest(retained),StringComparison.Ordinal)||
                (trust.Version==3?!trust.LinuxKernelBinding!.Matches(final):!trust.LinuxNativeHashBinding!.Matches(final)))throw new InvalidDataException("Linux prepared evidence changed outside Trust/Detection");
            return new(final,"LINUX_TRUST_DECISION_PREPARED");
        }
        catch(Exception ex)when(ex is not OutOfMemoryException)
        {
            var retained=JsonSerializer.Deserialize<AgentEvent>(frozen)!;
            return new(retained with{Forensics=retained.Forensics! with{Detection=retained.Forensics.Detection with{
                ReasonCodes=[..retained.Forensics.Detection.ReasonCodes,"LINUX_TRUST_PREPARATION_FAILED"]}}},"LINUX_TRUST_PREPARATION_FAILED:"+ex.GetType().Name);
        }
    }
}
