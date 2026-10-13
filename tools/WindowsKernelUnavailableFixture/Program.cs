using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;

// Synthetic wire records test unavailable-evidence handling; these are not
// evidence that a production kernel produced a missing-thread/high-IRQL callback.
var checks = new List<string>();
void Check(bool ok, string label) { if (!ok) throw new InvalidDataException(label); checks.Add(label); }
void U32(byte[] b, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), value);
void U64(byte[] b, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset), value);
void Token(byte[] b, int offset, bool available)
{
    U32(b, offset, available ? 31u : 0u);
    for (var i = 1; i <= 5; i++) U32(b, offset + i * 4, available ? 0u : 0xC00000BBu);
    if (!available) return;
    U32(b, offset + 24, 12); U32(b, offset + 28, 0); U32(b, offset + 32, 16384);
    U32(b, offset + 36, 1); U32(b, offset + 40, 1);
    U64(b, offset + 48, 10); U64(b, offset + 56, 999); U64(b, offset + 64, 20);
    b[offset + 72] = 1; b[offset + 73] = 1; b[offset + 79] = 5; U32(b, offset + 80, 18);
}
byte[] Frame(bool thread, uint irql, bool createAuthorization)
{
    var b = new byte[WindowsKernelDecoder.ExtendedEventBytes];
    U32(b, 0, 5); U32(b, 4, (uint)b.Length); U64(b, 8, 1); U64(b, 16, 1);
    var now = (ulong)DateTimeOffset.UtcNow.ToFileTime();
    U64(b, 24, now); U64(b, 32, now); U64(b, 40, now - 10000000);
    U64(b, 48, 1234); U64(b, 56, thread ? 2345u : 0u);
    // Native flags: THREAD_ABSENT=1, CONTEXT_IRQL=4, SUBJECT_ABSENT=8,
    // IMAGE_ABSENT=16. The fixture deliberately has no executable image text.
    U32(b, 72, 16u | (!thread ? 1u : 0u) | (irql != 0 ? 4u : 0u) | (!createAuthorization ? 8u : 0u));
    U32(b, 76, createAuthorization ? 0u : 3u); U32(b, 88, 0xC0000022);
    U32(b, 92, 1); Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume1\owned\test.bin").CopyTo(b, 240);
    U32(b, 3312, createAuthorization ? 1u : 0u);
    Token(b, 3320, createAuthorization); Token(b, 3464, false); Token(b, 3608, irql == 0);
    U32(b, 3760, 1); U32(b, 3776, irql);
    U32(b, 3780, thread ? 1234u : 0u); U64(b, 3784, 100); U64(b, 3792, 10000000);
    U32(b, 3800, 1); U32(b, 3804, 184); U64(b, 3808, 1); U64(b, 3816, 1);
    Token(b, 3824, false); U32(b, 3980, 1);
    return b;
}
foreach (var (thread, irql, authorization) in new[] { (false, 0u, false), (false, 0u, true), (true, 1u, false), (true, 2u, false) })
{
    var e = WindowsKernelDecoder.Decode(Frame(thread, irql, authorization), new string('a', 32), p => p, false);
    var a = e.Attribution!; var k = a.WindowsKernel!;
    Check(k.IsValid() && WindowsKernelEvidence.Matches(e), "partial envelope retained: " + (thread, irql, authorization));
    Check(!a.CompleteRecordSet && a.Level == "Partial attribution", "missing context never full: " + (thread, irql, authorization));
    Check(k.ThreadImpersonating == null && k.ThreadEffective.Sid == null && k.ThreadEffective.Captured == 0,
        "no impersonation or effective-user fabrication: " + (thread, irql, authorization));
    Check(k.ThreadOwnerStatus == (!thread ? "thread-unavailable" : "irql-not-passive"), "explicit unavailability reason: " + (thread, irql, authorization));
    Check(a.Outcome == "Failed" && a.OsStatus == "0xC0000022" && e.ProcessId == 1234,
        "failure status and known actor PID retained: " + (thread, irql, authorization));
    Check(a.UserSid == (authorization ? "S-1-5-18" : null), "CREATE authorization distinct from unknown thread: " + (thread, irql, authorization));
    var restored = JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(e))!;
    Check(WindowsKernelEvidence.Matches(restored) && restored.Attribution!.WindowsKernel!.ThreadImpersonating == null,
        "serialization preserves unavailable evidence: " + (thread, irql, authorization));
}
foreach (var frame in new[] { Frame(false, 0, false), Frame(true, 2, false) })
{
    Token(frame, 3824, true);
    try { WindowsKernelDecoder.Decode(frame, new string('a', 32), p => p, false); throw new Exception("Contradictory owner accepted"); }
    catch (InvalidDataException) { Check(true, "contradictory thread-owner capture rejected"); }
}
Console.WriteLine(JsonSerializer.Serialize(new { Passed = true, Checks = checks.Count, Scope = "Synthetic decoder/contract regression, not native callback qualification", Cases = checks }));
