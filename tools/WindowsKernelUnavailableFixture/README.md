# Unavailable Windows callback context regression

Run with the repository's .NET SDK:

```powershell
dotnet run --project tools/WindowsKernelUnavailableFixture/WindowsKernelUnavailableFixture.csproj --artifacts-path C:/path/to/isolated-artifacts --no-launch-profile
```

The fixture feeds synthetic version 5 native records into the production decoder,
contract validation and JSON round trip. It checks missing callback threads,
non-PASSIVE collection contexts, independent CREATE authorization, retention of
known PID and failed-operation status, explicit unavailable reasons, and rejection
of contradictory token evidence. Unknown impersonation remains null.

These tests do not generate native callbacks or establish that token collection
works in these contexts. The IRQL 2 case is defensive decoder validation, not a
claim that normal minifilter preoperation callbacks run at DISPATCH_LEVEL.

Live failed-operation acceptance must separately verify the actor's native return
code, successful handle opening, later operation, PID plus process birth, thread
ID, process-owner token, effective thread token, and actual server receipt. An
opening event must never be substituted for a missing failed-operation event.
