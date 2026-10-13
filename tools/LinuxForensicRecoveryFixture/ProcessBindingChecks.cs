using System.ComponentModel;
using System.Text.Json;
using RansomFree.Client.Forensics;

static class ProcessBindingChecks
{
    internal static void Run()
    {
        int checks=0;
        void Check(bool value,string name){if(!value)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
        void Reject(string? supplied,string current,DateTimeOffset birth,DateTimeOffset observed,string reason)
        {
            try{LinuxProcessBindingException.RequireStart(supplied,current,birth,observed);throw new Exception("Unsafe process binding accepted");}
            catch(LinuxProcessBindingException ex)
            {
                var status=ActorLease.FailedField("actor-capture-failed",ex);
                Check(status.State=="unavailable"&&status.Reason==reason,"binding failure retains distinct reason: "+reason);
                Check(JsonSerializer.Serialize(status).Contains(reason,StringComparison.Ordinal),"collection reason survives wire serialization");
            }
        }
        var eventTime=DateTimeOffset.Parse("2026-10-09T18:17:11.288Z");
        Reject(null,"204524453",eventTime.AddMilliseconds(5),eventTime,LinuxProcessBindingException.StartAmbiguous);
        // A matching PID is insufficient even when its replacement is older than the event.
        Reject("204524400","204524453",eventTime.AddSeconds(-1),eventTime,LinuxProcessBindingException.StartMismatch);
        LinuxProcessBindingException.RequireStart(null,"204524453",eventTime.AddMilliseconds(-90),eventTime);
        Check(true,"mature audit actor remains eligible");
        LinuxProcessBindingException.RequireStart("204524453","204524453",eventTime.AddMilliseconds(5),eventTime);
        Check(true,"event-time start identity remains authoritative over coarse wall-clock estimate");
        foreach(var reason in new[]{LinuxProcessBindingException.ImageMismatch,LinuxProcessBindingException.ChangedDuringCapture})
        {
            var status=ActorLease.FailedField("actor-capture-failed",new LinuxProcessBindingException(reason));
            Check(status.State=="unavailable"&&status.Reason==reason,"image race has explicit collection status: "+reason);
        }
        var native=ActorLease.FailedField("actor-capture-failed",new Win32Exception(13));
        Check(native.Reason=="actor-capture-failed"&&native.NativeCode=="13","raw OS permission error remains intact");
        var generic=ActorLease.FailedField("other-field-unavailable",new InvalidOperationException(LinuxProcessBindingException.StartAmbiguous));
        Check(generic.Reason=="other-field-unavailable","arbitrary exception text cannot assert a typed collection reason");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Actual process birth acceptance and collection-status serialization components; no native hook or endpoint deployment qualification."}));
    }
}
