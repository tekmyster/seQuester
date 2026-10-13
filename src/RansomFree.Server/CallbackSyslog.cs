using System.Security.Cryptography;
using System.Text;
using RansomFree;

namespace RansomFree
{
    // Actor fields are populated only for relayed endpoint evidence, never inferred from callbacks.
    internal record Alert(DateTime Time,string Operation,string Path,string Process,string User,string Source)
    {
        public string Product {get;init;}="RansomFree";
        public string EventId {get;init;}="";
        public string Machine {get;init;}=Environment.MachineName;
        public string? SourceAddress {get;init;}
        public string? TokenId {get;init;}
        public long CallbackSequence {get;init;}
        public string CanaryName {get;init;}="";
        public string CanaryType {get;init;}="";
        public string Location {get;init;}="";
        public string Description {get;init;}="";
        public string Note {get;init;}="";
        public string Detail {get;init;}="";
        [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public RansomFree.Contracts.ServiceHitContext? ServiceContext {get;init;}
        public string? EndpointId {get;init;}
        public long? EventSequence {get;init;}
        public int? ProcessId {get;init;}
        [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public RansomFree.Contracts.EventAttribution? Attribution {get;init;}
        [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public RansomFree.Contracts.EventTrust? Trust {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public RansomFree.Contracts.ForensicEvidence? Forensics {get;init;}
        [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public int? PolicySyslogSeverity {get;init;}
        // This is a server-validated disposition, including enrichment linked
        // to a suppressed original event. It is not a process safety verdict.
        [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public bool? NotificationSuppressed {get;init;}
        public string ForwardedBy {get;init;}=Environment.MachineName;
    }
}
namespace RansomFree.Server
{
    internal sealed class CallbackDeliveryStatus
    {
        public string Message {get;set;}="Disabled";
        public long LastSentSequence {get;set;}
    }
    internal sealed class CallbackSyslog(CallbackConfiguration callbacks,ServerSyslogConfiguration configuration,ProtectedNotificationFiles files,CallbackDeliveryStatus status,ILogger<CallbackSyslog> logger):BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            try{await Run(ct);}
            catch(OperationCanceledException) when(ct.IsCancellationRequested){}
            catch(Exception ex){status.Message="Worker blocked: "+ex.GetType().Name;logger.LogError("Callback syslog worker unavailable ({Type}); state preserved.",ex.GetType().Name);}
        }
        private async Task Run(CancellationToken ct)
        {
            var checkpoint=files.Resolve("callback-syslog-checkpoint.txt");
            using var lease=new FileStream(files.Resolve("callback-syslog-worker.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            var saved=files.Read<ServerEventSyslogProgress>("callback-syslog-progress.protected");long cursor=saved?.Sequence??0;
            if(saved==null&&File.Exists(checkpoint) && (new FileInfo(checkpoint).Length>64||!long.TryParse(File.ReadAllText(checkpoint),out cursor)||cursor<0))throw new InvalidDataException("Callback delivery checkpoint is invalid; preserved for recovery.");
            if(cursor<0)throw new InvalidDataException("Callback delivery checkpoint is invalid; preserved for recovery.");
            status.LastSentSequence=cursor;status.Message="Waiting for callback activity";
            while(!ct.IsCancellationRequested)
            {
                try
                {
                    var settings=configuration.Read();
                    if(!settings.Destination.Enabled||!settings.CallbackHits||callbacks.Storage==null)
                    {status.Message="Disabled; callback syslog pending hits retained";await Task.Delay(TimeSpan.FromSeconds(5),ct);continue;}
                    var options=settings.Destination;options.Validate();
                    if(settings.CallbackAfterSequence is null)throw new InvalidDataException("Callback syslog activation checkpoint missing.");
                    cursor=Math.Max(cursor,settings.CallbackAfterSequence.Value);
                    files.Write("callback-syslog-progress.protected",new ServerEventSyslogProgress(cursor));status.LastSentSequence=cursor;
                    var hits=callbacks.Storage.Hits(cursor);
                    foreach(var hit in hits)
                    {
                        settings=configuration.Read();if(!settings.Destination.Enabled||!settings.CallbackHits)break;options=settings.Destination;
                        var token=callbacks.Storage.Get(hit.TokenId);
                        var eventId=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(hit.TokenId+":"+hit.Sequence)))[..32].ToLowerInvariant();
                        var alert=new Alert(DateTimeOffset.FromUnixTimeMilliseconds(hit.Received).UtcDateTime,"Canary callback: "+hit.Transport,token?.Name??"Unknown token","Unavailable","Unavailable","Remote callback")
                        {EventId=eventId,SourceAddress=hit.SourceAddress,TokenId=hit.TokenId,CallbackSequence=hit.Sequence,
                            CanaryName=token?.Name??"Unknown token",CanaryType=token?.Type??"Unknown",Location=token?.Location??"",Description=token?.Description??"",Note=token?.Note??"",Detail=hit.Detail};
                        var sent=await SyslogClient.SendAsync(alert,options,ct);
                        files.Write("callback-syslog-progress.protected",new ServerEventSyslogProgress(hit.Sequence));cursor=hit.Sequence;status.LastSentSequence=cursor;status.Message=sent;
                    }
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){status.Message="Delivery pending: "+ex.GetType().Name;logger.LogWarning("Callback syslog delivery failed ({Type}); durable callback inbox retained for retry.",ex.GetType().Name);}
                try{await Task.Delay(TimeSpan.FromSeconds(5),ct);}catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            }
        }
    }
}
