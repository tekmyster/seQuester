using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using RansomFree.Server;
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","service-email-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool condition,string label){if(!condition)throw new Exception(label);checks.Add("PASS: "+label);Console.WriteLine(checks[^1]);File.WriteAllLines(Path.Combine(root,"results.txt"),checks);}
var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["RF_DATA_DIR"]=root}).Build();var protector=new EphemeralDataProtectionProvider();var files=new ProtectedNotificationFiles(config,protector);var store=new Store(root);store.InitializeDecoyServiceStorage();
var definition=new DecoyServiceChange("Synthetic payroll","No real data",false,0,"unused"){RequestId=Guid.NewGuid().ToString("N"),Location="Finance lab",Note="Synthetic fixture\nContact the lab owner"};var resource=store.CreateDecoyService(definition,"fixture");store.ChangeDecoyService(resource.Service.Id,definition with{Enabled=true,ExpectedRevision=1},"fixture");void Touch()=>store.TouchDecoyService(resource.Service.Id,resource.ActivationPath.Split('/')[^1],"127.0.0.1","GET");
var configuration=new CallbackEmailConfiguration(files);var transport=new FakeTransport();var status=new ServiceEmailStatus();var pump=new ServiceEmailPump(store,configuration,files,transport,status);
Check(!configuration.Read().ServiceHits,"service email defaults off");
Touch();await pump.Step(default);Check(transport.Sent.Count==0,"disabled email sends nothing and evidence remains");
var body=new SaveCallbackEmailBody(0,true,"smtp.example.invalid",587,"alerts@example.invalid",["first@example.invalid","second@example.invalid"],"",null,false,"[seQuester]",1,"unused"){ServiceHits=true};
var saved=configuration.Save(body,null,store);await pump.Step(default);Check(transport.Sent.Count==0&&saved.ServiceStartAfterSequence==1,"first enable sets future-hit checkpoint without replaying old hits");
Touch();transport.Fail="second@example.invalid";var failed=false;try{await pump.Step(default);}catch(IOException){failed=true;}var pending=files.Read<EmailProgress>("service-email-progress.protected")!;
Check(failed&&pending.Sequence==1&&pending.PendingSequence==2&&pending.AcceptedRecipients!.SequenceEqual(["first@example.invalid"]),"partial recipient acceptance persists without advancing event checkpoint");
transport.Fail=null;var reopenedFiles=new ProtectedNotificationFiles(config,protector);pump=new(store,new CallbackEmailConfiguration(reopenedFiles),reopenedFiles,transport,status);await pump.Step(default);
Check(transport.Sent.Count==2&&transport.Sent.Select(x=>x.Recipient).Distinct().Count()==2,"restart resumes only the unaccepted recipient");
Check(reopenedFiles.Read<EmailProgress>("service-email-progress.protected")!.Sequence==2,"all recipients accepted before event checkpoint advances");
Check(transport.Sent.All(x=>x.Body.Contains("Synthetic payroll")&&x.Body.Contains("No real data")&&x.Body.Contains("Source address: 127.0.0.1")&&x.Body.Contains("not a verified user or process")),"email includes saved context and honest actor-evidence boundary");
Check(transport.Sent.All(x=>x.Body.Contains("Location: Finance lab")&&x.Body.Contains("Note: Synthetic fixture\nContact the lab owner")),"email retains location and multiline note");
configuration.Save(body with{ExpectedRevision=1,Enabled=false,ServiceHits=false},null,store);Touch();await pump.Step(default);Check(transport.Sent.Count==2&&store.ServiceEvents(2).Count==1,"pause retains unsent service evidence");
configuration.Save(body with{ExpectedRevision=2},null,store);await pump.Step(default);Check(transport.Sent.Count==4&&reopenedFiles.Read<EmailProgress>("service-email-progress.protected")!.Sequence==3,"reenabling sends pending hits instead of discarding them");
files.Write("service-email-progress.protected",new EmailProgress(3,99,[]));failed=false;try{await pump.Step(default);}catch(InvalidDataException){failed=true;}Check(failed&&files.Read<EmailProgress>("service-email-progress.protected")!.PendingSequence==99,"missing pending evidence blocks without overwriting recovery state");
Console.WriteLine(root);Console.WriteLine("Fake transport only; no SMTP server contacted, no TLS/mailbox delivery acceptance.");
var syslogConfiguration=new ServerSyslogConfiguration(files,config);var callbackConfiguration=new CallbackConfiguration(config);var syslogStatus=new ServiceSyslogStatus();var syslogTransport=new FakeSyslogTransport();var syslogPump=new ServiceSyslogPump(store,syslogConfiguration,files,syslogStatus,syslogTransport);
await syslogPump.Step(default);Check(syslogTransport.Sent.Count==0,"service syslog defaults off");
var syslogBody=new SaveServerSyslogBody(0,new RansomFree.SyslogOptions{Enabled=true,Host="collector.example.invalid",Port=514,Transport="TCP"},false,false,"unused"){ServiceHits=true};
var syslogSettings=syslogConfiguration.Save(syslogBody,store,callbackConfiguration);await syslogPump.Step(default);
Check(syslogSettings.ServiceAfterSequence==3&&syslogStatus.LastSentSequence==3&&syslogTransport.Sent.Count==0,"service syslog first enable selects future evidence and reports its saved checkpoint");
Touch();syslogTransport.Fail=true;failed=false;try{await syslogPump.Step(default);}catch(IOException){failed=true;}
Check(failed&&files.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")!.Sequence==3&&syslogTransport.Sent.Count==0,"failed service syslog send retains source evidence and checkpoint");
syslogTransport.Fail=false;syslogPump=new ServiceSyslogPump(new Store(root),new ServerSyslogConfiguration(reopenedFiles,config),reopenedFiles,syslogStatus,syslogTransport);await syslogPump.Step(default);
Check(syslogTransport.Sent.Count==1&&syslogTransport.Sent[0].Alert.EventId==store.ServiceEvents(3).Single().Event.EventId&&files.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")!.Sequence==4,"service relay restart resumes the durable event identity");
Check(syslogTransport.Sent[0].Alert is {Location:"Finance lab",Note:"Synthetic fixture\nContact the lab owner",EndpointId:null,ProcessId:null},"service syslog retains meaningful context without a fabricated endpoint or PID");
syslogConfiguration.Save(syslogBody with{ExpectedRevision=1,ServiceHits=false,Destination=new(){Enabled=false}},store,callbackConfiguration);Touch();await syslogPump.Step(default);Check(syslogTransport.Sent.Count==1&&store.ServiceEvents(4).Count==1,"paused service relay preserves pending evidence");
syslogConfiguration.Save(syslogBody with{ExpectedRevision=2,Destination=new(){Enabled=true,Host="replacement.example.invalid",Port=514,Transport="TCP"}},store,callbackConfiguration);await syslogPump.Step(default);
Check(syslogTransport.Sent.Count==2&&syslogTransport.Sent[1].Host=="replacement.example.invalid"&&syslogStatus.LastSentSequence==5,"reenabling service relay uses the configured destination for pending work");
files.Write("service-syslog-progress.protected",new ServerEventSyslogProgress(-1));failed=false;try{await syslogPump.Step(default);}catch(InvalidDataException){failed=true;}
Check(failed&&files.Read<ServerEventSyslogProgress>("service-syslog-progress.protected")!.Sequence== -1,"invalid relay checkpoint remains preserved for recovery");
Console.WriteLine(root);Console.WriteLine("Fake syslog transport only; no collector, Wazuh, TCP or TLS delivery acceptance.");
// A restored older database must not silently accept a checkpoint from its future.
files.Write("service-syslog-progress.protected",new ServerEventSyslogProgress(500));
var relayBytes=File.ReadAllBytes(files.Resolve("service-syslog-progress.protected"));failed=false;
try{await syslogPump.Step(default);}catch(InvalidDataException){failed=true;}
Check(failed&&relayBytes.SequenceEqual(File.ReadAllBytes(files.Resolve("service-syslog-progress.protected"))),"ahead-of-evidence relay checkpoint is rejected and preserved byte-for-byte");
files.Write("service-email-progress.protected",new EmailProgress(500));
var emailBytes=File.ReadAllBytes(files.Resolve("service-email-progress.protected"));failed=false;
try{await pump.Step(default);}catch(InvalidDataException){failed=true;}
Check(failed&&emailBytes.SequenceEqual(File.ReadAllBytes(files.Resolve("service-email-progress.protected"))),"ahead-of-evidence email checkpoint is rejected and preserved byte-for-byte");
// Restore known valid fixture checkpoints, then prove the unchanged evidence can drain.
files.Write("service-syslog-progress.protected",new ServerEventSyslogProgress(5));
files.Write("service-email-progress.protected",new EmailProgress(3));Touch();
await syslogPump.Step(default);await pump.Step(default);
Check(syslogStatus.LastSentSequence==6&&files.Read<EmailProgress>("service-email-progress.protected")!.Sequence==6,"restoring valid checkpoints resumes both delivery paths without losing durable evidence");
await NetworkChecks.Run(root,Check);
SqlChecks.Run(Check);
sealed class FakeTransport:IEmailTransport
{
    public string? Fail;public List<(string Recipient,string Subject,string Body)> Sent=[];
    public Task Send(CallbackEmailSettings settings,string recipient,string subject,string body,CancellationToken ct){if(recipient==Fail)throw new IOException("Synthetic relay failure");Sent.Add((recipient,subject,body));return Task.CompletedTask;}
}
sealed class FakeSyslogTransport:IServiceSyslogTransport
{
    public bool Fail;public List<(RansomFree.Alert Alert,string Host)> Sent=[];
    public Task<string> Send(RansomFree.Alert alert,RansomFree.SyslogOptions destination,CancellationToken ct){if(Fail)throw new IOException("Synthetic send failure");Sent.Add((alert,destination.Host));return Task.FromResult("TCP sent to fixture; collector persistence is unconfirmed.");}
}
