using RansomFree.Contracts;
using RansomFree.Server;

internal static class StoreChecks
{
    internal static void Run(Action<bool,string> check)
    {
        var root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-advanced-policy-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store=new Store(root);store.InitializeTrustStorage();
        var linux=store.Enroll(new(store.CreateCode().Code,"Linux isolated policy fixture","fixture"))!;
        var windows=store.Enroll(new(store.CreateCode().Code,"Windows isolated policy fixture","fixture"))!;
        var now=DateTimeOffset.UtcNow;
        var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["read"],"log-only",now.AddMinutes(-1),now.AddHours(1))
        {OperatingSystem="windows",Executable=@"C:\QA\reader.exe",Sha256=new string('A',64),Path=@"C:\QA\files",PathMatch="directory",Enabled=true};
        void Blocked(Action action,string code,string name)
        {
            try{action();throw new InvalidDataException("Unexpected policy acceptance: "+name);}
            catch(TrustCapabilityException e){check(e.Code==code,name);}
        }
        void Report(string id,TrustCapabilitiesReport report)
        {check(store.RecordTrustCapabilities(id,report)&&store.RecordNativeHashTrustCapabilities(id,report),"isolated authenticated capability storage: "+report.OperatingSystem);}
        Blocked(()=>store.PublishTrustPolicy(new(0,"enforce",[rule],[],""),"fixture"),"TRUST_PARSER_UPGRADE_REQUIRED","advanced rules cannot publish without sensor parser evidence");
        Report(linux.EndpointId,new(PolicyVersion:4,OperatingSystem:"linux"));
        Report(windows.EndpointId,new(PolicyVersion:3,OperatingSystem:"windows"));
        Blocked(()=>store.PublishTrustPolicy(new(0,"enforce",[rule],[],""),"fixture"),"TRUST_PARSER_UPGRADE_REQUIRED","one old enrolled parser prevents incompatible publication");
        Report(windows.EndpointId,new(PolicyVersion:4,OperatingSystem:"windows"));
        var published=store.PublishTrustPolicy(new(0,"enforce",[rule],[],""),"fixture");
        check(published.Version==4&&store.ReadTrustPolicy().Digest()==published.Digest(),"advanced version 4 policy persists without changing its digest");
        var assigned=store.TrustAssignment(windows.EndpointId);
        check(assigned.Policy.Version==4,"new parser receives advanced assignment");
        check(!store.RecordTrustReceipt(windows.EndpointId,new(1,published.Revision,published.Digest(),null,"enforce"){PolicyVersion=3}),"old parser receipt cannot confirm version 4 policy");
        check(store.RecordTrustReceipt(windows.EndpointId,new(1,published.Revision,published.Digest(),null,"enforce"){PolicyVersion=4}),"matching advanced parser receipt is recorded");
        var hashRule=rule with{Id=Guid.NewGuid().ToString("N"),OperatingSystem="linux",Executable=null,Path=null,PathMatch=null,ProcessMatch=TrustEvaluation.LinuxNativeHashProcessMatch,Actions=["write","append"]};
        Blocked(()=>store.PublishTrustPolicy(new(published.Revision,"enforce",[hashRule],[],""),"fixture"),"TRUST_NATIVE_SOURCE_REQUIRED","parser support alone cannot authorize Linux native hash rules");
        Report(linux.EndpointId,new(PolicyVersion:4,OperatingSystem:"linux"){LinuxNativeHashTrustVersion=1});
        var hashed=store.PublishTrustPolicy(new(published.Revision,"enforce",[hashRule],[],""),"fixture");
        check(hashed.Version==4&&hashed.Rules.Single().ProcessMatch==TrustEvaluation.LinuxNativeHashProcessMatch,"qualified explicit Linux hash rule persists its matching mode");
        Report(linux.EndpointId,new(PolicyVersion:4,OperatingSystem:"linux"));
        Blocked(()=>store.PublishTrustPolicy(new(hashed.Revision,"enforce",[hashRule],[],""),"fixture"),"TRUST_NATIVE_SOURCE_REQUIRED","source capability loss blocks subsequent native-hash publication");
        check(!store.RecordNativeHashTrustCapabilities(Guid.NewGuid().ToString("N"),new(PolicyVersion:4,OperatingSystem:"linux"){LinuxNativeHashTrustVersion=1}),"unenrolled sensor cannot supply native capability");
        check(store.ReadTrustPolicy().Digest()==hashed.Digest(),"rejected policy publication retains the previous persisted policy");
    }
}
