using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class RawCapacityChecks
{
    internal static void Run(string root)
    {
        var checks=new List<string>();
        void Check(bool value,string name){if(!value)throw new Exception(name);checks.Add(name);}
        const string sensor="f32ed917e32f466e996ff0a2ccd57980";
        byte[] Bytes(long quota)=>JsonSerializer.SerializeToUtf8Bytes(new LinuxNativeRawStorageCapacity.Definition(1,sensor,quota));
        void Refuse(Action action,string name){try{action();}catch(Exception e)when(e is IOException or InvalidDataException or System.ComponentModel.Win32Exception){Check(true,name);return;}throw new Exception("Accepted "+name);}
        Check(LinuxNativeRawStorageCapacity.Parse(Bytes(512L*1024*1024),sensor)==512L*1024*1024,"original default capacity retained");
        Check(LinuxNativeRawStorageCapacity.Parse(Bytes(2L*1024*1024*1024),sensor)==2L*1024*1024*1024,"explicit bounded two GiB accepted");
        Check(LinuxNativeRawStorageCapacity.Parse(Bytes(8L*1024*1024*1024),sensor)==8L*1024*1024*1024,"upper bound accepted");
        foreach(var value in new[]{-1L,0,512L*1024*1024-1,512L*1024*1024+1,8L*1024*1024*1024+1,long.MaxValue})
            Refuse(()=>LinuxNativeRawStorageCapacity.Parse(Bytes(value),sensor),"invalid capacity refused "+value);
        var text=Encoding.UTF8.GetString(Bytes(2L*1024*1024*1024));
        foreach(var value in new[]{"null","{}",text+"\n",text.Replace("\"Version\":1","\"Version\":2"),text.Replace(sensor,new string('a',32)),text.Replace("\"Version\":1","\"Version\":1,\"Version\":1"),text.Replace("\"Version\":1","\"Version\":1,\"Unknown\":1"),text.Replace("2147483648","\"2147483648\""),"{"})
            Refuse(()=>LinuxNativeRawStorageCapacity.Parse(Encoding.UTF8.GetBytes(value),sensor),"noncanonical missing duplicate mismatched or malformed definition refused");
        Refuse(()=>LinuxNativeRawStorageCapacity.Parse(new byte[4097],sensor),"oversized metadata refused");
        if(OperatingSystem.IsLinux())
        {
            EvidenceStore.EnsurePrivate(root);
            using var directory=LinuxProtectedDirectory.OpenRoot(root);
            Check(LinuxNativeRawStorageCapacity.Read(directory,sensor)==LinuxNativeRawStorageCapacity.DefaultBytes,"absent capacity file preserves installed default");
            var config=Path.Combine(root,LinuxNativeRawStorageCapacity.FileName);
            File.WriteAllBytes(config,Bytes(2L*1024*1024*1024));File.SetUnixFileMode(config,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            Check(LinuxNativeRawStorageCapacity.Read(directory,sensor)==2L*1024*1024*1024,"actual protected root file accepted");
            File.SetUnixFileMode(config,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead);
            Refuse(()=>LinuxNativeRawStorageCapacity.Read(directory,sensor),"group-readable override refused");
            File.SetUnixFileMode(config,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            File.Move(config,config+".retained");File.CreateSymbolicLink(config,config+".retained");
            Refuse(()=>LinuxNativeRawStorageCapacity.Read(directory,sensor),"symlink override refused");File.Delete(config);File.Move(config+".retained",config);
            var banks=new List<(string Path,long Length,DateTime Modified)>();
            const long bankBytes=4096L+257L*(128+131072);
            for(var n=0;n<15;n++)
            {
                var folder=Path.Combine(root,"source-"+n,"raw");EvidenceStore.EnsurePrivate(folder);var path=Path.Combine(folder,"raw-ingress-v3.bin");
                using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write)){file.SetLength(bankBytes);file.Flush(true);}
                File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);banks.Add((path,new FileInfo(path).Length,File.GetLastWriteTimeUtc(path)));
            }
            Refuse(()=>{using var prepared=LinuxRawIngressReserve.Prepare(Path.Combine(root,"source-default-refused","raw"),sensor,Guid.NewGuid().ToString("N"),256,quotaDirectory:root);},"retained fifteen banks still exhaust unchanged 512 MiB quota");
            var budget=LinuxNativeRawStorageCapacity.Read(directory,sensor);
            using(var prepared=LinuxRawIngressReserve.Prepare(Path.Combine(root,"source-expanded","raw"),sensor,Guid.NewGuid().ToString("N"),256,quotaDirectory:root,quotaBytes:budget))
            {
                Check(prepared.PhysicalAllocationEstablished&&prepared.Identity.Size==bankBytes,"bounded root override physically reserves next bank without loader activation");
                using var bank=new LinuxRawIngressReserve(prepared,"123");
                var journalRoot=Path.Combine(root,"registered-budget-fixture");
                using var journal=new LinuxForensicJournal(journalRoot,sensor);
                // Synthetic historical accounting rows exercise the actual SQL
                // quota gate, not native or historical-recovery qualification.
                using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(journalRoot,"linux-forensic-intake","journal.db"),Pooling=false}.ToString()))
                {
                    c.Open();using var transaction=c.BeginTransaction();
                    for(var n=0;n<15;n++)
                    {
                        using var q=c.CreateCommand();q.Transaction=transaction;q.CommandText="INSERT INTO source_banks VALUES($id,$path,$stable,$bytes)";
                        q.Parameters.AddWithValue("$id",Guid.NewGuid().ToString("N"));q.Parameters.AddWithValue("$path",banks[n].Path);q.Parameters.AddWithValue("$stable","synthetic-budget-fixture:"+n);q.Parameters.AddWithValue("$bytes",bankBytes);q.ExecuteNonQuery();
                    }
                    transaction.Commit();
                }
                journal.AdmitOwnedRuntime();
                Refuse(()=>journal.PrepareControlledSource(bank,new ForensicPolicy(),"0",DateTimeOffset.UtcNow,LinuxNativeRawStorageCapacity.DefaultBytes),"registered journal quota still refuses original 512 MiB after physical bank allocation");
                var source=journal.PrepareControlledSource(bank,new ForensicPolicy(),"0",DateTimeOffset.UtcNow,budget);
                Check(source.State=="OPEN","same configured capacity admits actual registered journal gate");
                journal.RecordSourceNoController(source.Id,null,DateTimeOffset.UtcNow);
                Check(journal.ReadSource(source.Id).State=="CLOSED","fixture journal records actual no-controller terminal boundary");
                journal.ReleaseOwnedRuntime(source.Id);
            }
            Check(banks.All(b=>new FileInfo(b.Path).Length==b.Length&&File.GetLastWriteTimeUtc(b.Path)==b.Modified),"all historical bank lengths and modification times unchanged");
            Check(new FileInfo(Path.Combine(root,"source-expanded","raw","raw-ingress-v3.bin")).Length==bankBytes,"new reservation retained after disposal");
        }
        var result=new{Passed=true,Checks=checks.Count,Details=checks,LinuxStorageChecks=OperatingSystem.IsLinux(),NativeActivation=false,Scope="Bounded metadata and isolated synthetic raw bank storage tests; no evidence retirement or capacity-independent recovery claim"};
        if(Directory.Exists(root))File.WriteAllBytes(Path.Combine(root,"RESULTS.json"),JsonSerializer.SerializeToUtf8Bytes(result));
        Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
