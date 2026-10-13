using System.Runtime.InteropServices;
using System.Text.Json;

namespace RansomFree.LinuxAgent;

// Generates a reviewable shell draft only. Never installs/clears rules or changes auditd.
internal static class AuditRules
{
    public static void Print(bool persistent=false)
    {
        if(!Native.Root)throw new UnauthorizedAccessException("Run the read-only audit rule draft command as root.");
        var config=AuditDispatcher.Read<ClientConfiguration>(Platform.ConfigPath);config.Validate(Platform.DataPath);
        using var input=Native.FileAt(Platform.DataPath+"/canaries.json",false);
        if(input.Length>2097152)throw new InvalidDataException("Inventory exceeds limit.");
        var inventory=JsonSerializer.Deserialize<Canary[]>(input,PrivateState.Json)??throw new InvalidDataException("Inventory unavailable.");
        if(inventory.Length>1000)throw new InvalidDataException("Inventory exceeds canary limit.");
        var paths=inventory.Where(c=>c.Active).Select(c=>Paths.NoLinks(c.Path)).Distinct().Order().ToArray();
        foreach(var path in paths)
        {
            if(!config.Folders.Values.Any(folder=>path.StartsWith(folder.TrimEnd('/')+"/",StringComparison.Ordinal)))throw new InvalidDataException("Canary outside approved folders; no draft generated.");
            if(persistent&&path.Any(c=>!(char.IsAsciiLetterOrDigit(c)||c is '/' or '_' or '-' or '.')))throw new InvalidDataException("Persistent auditctl rules export currently requires ASCII letters/digits, slash, underscore, dash or dot in paths. Use the reviewed shell draft for other names; never strip quoting to force a rules file.");
            using var check=Native.FileAt(path,false);
        }
        static string Quote(string value)=>"'"+value.Replace("'","'\"'\"'")+"'";
        if(!persistent)Console.WriteLine("#!/usr/bin/env bash\n# REVIEW BEFORE EXECUTION. Snapshot of current active canaries, not a live policy.\n# No rule clearing, audit locking, daemon restart or backlog changes.\n# Reconcile after deployment/rotation/replacement; preserve existing Wazuh rules.\nset -euo pipefail");
        var arches=RuntimeInformation.ProcessArchitecture==Architecture.X64?new[]{"b64","b32"}:new[]{"b64"};
        foreach(var path in paths)foreach(var arch in arches)
        {
            var field=persistent?"path="+path:Quote("path="+path);
            var rule=$"always,exit -F arch={arch} -F {field} -F perm=rwa -k {AuditDispatcher.Key}";
            Console.WriteLine((persistent?"-a ":"auditctl -a ")+rule);
            if(!persistent)Console.WriteLine("# Exact inverse for an approved removal: auditctl -d "+rule);
        }
        if(!persistent)Console.WriteLine("# Review auditctl -s and auditctl -l separately; immutable audit configurations need planned maintenance.\n# A syscall permission watch is not proof of copy completion or remote SMB identity.");
    }
}
