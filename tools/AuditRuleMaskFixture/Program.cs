using System.Runtime.InteropServices;
using RansomFree.LinuxAgent;

// One compilation per process: upstream libaudit rule-parser globals are not
// reentrant. No audit_open, audit_send, netlink socket or kernel rule API exists
// in this fixture. This only builds and inspects a heap-resident rule structure.
if(!OperatingSystem.IsLinux()||args.Length!=2||args[0] is not ("explicit" or "implicit")||args[1] is not ("b64" or "b32")||Environment.GetEnvironmentVariable("SEQUESTER_RULE_MASK_FIXTURE")!="1"||!File.Exists("/.dockerenv"))throw new InvalidOperationException("Isolated Linux fixture only.");
var arguments=new ManagedAuditRule(args[1],"/fixture/nonexistent-canary.xlsx").Arguments;
if(args[0]=="implicit")arguments=arguments.Where((_,i)=>i!=4&&i!=5).ToArray(); // historical dropped -S all
var rule=Native.audit_rule_create_data();if(rule==0)throw new IOException("Native rule allocation failed.");
try
{
    for(var i=2;i<arguments.Length;i+=2)
    {
        int result;
        if(arguments[i]=="-S")result=Native.audit_rule_syscallbyname_data(rule,arguments[i+1]);
        else
        {
            var pair=arguments[i]=="-k"?"key="+arguments[i+1]:arguments[i+1];
            var value=Marshal.StringToCoTaskMemUTF8(pair);
            try{result=Native.audit_rule_fieldpair_data(ref rule,value,4);}
            finally{Marshal.FreeCoTaskMem(value);}
        }
        if(result!=0)throw new IOException("Native in-memory rule compilation failed: "+result);
    }
    // Linux UAPI audit_rule_data starts with flags/action/field_count then
    // AUDIT_BITMASK_SIZE=64 uint32 words; no pointer-sized ABI fields precede it.
    var mask=new int[64];Marshal.Copy(rule+12,mask,0,mask.Length);
    if(args[0]=="explicit")
    {
        if(mask.Any(x=>x!=-1))throw new IOException("Corrected explicit-all command did not preserve all mask bits.");
        Console.WriteLine("PASS: production explicit -S all retained 2048 mask bits for "+args[1]+"; no kernel operation.");
    }
    else
    {
        if(mask.All(x=>x==-1))throw new IOException("Expected legacy unset or inferred mask.");
        var machine=Native.audit_name_to_machine(args[1]=="b64"?"x86_64":"i386");
        if(machine<0)throw new IOException("Machine map unavailable.");
        var names=new List<string>();
        for(var n=0;n<2048;n++)if(((uint)mask[n/32]&(1u<<(n%32)))!=0)names.Add(Marshal.PtrToStringUTF8(Native.audit_syscall_to_name(n,machine))??n.ToString());
        Console.WriteLine("LEGACY: "+args[1]+" count="+names.Count+" syscalls="+string.Join(',',names));
    }
}
finally{if(rule!=0)Native.audit_rule_free_data(rule);}
static class Native
{
    [DllImport("libaudit.so.1")]public static extern nint audit_rule_create_data();
    [DllImport("libaudit.so.1")]public static extern void audit_rule_free_data(nint rule);
    [DllImport("libaudit.so.1")]public static extern int audit_rule_fieldpair_data(ref nint rule,nint field,int flags);
    [DllImport("libaudit.so.1")]public static extern int audit_rule_syscallbyname_data(nint rule,[MarshalAs(UnmanagedType.LPUTF8Str)]string name);
    [DllImport("libaudit.so.1")]public static extern int audit_name_to_machine([MarshalAs(UnmanagedType.LPUTF8Str)]string name);
    [DllImport("libaudit.so.1")]public static extern nint audit_syscall_to_name(int number,int machine);
}
