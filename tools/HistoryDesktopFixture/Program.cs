using System.Reflection;
using RansomFree;
using RansomFree.Contracts;
internal static class Program
{
    [STAThread] static void Main()
    {
        ApplicationConfiguration.Initialize();var checks=new List<string>();
        void Check(bool yes,string label){if(!yes)throw new Exception(label);checks.Add("PASS: "+label);Console.WriteLine(checks[^1]);}
        using var list=new ListView{View=View.Details};foreach(var title in new[]{"Time","Activity","File","User","Process","PID","Evidence"})list.Columns.Add(title);
        LocalHistorySort.Attach(list,LocalHistorySort.Managed);list.CreateControl();var handle=list.Handle;
        var now=DateTime.UtcNow;var rows=new[]{new AgentConsoleEvent("a",now,"Read","/a","tool2","user2","fixture",false,false){ProcessId=2},new("b",now,"Read","/b","tool10","user10","fixture",false,false){ProcessId=10},new("c",now,"Read","/c","","","fixture",false,false)};
        foreach(var e in rows)list.Items.Add(new ListViewItem([e.Time.ToString(),e.Operation,e.Path,e.User,e.Process,e.ProcessId?.ToString()??"Unknown","Recorded"]){Tag=e});
        var click=typeof(ListView).GetMethod("OnColumnClick",BindingFlags.Instance|BindingFlags.NonPublic)!;
        foreach(var (column,first) in new[]{(3,"b"),(4,"b"),(5,"a")})
        {
            click.Invoke(list,[new ColumnClickEventArgs(column)]);
            Check(((AgentConsoleEvent)list.Items[0].Tag!).EventId==first&&((AgentConsoleEvent)list.Items[2].Tag!).EventId=="c","native ListView ascending text/numeric/null-last column "+column);
            click.Invoke(list,[new ColumnClickEventArgs(column)]);
            Check(((AgentConsoleEvent)list.Items[0].Tag!).EventId==(first=="a"?"b":"a")&&((AgentConsoleEvent)list.Items[2].Tag!).EventId=="c","native ListView descending null-last column "+column);
        }
        Check(list.Columns[3].Text.StartsWith("User")&&list.Columns[4].Text.StartsWith("Process")&&list.Columns[5].Text.StartsWith("PID"),"separate native actor columns remain aligned");
        list.ContextMenuStrip!.Items[5].PerformClick();Check(((AgentConsoleEvent)list.Items[0].Tag!).ProcessId==2,"native keyboard-menu sort routes to numeric comparator");
        var path="D:\\Codex\\RansomFree\\tests\\wsq03-20260914\\desktop-results.txt";File.WriteAllLines(path,checks);Console.WriteLine("Native control fixture only; no packaged desktop, tray service or native sensor UI acceptance.");
    }
}
