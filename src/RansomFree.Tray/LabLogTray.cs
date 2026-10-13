using System.Text.Json;
using RansomFree;

// Explicit development-only log observer. Does not impersonate installed-agent IPC or offer response controls.
internal sealed class LabLogTray:Form
{
    private readonly string directory;
    private readonly NotifyIcon icon=new(){Icon=BrandIcon.Load(),Text="seQuester · Lab observer",Visible=true};
    private readonly ListBox entries=new(){Dock=DockStyle.Fill,HorizontalScrollbar=true};
    private readonly Label status=new(){Dock=DockStyle.Top,Height=65,Text="Lab observer · Protection unverified"};
    private readonly System.Windows.Forms.Timer timer=new(){Interval=3000};
    private readonly HashSet<string> seen=[];
    private bool initial=true,quit;
    private DateTime balloon;
    public LabLogTray(string directory)
    {
        if(!Path.IsPathFullyQualified(directory)||!Directory.Exists(directory))throw new ArgumentException("Select an existing absolute lab log directory.");
        this.directory=Path.GetFullPath(directory);ValidatePath(this.directory);
        Text="seQuester · Lab activity";Width=1000;Height=550;Icon=BrandIcon.Load();Controls.Add(entries);Controls.Add(status);
        var menu=new ContextMenuStrip();menu.Items.Add("Open activity",null,(_,_)=>{Show();Activate();});
        menu.Items.Add("Open WebUI",null,(_,_)=>System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("http://127.0.0.1:18080/"){UseShellExecute=true}));
        menu.Items.Add("Exit lab observer",null,(_,_)=>{quit=true;Close();});icon.ContextMenuStrip=menu;icon.DoubleClick+=(_,_)=>{Show();Activate();};
        timer.Tick+=(_,_)=>RefreshLog();Shown+=(_,_)=>{Hide();RefreshLog();timer.Start();};
        FormClosing+=(_,e)=>{if(!quit&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};
        FormClosed+=(_,_)=>{timer.Stop();timer.Dispose();icon.Visible=false;icon.Dispose();};
    }
    private static void ValidatePath(string path)
    {for(string? current=path;current!=null;current=Path.GetDirectoryName(current))if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new IOException("Lab observer refuses linked paths.");}
    private void RefreshLog()
    {
        try
        {
            var path=Path.Combine(directory,"activity.jsonl");ValidatePath(directory);
            if(!File.Exists(path)){status.Text="Waiting for lab activity · Protection unverified";return;}
            ValidatePath(path);if(new FileInfo(path).Length>6000000)throw new IOException("Log exceeds observer bound.");
            foreach(var line in File.ReadLines(path).TakeLast(100))
            {
                JsonDocument document;try{document=JsonDocument.Parse(line);}catch(JsonException){continue;}
                using(document)
                {
                    var data=document.RootElement;var id=data.GetProperty("EventId").GetString()!;
                    if(!seen.Add(id))continue;
                    var operation=data.GetProperty("Operation").GetString()!;var file=data.GetProperty("Path").GetString()!;
                    entries.Items.Insert(0,$"{data.GetProperty("Time").GetString()} | {operation} | {file} | {data.GetProperty("User").GetString()} | {data.GetProperty("Process").GetString()}");
                    if(!initial&&DateTime.UtcNow-balloon>TimeSpan.FromSeconds(5))
                    {
                        icon.ShowBalloonTip(5000,"Canary activity",operation+"\n"+Path.GetFileName(file),ToolTipIcon.Warning);balloon=DateTime.UtcNow;
                        var receipt=Path.Combine(directory,"lab-notifications.log");if(File.Exists(receipt))ValidatePath(receipt);
                        File.AppendAllText(receipt,DateTimeOffset.UtcNow.ToString("O")+" Balloon requested for "+id+Environment.NewLine);
                    }
                }
            }
            while(entries.Items.Count>200)entries.Items.RemoveAt(entries.Items.Count-1);
            status.Text="Lab activity loaded · Protection unverified";
            initial=false;if(seen.Count>2000)seen.Clear();
        }
        catch(Exception ex){status.Text="Lab observer unavailable: "+ex.GetType().Name;}
    }
}
