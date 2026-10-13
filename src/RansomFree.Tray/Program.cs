using RansomFree;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try
        {
            if(args.Length==2&&args[0]=="--lab-log"){Application.Run(new LabLogTray(args[1]));return;}
            Application.Run(new ReadOnlyTray(args.Contains("--tray")));
        }
        catch(Exception ex){UiMessages.Failure(null,"seQuester could not start.",ex);}
    }
}

internal sealed class ReadOnlyTray:Form
{
    private readonly NotifyIcon icon=new(){Icon=BrandIcon.Load(),Text="seQuester · Read-only",Visible=true};
    private readonly Label status=new(){Dock=DockStyle.Top,Height=85,Padding=new Padding(12)};
    private readonly ListView events=new(){Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true};
    private readonly System.Windows.Forms.Timer timer=new(){Interval=5000};
    private readonly CancellationTokenSource stop=new();
    private readonly HashSet<string> seen=[];
    private bool busy,quit,initial=true;
    private DateTime balloon;
    private string diagnostics="Status not yet available.";
    public ReadOnlyTray(bool trayOnly)
    {
        Text="seQuester · Endpoint activity";Width=1000;Height=600;MinimumSize=new Size(720,450);Font=new Font("Segoe UI",10);Icon=BrandIcon.Load();
        foreach(var item in new[]{("Time",150),("Activity",230),("File",280),("User",170),("Process",230),("PID",80),("Evidence",160)})events.Columns.Add(item.Item1,item.Item2);
        LocalHistorySort.Attach(events,LocalHistorySort.Managed);
        var refresh=new Button{Text="Refresh",Dock=DockStyle.Top,Height=36};refresh.Click+=async(_,_)=>await RefreshActivity();
        var inspect=new Button{Text="Diagnostics",Dock=DockStyle.Top,Height=36};inspect.Click+=(_,_)=>MessageBox.Show(this,diagnostics,"Endpoint diagnostics");
        events.DoubleClick+=(_,_)=>{if(events.SelectedItems.Count==1&&events.SelectedItems[0].Tag is RansomFree.Contracts.AgentConsoleEvent entry)MessageBox.Show(this,$"{entry.Time:G}\n{entry.Operation}\n{entry.Path}\nUser: {entry.User}\nProcess: {entry.Process}\nSource: {entry.Source}","Event evidence");};
        Controls.Add(events);Controls.Add(inspect);Controls.Add(refresh);Controls.Add(status);Controls.Add(new Label{Dock=DockStyle.Bottom,Height=45,Padding=new Padding(10),Text="Latest 100 local events · Read-only. Protection continues when the tray closes."});
        var menu=new ContextMenuStrip();menu.Items.Add("Open",null,(_,_)=>Reveal());menu.Items.Add("Exit tray",null,(_,_)=>{quit=true;Close();});icon.ContextMenuStrip=menu;icon.DoubleClick+=(_,_)=>Reveal();icon.BalloonTipClicked+=(_,_)=>Reveal();
        timer.Tick+=async(_,_)=>await RefreshActivity();Shown+=async(_,_)=>{if(trayOnly)Hide();timer.Start();await RefreshActivity();};
        FormClosing+=(_,e)=>{if(!quit&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};
        FormClosed+=(_,_)=>{stop.Cancel();timer.Stop();timer.Dispose();icon.Visible=false;icon.Dispose();stop.Dispose();};
    }
    private void Reveal(){Show();WindowState=FormWindowState.Normal;Activate();}
    private async Task RefreshActivity()
    {
        if(busy||IsDisposed)return;busy=true;
        try
        {
            var reply=await ManagedAgentConnection.SendAsync(new("status"),stop.Token,readOnly:true);if(IsDisposed)return;
            if(!reply.Success||reply.Status is not {} value){status.Text="Endpoint status unavailable · Protection unconfirmed";diagnostics=reply.Message;events.Items.Clear();return;}
            var capacity=value.QueueCapacity>0?$"/{value.QueueCapacity:N0} ({value.QueuePayloadBytes/1048576d:N1}/{value.QueuePayloadLimitBytes/1048576d:N0} MiB)":"";
            status.Text=$"{RansomFree.Contracts.EndpointStatusText.Health(value.Health)} · {value.CanaryCount} canaries\nUser/process attribution: {(value.AuditConnected?"active":"unavailable")} · Queued alerts: {value.PendingEvents:N0} · Queued syslog: {value.PendingSyslog}";
            diagnostics=$"Agent {value.Version} · Policy {value.PolicyRevision}\nEvent queue: {value.PendingEvents:N0}{capacity}\n{value.Health}";
            events.BeginUpdate();try
            {
                events.Items.Clear();foreach(var entry in value.Events)
                {
                    events.Items.Add(new ListViewItem([entry.Time.ToString("G"),entry.Operation,entry.Path,entry.User,entry.Process,entry.ProcessId?.ToString()??"Unknown",entry.Allowlisted?"Trusted":"Recorded"]){Tag=entry});
                    if(seen.Add(entry.EventId)&&!initial&&!entry.Allowlisted&&!entry.SuppressPopup&&DateTime.UtcNow-balloon>TimeSpan.FromSeconds(5))
                    {icon.ShowBalloonTip(5000,"Canary activity",entry.Operation+"\n"+Path.GetFileName(entry.Path),ToolTipIcon.Warning);balloon=DateTime.UtcNow;}
                }
            }finally{events.EndUpdate();}
            initial=false;if(seen.Count>1000){seen.Clear();foreach(var entry in value.Events)seen.Add(entry.EventId);}
        }
        catch(Exception ex){if(!IsDisposed){status.Text="Agent connection unavailable · Protection unconfirmed";diagnostics=ex.ToString();events.Items.Clear();}}
        finally{busy=false;}
    }
}
