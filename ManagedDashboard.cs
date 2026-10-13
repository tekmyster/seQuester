using RansomFree.Contracts;

namespace RansomFree;

internal sealed class ManagedDashboard:Form
{
    private readonly NotifyIcon tray=new(){Icon=BrandIcon.Load(),Text="seQuester · Managed agent",Visible=true};
    private readonly Label status=new(){Dock=DockStyle.Top,Height=75,Padding=new Padding(16)};
    private readonly ListView events=new(){Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true};
    private readonly System.Windows.Forms.Timer timer=new(){Interval=5000};
    private readonly CancellationTokenSource stop=new();
    private readonly HashSet<string> seen=[];
    private bool busy,quit,initial=true;
    private DateTime lastBalloon;
    private string diagnostics="Status not yet available.";
    public ManagedDashboard(bool trayOnly)
    {
        Text="seQuester · Managed endpoint";Width=1100;Height=650;MinimumSize=new Size(800,500);Font=new Font("Segoe UI",10);Icon=BrandIcon.Load();
        var actions=new FlowLayoutPanel{Dock=DockStyle.Top,Height=50,Padding=new Padding(12,5,5,5)};
        var refresh=new Button{Text="Refresh",AutoSize=true};var end=new Button{Text="End selected process…",AutoSize=true};var inspect=new Button{Text="Diagnostics",AutoSize=true};inspect.Click+=(_,_)=>MessageBox.Show(this,diagnostics,"Endpoint diagnostics");actions.Controls.AddRange([refresh,end,inspect]);
        foreach(var column in new[]{("Time",150),("Activity",250),("File",300),("User",180),("Process",230),("PID",80),("Evidence",160)})events.Columns.Add(column.Item1,column.Item2);
        LocalHistorySort.Attach(events,LocalHistorySort.Managed);
        Controls.Add(events);Controls.Add(actions);Controls.Add(status);Controls.Add(new Label{Dock=DockStyle.Bottom,Height=48,Padding=new Padding(12,5,5,5),Text="Latest 100 local events · Managed endpoint. Protection continues when the tray closes."});
        var menu=new ContextMenuStrip();menu.Items.Add("Open seQuester",null,(_,_)=>Reveal());menu.Items.Add("Exit tray",null,(_,_)=>{quit=true;Close();});tray.ContextMenuStrip=menu;tray.DoubleClick+=(_,_)=>Reveal();tray.BalloonTipClicked+=(_,_)=>Reveal();
        events.DoubleClick+=(_,_)=>{if(events.SelectedItems.Count==1&&events.SelectedItems[0].Tag is AgentConsoleEvent item)MessageBox.Show(this,$"{item.Time:G}\n{item.Operation}\n{item.Path}\nUser: {item.User}\nProcess: {item.Process}\nSource: {item.Source}","Event evidence");};
        refresh.Click+=async(_,_)=>await RefreshAsync();timer.Tick+=async(_,_)=>await RefreshAsync();
        end.Click+=async(_,_)=>
        {
            if(busy || events.SelectedItems.Count!=1 || events.SelectedItems[0].Tag is not AgentConsoleEvent item)return;
            if(!item.CanEndProcess){MessageBox.Show(this,"Select a recent event with an available, untrusted process.");return;}
            if(MessageBox.Show(this,"Stop this process? Unsaved work can be lost.","Confirm process response",MessageBoxButtons.OKCancel,MessageBoxIcon.Warning)!=DialogResult.OK)return;
            var password=PasswordLock.Prompt(this,"Agent administration","Enter the agent administration password.");if(password==null)return;
            busy=true;try{var reply=await ManagedAgentConnection.SendAsync(new("end-process",item.EventId,password),stop.Token);if(!IsDisposed)MessageBox.Show(this,reply.Message,"Agent response");}catch(Exception ex){if(!IsDisposed)UiMessages.Failure(this,"Process response unavailable.",ex);}finally{busy=false;}
            await RefreshAsync();
        };
        Shown+=async(_,_)=>{if(trayOnly)Hide();timer.Start();await RefreshAsync();};
        FormClosing+=(_,e)=>{if(!quit&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};
        FormClosed+=(_,_)=>{stop.Cancel();timer.Stop();timer.Dispose();tray.Visible=false;tray.Dispose();stop.Dispose();};
    }
    private void Reveal(){Show();WindowState=FormWindowState.Normal;Activate();}
    private async Task RefreshAsync()
    {
        if(busy||IsDisposed)return;busy=true;
        try
        {
            var reply=await ManagedAgentConnection.SendAsync(new("status"),stop.Token);if(IsDisposed)return;
            if(!reply.Success || reply.Status is not {} state){status.Text="Endpoint status unavailable · Protection unconfirmed";diagnostics=reply.Message;events.Items.Clear();return;}
            var capacity=state.QueueCapacity>0?$"/{state.QueueCapacity:N0} ({state.QueuePayloadBytes/1048576d:N1}/{state.QueuePayloadLimitBytes/1048576d:N0} MiB)":"";
            status.Text=$"{RansomFree.Contracts.EndpointStatusText.Health(state.Health)} · {state.CanaryCount} canaries\nUser/process attribution: {(state.AuditConnected?"active":"unavailable")} · Queued alerts: {state.PendingEvents:N0} · Queued syslog: {state.PendingSyslog}";
            diagnostics=$"Agent {state.Version} · Policy {state.PolicyRevision}\nAudit: {(state.AuditConnected?"connected":"unavailable")}\nEvent queue: {state.PendingEvents:N0}{capacity}\n{state.Health}";
            events.BeginUpdate();events.Items.Clear();
            foreach(var item in state.Events)
            {
                events.Items.Add(new ListViewItem([item.Time.ToString("G"),item.Operation,item.Path,item.User,item.Process,item.ProcessId?.ToString()??"Unknown",item.Allowlisted?"Trusted":"Recorded"]){Tag=item});
                if(seen.Add(item.EventId)&&!initial&&!item.Allowlisted&&!item.SuppressPopup&&DateTime.UtcNow-lastBalloon>TimeSpan.FromSeconds(5)){tray.ShowBalloonTip(5000,"Canary activity",item.Operation+"\n"+Path.GetFileName(item.Path),ToolTipIcon.Warning);lastBalloon=DateTime.UtcNow;}
            }
            events.EndUpdate();initial=false;
            if(seen.Count>1000){seen.Clear();foreach(var item in state.Events)seen.Add(item.EventId);}
        }
        catch(Exception ex){if(!IsDisposed){status.Text="Agent connection unavailable · Protection unconfirmed";diagnostics=ex.ToString();events.Items.Clear();}}
        finally{busy=false;}
    }
}
