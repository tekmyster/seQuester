using System.Diagnostics;

namespace RansomFree;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if(args.Contains("--self-test")) { Environment.ExitCode=SelfTest.Run(); return; }
        if(args.Length==2 && args[0]=="--exercise") { SelfTest.Exercise(args[1]); return; }
        if(args.Contains("--hold-test")) { Thread.Sleep(30000); return; }
        ApplicationConfiguration.Initialize();
        using var mutex=new Mutex(true,"Local\\RansomFree.Tray",out var first);
        if(!first) { MessageBox.Show("seQuester is already running. Double-click its shield in the system tray.","seQuester"); return; }
        try
        {
            if(args.Contains("--managed-tray")){using var managed=new ManagedDashboard(args.Contains("--tray"));Application.Run(managed);return;}
            using var form=new Dashboard(args.Contains("--tray"));
            if(args.Contains("--ui-smoke"))
            {
                form.Shown+=(_,_)=>form.BeginInvoke((Action)(()=>
                {
                    using var bitmap=new Bitmap(form.Width,form.Height);
                    form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height));
                    bitmap.Save(Path.Combine(AppContext.BaseDirectory,"dashboard.png"));
                    using var deployment=new DeploymentDialog(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
                    using var syslog=new SyslogDialog(new());
                    using var allowlist=new AllowlistDialog([]);
                    foreach(var item in new (Form Form,string Name)[]{(deployment,"deployment"),(syslog,"syslog"),(allowlist,"allowlist")})
                    {
                        item.Form.Show();item.Form.PerformLayout();
                        using var capture=new Bitmap(item.Form.Width,item.Form.Height);
                        item.Form.DrawToBitmap(capture,new Rectangle(0,0,capture.Width,capture.Height));
                        capture.Save(Path.Combine(AppContext.BaseDirectory,item.Name+".png"));item.Form.Close();
                    }
                    File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"ui-smoke.txt"),"PASS: dashboard rendered and tray icon created");
                    Application.Exit();
                }));
            }
            Application.Run(form);
        }
        catch(Exception ex) { UiMessages.Failure(null,"seQuester could not start. Review diagnostics for the cause.",ex); }
    }
}

internal sealed class Dashboard : Form
{
    private readonly Queue<ListViewItem> displayedEvents=[];
    private readonly CanaryMonitor monitor=new();
    private readonly NotifyIcon tray=new();
    private readonly SyslogOutbox outbox=new(CanaryMonitor.DataDirectory,false);
    private readonly PasswordLock passwordLock=new();
    private readonly Label delivery=new() {Dock=DockStyle.Bottom,Height=50,Padding=new Padding(16,4,10,4),ForeColor=Color.DimGray};
    private readonly Label health=new() { AutoSize=false, Height=54, Dock=DockStyle.Top, Padding=new Padding(16,8,16,4) };
    private readonly ListView files=new() { Dock=DockStyle.Fill, View=View.Details, FullRowSelect=true };
    private readonly ListView events=new() { Dock=DockStyle.Fill, View=View.Details, FullRowSelect=true };
    private readonly System.Windows.Forms.Timer timer=new() { Interval=15000 };
    private readonly Dictionary<string,DateTime> recent=[];
    private bool quitting;
    private bool busy;
    private bool degraded;
    private string healthDiagnostics="No monitoring warnings.",deliveryDiagnostics="";
    private int count;
    private DateTime lastBalloon=DateTime.MinValue;
    public Dashboard(bool trayOnly)
    {
        Text="seQuester • Canary monitor"; Width=1100; Height=740; MinimumSize=new Size(840,560);
        StartPosition=FormStartPosition.CenterScreen; Icon=BrandIcon.Load();
        Font=new Font("Segoe UI",10); BackColor=Color.FromArgb(245,247,251);
        var title=new Label { Text="seQuester", Font=new Font("Segoe UI",24,FontStyle.Bold), Dock=DockStyle.Top, Height=68, Padding=new Padding(16,12,0,0) };
        var hint=new Label { Text="Closing this window keeps monitoring in the system tray.", Dock=DockStyle.Top, Height=42, Padding=new Padding(16,8,0,0) };
        var actions=new FlowLayoutPanel { Dock=DockStyle.Top, Height=116, Padding=new Padding(12,8,8,8), AutoScroll=true };
        AddButton(actions,"Create canaries…",()=>Deploy(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)));
        AddButton(actions,"Repair monitoring",()=> { monitor.Repair(); degraded=false; UpdateHealth(); });
        AddButton(actions,"Test notification",()=>Receive(new(DateTime.Now,"Test notification — monitoring UI works","No file was accessed","seQuester","","UI test")));
        AddButton(actions,"Open logs",()=>Process.Start(new ProcessStartInfo("explorer.exe",CanaryMonitor.DataDirectory) { UseShellExecute=true }));
        AddButton(actions,"Diagnostics",()=>MessageBox.Show(this,healthDiagnostics+"\n\nSyslog: "+outbox.LastStatus+"\n"+deliveryDiagnostics,"Endpoint diagnostics"),false);
        AddButton(actions,"Forget selected",()=>ForgetSelected());
        AddButton(actions,"Syslog / Wazuh…",()=> {using var dialog=new SyslogDialog(monitor.Settings.Syslog); if(dialog.ShowDialog(this)==DialogResult.OK) {monitor.Settings.Syslog=dialog.Options; monitor.Save(); outbox.SetEnabled(dialog.Options.Enabled); UpdateDelivery();}});
        AddButton(actions,"Process allowlist…",()=> {using var dialog=new AllowlistDialog(monitor.Settings.Allowlist); if(dialog.ShowDialog(this)==DialogResult.OK) {monitor.Settings.Allowlist=dialog.Rules; monitor.Save();}});
        AddButton(actions,"End selected process",EndSelectedProcess);
        AddButton(actions,"Set password…",()=>
        {
            var password=PasswordLock.Prompt(this,"Administration password","Set a password for settings, response actions and app exit. Minimum 12 characters.",true);
            if(password==null)return;
            monitor.Settings.Password=PasswordHash.Create(password);monitor.Save();passwordLock.Lock();
            Receive(new(DateTime.Now,"Administration password configured","Settings","seQuester",Environment.UserName,"Administration"));
            MessageBox.Show(this,"Settings and app exit now require the password. This UI lock does not prevent a Windows administrator from forcibly stopping or removing this portable app.","Password enabled");
        });
        AddButton(actions,"Lock now",()=> {passwordLock.Lock(); MessageBox.Show(this,monitor.Settings.Password==null?"Set an administration password first.":"Administration is locked.");},false);
        var tabs=new TabControl { Dock=DockStyle.Fill, Padding=new Point(18,8) };
        var fileTab=new TabPage("Canary files"); var eventTab=new TabPage("Local activity · Latest 1,000"); tabs.TabPages.AddRange([fileTab,eventTab]);
        files.Columns.Add("Monitored file",600); files.Columns.Add("Baseline",160); files.Columns.Add("Tripwire",300);
        events.Columns.Add("Time",155); events.Columns.Add("Activity",235); events.Columns.Add("File",300); events.Columns.Add("User",200); events.Columns.Add("Process",250); events.Columns.Add("PID",80); events.Columns.Add("Source",145);
        LocalHistorySort.Attach(events,value=>{var e=(Alert)value;return new(e.EventId,new DateTimeOffset(e.Time),e.Operation,e.Path,e.User,e.Executable??e.Process,e.ProcessId);});
        events.DoubleClick+=(_,_)=> { if(events.SelectedItems.Count>0 && events.SelectedItems[0].Tag is Alert a) MessageBox.Show(this,$"{a.Time:G}\n{a.Operation}\n\n{a.Path}\n\nProcess: {a.Process}\nUser: {a.User}\nSource: {a.Source}","Activity details"); };
        fileTab.Controls.Add(files); eventTab.Controls.Add(events);
        var footer=new Label { Text="Monitoring continues in the tray. Exiting this app stops protection.", Dock=DockStyle.Bottom, Height=60, Padding=new Padding(16,8,10,4), ForeColor=Color.DimGray };
        Controls.Add(tabs); Controls.Add(delivery); Controls.Add(footer); Controls.Add(actions); Controls.Add(health); Controls.Add(hint); Controls.Add(title);
        var menu=new ContextMenuStrip(); menu.Items.Add("Open seQuester",null,(_,_)=>Reveal());
        menu.Items.Add("Monitoring details",null,(_,_)=>MessageBox.Show(this,"Reads may be copies or scans. File changes may be encryption. Alerts do not block access. File names cannot guarantee search ordering. Integrity checks run every 15 seconds. Monitoring runs while this app is open.","Monitoring details"));
        menu.Items.Add("Test notification",null,(_,_)=>Receive(new(DateTime.Now,"Test notification","No file was accessed","seQuester","","UI test")));
        menu.Items.Add(new ToolStripSeparator()); menu.Items.Add("Lock administration",null,(_,_)=>passwordLock.Lock());
        menu.Items.Add("Exit monitoring",null,(_,_)=> { if(!Authorize())return; quitting=true; Close(); });
        tray.Icon=BrandIcon.Load(); tray.Text="seQuester • Starting"; tray.ContextMenuStrip=menu; tray.Visible=true;
        tray.DoubleClick+=(_,_)=>Reveal(); tray.BalloonTipClicked+=(_,_)=> { Reveal(); tabs.SelectedTab=eventTab; };
        monitor.Alerted+=a=>Post(()=>Receive(a));
        outbox.Status+=_=>Post(UpdateDelivery);
        monitor.HealthChanged+=message=>Post(()=> { degraded=true;healthDiagnostics=message; health.Text=RansomFree.Contracts.EndpointStatusText.Health(message); health.ForeColor=Color.Firebrick; tray.Text="seQuester • Monitoring needs attention"; });
        Shown+=(_,_)=>
        {
            monitor.Start(); outbox.SetEnabled(monitor.Settings.Syslog.Enabled); RefreshFiles(); UpdateHealth(); UpdateDelivery();
            timer.Start();
            if(trayOnly) Hide();
        };
        timer.Tick+=async(_,_)=>
        {
            if(busy) return; busy=true;
            try { await Task.Run(monitor.CheckIntegrity); }
            catch(Exception ex) { degraded=true;healthDiagnostics=ex.ToString();health.Text="Monitoring needs attention · See Diagnostics"; }
            finally { busy=false; }
        };
        FormClosing+=(_,e)=> { if(!quitting && e.CloseReason==CloseReason.UserClosing) { e.Cancel=true; Hide(); } };
        FormClosed+=(_,_)=> { timer.Stop(); timer.Dispose(); monitor.Dispose(); outbox.Dispose(); tray.Visible=false; tray.Dispose(); };
    }
    private void Post(Action action) { if(!IsDisposed && IsHandleCreated) { try { BeginInvoke(action); } catch(InvalidOperationException) { } } }
    private bool Authorize()=>passwordLock.Authorize(this,monitor.Settings.Password,operation=>Receive(new(DateTime.Now,operation,"Settings","seQuester",Environment.UserName,"Administration")));
    private void AddButton(FlowLayoutPanel panel,string text,Action action,bool requiresUnlock=true)
    {
        var button=new Button { Text=text, AutoSize=true, Height=34, Padding=new Padding(8,3,8,3), Margin=new Padding(4) };
        button.Click+=(_,_)=> { if(busy) { MessageBox.Show(this,"An integrity check is in progress. Please try again in a moment."); return; } try { if(requiresUnlock && !Authorize())return; action(); } catch(Exception ex) { MessageBox.Show(this,ex.Message,"Action could not complete",MessageBoxButtons.OK,MessageBoxIcon.Warning); RefreshFiles(); } };
        panel.Controls.Add(button);
    }
    private void Deploy(string directory)
    {
        using var dialog=new DeploymentDialog(directory);
        if(dialog.ShowDialog(this)!=DialogResult.OK) return;
        try { monitor.Deploy(dialog.DirectoryPath,dialog.Specifications); }
        finally { monitor.Start(); RefreshFiles(); UpdateHealth(); }
    }
    private void ForgetSelected()
    {
        if(files.SelectedItems.Count==0) return;
        var path=files.SelectedItems[0].Text;
        monitor.Settings.Canaries.RemoveAll(c=>c.Path.Equals(path,StringComparison.OrdinalIgnoreCase)); monitor.Save(); monitor.Start(); RefreshFiles(); UpdateHealth();
        MessageBox.Show(this,"Monitoring entry removed. The decoy file remains in place; delete it manually if no longer needed. Its audit rule remains until the file is deleted.","Canary removed");
    }
    private void RefreshFiles()
    {
        files.Items.Clear(); foreach(var c in monitor.Settings.Canaries) files.Items.Add(new ListViewItem([c.Path,File.Exists(c.Path)?"Recorded SHA-256":"Missing",c.Tripwire]));
    }
    private void UpdateHealth()
    {
        if(degraded) return;
        health.ForeColor=monitor.AuditConnected ? Color.FromArgb(0,100,70):Color.Firebrick;
        health.Text=monitor.Settings.Canaries.Count==0 ? "Create canaries to start monitoring." : $"{monitor.Settings.Canaries.Count} canaries • User/process attribution {(monitor.AuditConnected?"active":"unavailable")} • {count} alerts";
        tray.Text=monitor.Settings.Canaries.Count==0 ? "seQuester • No canaries configured" : "seQuester • "+(monitor.AuditConnected?"Monitoring":"Degraded monitoring");
    }
    private void Receive(Alert alert)
    {
        alert=alert with {Allowlisted=monitor.Settings.Allowlist.Any(r=>r.Matches(alert))};
        var key=alert.Path+"|"+alert.Process+"|"+alert.Operation;
        if(recent.TryGetValue(key,out var previous) && DateTime.Now-previous<TimeSpan.FromSeconds(2)) return;
        if(recent.Count>2000) recent.Clear(); recent[key]=DateTime.Now;
        count++;
        var row=new ListViewItem([alert.Time.ToString("yyyy-MM-dd HH:mm:ss"),(alert.Allowlisted?"[Allowed] ":"")+alert.Operation,alert.Path,alert.User,alert.Executable??alert.Process,alert.ProcessId?.ToString()??"Unknown",alert.Source]) { Tag=alert };
        if(alert.Allowlisted) row.ForeColor=Color.DimGray;
        displayedEvents.Enqueue(row);events.Items.Add(row);if(displayedEvents.Count>1000)displayedEvents.Dequeue().Remove();
        try
        {
            var log=Path.Combine(CanaryMonitor.DataDirectory,"activity.jsonl");
            if(File.Exists(log) && new FileInfo(log).Length>5_000_000) File.Move(log,log+".previous",true);
            File.AppendAllText(log,System.Text.Json.JsonSerializer.Serialize(alert)+Environment.NewLine);
        }
        catch(Exception ex) { degraded=true;healthDiagnostics=ex.ToString();health.Text="Activity log unavailable · See Diagnostics"; }
        try {outbox.Enqueue(alert,monitor.Settings.Syslog);} catch(Exception ex) {deliveryDiagnostics=ex.ToString();delivery.Text="Syslog queue unavailable · See Diagnostics";}
        if(!alert.Allowlisted && DateTime.Now-lastBalloon>TimeSpan.FromSeconds(3))
        {
            lastBalloon=DateTime.Now;
            var text=alert.Operation+"\n"+Path.GetFileName(alert.Path)+"\n"+alert.Process;
            tray.ShowBalloonTip(10000,"seQuester • Canary activity",text[..Math.Min(text.Length,250)],ToolTipIcon.Warning);
        }
        UpdateHealth();
    }
    private void UpdateDelivery()=>delivery.Text=(monitor.Settings.Syslog.Enabled ? "Syslog • " : "Syslog disabled • ")+RansomFree.Contracts.EndpointStatusText.Delivery(outbox.LastStatus)+$" • Queued: {outbox.Count}";
    private void EndSelectedProcess()
    {
        if(events.SelectedItems.Count==0 || events.SelectedItems[0].Tag is not Alert alert) throw new InvalidOperationException("Select an attributed event in the Activity tab first.");
        if(alert.Identity==null) throw new InvalidOperationException("No verified live process identity was captured for this event. Nothing can be terminated.");
        if(monitor.Settings.Allowlist.Any(r=>r.Matches(alert))) throw new InvalidOperationException("This process matches the allowlist. Remove its rule before requesting termination.");
        if(MessageBox.Show(this,$"End this process? Unsaved work in that process may be lost.\n\n{alert.Identity.Executable}\nPID {alert.Identity.Pid}\nUser: {alert.User}\n\nOnly this process will be ended, not its children.","End process",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes) return;
        try
        {
            ProcessControls.End(alert.Identity);
            Receive(new(DateTime.Now,"Process terminated",alert.Path,alert.Process,Environment.UserName,"Manual response"));
        }
        catch(Exception ex)
        {
            Receive(new(DateTime.Now,"Process termination failed: "+ex.Message,alert.Path,alert.Process,Environment.UserName,"Manual response"));
            throw;
        }
    }
    private void Reveal() { Show(); WindowState=FormWindowState.Normal; Activate(); }
}
