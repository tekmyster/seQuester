using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Threading;

namespace RansomFree.UnixDesktop;

public sealed class EndpointApp:Application
{
    private readonly TextBlock health=new(){Text="Waiting for endpoint status",FontSize=22,FontWeight=FontWeight.SemiBold,TextWrapping=TextWrapping.Wrap};
    private readonly TextBlock summary=new(){TextWrapping=TextWrapping.Wrap};
    private readonly TextBlock detail=new(){TextWrapping=TextWrapping.Wrap};
    private readonly TextBlock delivery=new(){TextWrapping=TextWrapping.Wrap};
    private readonly TextBlock sensorState=new(){TextWrapping=TextWrapping.Wrap};
    private readonly StackPanel events=new(){Spacing=8,MinHeight=240};
    private EndpointEvent[] recentEvents=[];
    private string eventSort="time";
    private bool eventDescending=true;
    private readonly TextBox eventDetails=new(){IsReadOnly=true,AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,MinHeight=200};
    private readonly HashSet<string> seen=new(StringComparer.Ordinal);
    private readonly Queue<string> seenOrder=new();
    private IClassicDesktopStyleApplicationLifetime? lifetime;
    private Window? window,notice;
    private TrayIcon? tray;
    private DispatcherTimer? timer;
    private bool busy,initialized,exiting;
    public override void Initialize(){Styles.Add(new FluentTheme());RequestedThemeVariant=ThemeVariant.Default;}
    public override void OnFrameworkInitializationCompleted()
    {
        lifetime=(IClassicDesktopStyleApplicationLifetime)ApplicationLifetime!;
        lifetime.ShutdownMode=ShutdownMode.OnExplicitShutdown;
        var refresh=new Button{Content="Refresh"};refresh.Click+=async(_,_)=>await Refresh();
        var quit=new Button{Content="Quit desktop"};quit.Click+=(_,_)=>Quit();
        var controls=new StackPanel{Orientation=Orientation.Horizontal,Spacing=12,Children={refresh,quit}};
        var body=new StackPanel{Margin=new Thickness(24),Spacing=18,Children={new TextBlock{Text="seQuester · Endpoint",FontSize=16},health,summary,sensorState,delivery,new Expander{Header="Diagnostics",Content=detail},new TextBlock{Text="Recent local events · Up to 100",FontWeight=FontWeight.SemiBold},new ScrollViewer{Content=events,HorizontalScrollBarVisibility=Avalonia.Controls.Primitives.ScrollBarVisibility.Auto},new Expander{Header="Event evidence",Content=eventDetails},controls,new TextBlock{Text="Quit closes desktop alerts. Endpoint protection keeps running.",TextWrapping=TextWrapping.Wrap}}};
        window=new Window{Title="seQuester Endpoint",Width=800,Height=690,MinWidth=540,MinHeight=400,Content=new ScrollViewer{Content=body},Icon=CreateIcon()};
        // IsVisible expresses requested tray visibility, not proof a Linux desktop
        // has a tray host. Never hide the only window on that assumption.
        window.Closing+=(_,e)=>{if(!exiting){e.Cancel=true;Quit();}};
        lifetime.MainWindow=window;
        var menu=new NativeMenu();var show=new NativeMenuItem("Open endpoint");show.Click+=(_,_)=>Show();menu.Items.Add(show);
        var quitItem=new NativeMenuItem("Quit desktop");quitItem.Click+=(_,_)=>Quit();menu.Items.Add(quitItem);
        tray=new TrayIcon{Icon=CreateIcon(),ToolTipText="seQuester · status pending",Menu=menu,IsVisible=true};tray.Clicked+=(_,_)=>Show();
        TrayIcon.SetIcons(this,new TrayIcons{tray});
        timer=new DispatcherTimer{Interval=TimeSpan.FromSeconds(5)};timer.Tick+=async(_,_)=>await Refresh();timer.Start();
        lifetime.Exit+=(_,_)=>{exiting=true;timer.Stop();tray.Dispose();};
        window.Show();_ = Refresh();base.OnFrameworkInitializationCompleted();
    }
    private void Show(){window!.Show();window.WindowState=WindowState.Normal;window.Activate();}
    private void Quit(){exiting=true;timer?.Stop();notice?.Close();tray?.Dispose();lifetime?.Shutdown();}
    private static string Clean(string? text,int max=2048)=>new((text??"Unavailable").Where(c=>!char.IsControl(c)).Take(max).ToArray());
    private async Task Refresh()
    {
        if(busy||exiting)return;busy=true;
        try
        {
            var value=await Task.Run(SafeStatusFile.Read);if(exiting)return;
            var age=DateTimeOffset.UtcNow-value.UpdatedUtc;var stale=age.TotalSeconds>120||age.TotalSeconds< -60;
            health.Text=stale?"Status stale — protection unconfirmed":RansomFree.Contracts.EndpointStatusText.Health(value.Health);
            summary.Text=$"{RansomFree.Contracts.EndpointStatusText.Connectivity(value.Connectivity)}   ·   {value.Canaries} canaries";
            sensorState.Text=DesktopStatusText.Sensor(value.Monitor,stale);
            delivery.Text=$"Queued alerts: {value.Queue?.Pending.ToString("N0")??"Unknown"} · Queued syslog: {value.PendingSyslog}\n{RansomFree.Contracts.EndpointStatusText.Delivery(value.SyslogStatus)}";
            var queue=value.Queue is {} q&&q.Pending>=0&&q.PayloadBytes>=0&&q.MaxEvents>0&&q.MaxPayloadBytes>0?$"{q.Pending:N0} of {q.MaxEvents:N0} events · {q.PayloadBytes/1048576d:N1} of {q.MaxPayloadBytes/1048576d:N1} MiB":"Unavailable";
            detail.Text=$"Health: {Clean(value.Health)}\nConnection: {Clean(value.Connectivity)}\nPolicy: {value.PolicyRevision}\nMonitor: {Clean(value.Monitor)}\nUpdated: {value.UpdatedUtc.ToLocalTime():g}   ·   Last sync: {value.LastSyncUtc?.ToLocalTime().ToString("g")??"Never"}\nPending syslog: {value.PendingSyslog} · {Clean(value.SyslogStatus)}\nEvent queue: {queue}\nVersion: {Clean(value.Version,80)}";
            recentEvents=value.Events;RenderEvents();
            eventDetails.Text=string.Join("\n\n",value.Events.Select(e=>$"{e.Time.ToLocalTime():g} · {Clean(e.Path)}\nAttribution: {Clean(e.Attribution?.Level??"Not reported",80)} · Parent PID: {e.Attribution?.ParentProcessId?.ToString()??"Unknown"}\n{Clean(e.Attribution?.Basis??"",512)}\nSource: {Clean(e.Source,120)}"));
            tray!.ToolTipText=stale?"seQuester · status stale":"seQuester · "+RansomFree.Contracts.EndpointStatusText.Connectivity(value.Connectivity);
            if(!stale)
            {
                var fresh=value.Events.Where(e=>!string.IsNullOrEmpty(e.EventId)&&!seen.Contains(e.EventId)&&!e.Allowlisted&&e.Trust?.Result.Decision.SuppressPopup!=true).ToArray();
                foreach(var item in value.Events)if(!string.IsNullOrEmpty(item.EventId)&&seen.Add(item.EventId)){seenOrder.Enqueue(item.EventId);while(seenOrder.Count>1000)seen.Remove(seenOrder.Dequeue());}
                if(initialized&&fresh.Length>0)Notify(fresh);
                initialized=true;
            }
        }
        catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException or ArgumentException)
        {health.Text="Endpoint status unavailable";summary.Text="Check the service and your access permissions.";sensorState.Text="";delivery.Text="Protection unconfirmed.";detail.Text="Check service health and approved read-only group membership. "+ex.GetType().Name;recentEvents=[];events.Children.Clear();events.Children.Add(new TextBlock{Text="Events unavailable."});eventDetails.Text="";if(tray!=null)tray.ToolTipText="seQuester · status unavailable";}
        finally{busy=false;}
    }
    private void Notify(EndpointEvent[] fresh)
    {
        // Managed alert window: no Python, shell execution, private-state access or
        // link activation. Native notification-center integration is not implied.
        notice?.Close();
        var open=new Button{Content="View events"};open.Click+=(_,_)=>{notice?.Close();Show();};
        notice=new Window{Title="seQuester alert",Icon=CreateIcon(),Width=420,Height=220,CanResize=false,Topmost=true,ShowInTaskbar=false,Content=new StackPanel{Margin=new Thickness(20),Spacing=14,Children={new TextBlock{Text=$"{fresh.Length} new canary alert{(fresh.Length==1?"":"s")}",FontSize=20,FontWeight=FontWeight.SemiBold},new TextBlock{Text=Clean(fresh[0].Operation,180),TextWrapping=TextWrapping.Wrap},open}}};
        notice.Show();var current=notice;
        DispatcherTimer.RunOnce(()=>{if(current==notice){current.Close();notice=null;}},TimeSpan.FromSeconds(15));
    }
    private static WindowIcon CreateIcon()
    {
        using var png=typeof(EndpointApp).Assembly.GetManifestResourceStream("Quiver.seQuester.Icon")??throw new InvalidOperationException("Application icon missing.");
        return new WindowIcon(png);
    }
    private void RenderEvents()
    {
        var header=events.Children.FirstOrDefault() as Grid;var columns=new[]{("time","Observed"),("operation","Activity"),("path","File"),("user","User"),("process","Process"),("pid","PID")};
        if(header==null){events.Children.Clear();header=new Grid{ColumnDefinitions=new ColumnDefinitions("165,190,220,150,220,80")};events.Children.Add(header);}
        while(events.Children.Count>1)events.Children.RemoveAt(events.Children.Count-1);
        for(var i=0;i<columns.Length;i++)
        {
            var (key,title)=columns[i];var active=key==eventSort;
            var button=header.Children.OfType<Button>().FirstOrDefault(b=>Equals(b.Tag,key));
            if(button==null)
            {
                button=new Button{HorizontalAlignment=HorizontalAlignment.Stretch,Tag=key};
                button.Click+=(_,_)=>{eventDescending=eventSort==key?!eventDescending:false;eventSort=key;RenderEvents();};
                Grid.SetColumn(button,i);header.Children.Add(button);
            }
            button.Content=title+(active?(eventDescending?" ▼":" ▲"):"");
            Avalonia.Automation.AutomationProperties.SetName(button,title+": sort "+(active&&!eventDescending?"descending":"ascending"));
        }
        RansomFree.Contracts.LocalHistoryKey Key(EndpointEvent e)=>new(e.EventId,e.Time,e.Operation,e.Path,e.User,e.Process,e.ProcessId);
        var sorted=recentEvents.OrderBy(e=>e,Comparer<EndpointEvent>.Create((a,b)=>RansomFree.Contracts.LocalHistoryOrder.Compare(Key(a),Key(b),eventSort,eventDescending)));
        foreach(var entry in sorted)
        {
            var row=new Grid{ColumnDefinitions=new ColumnDefinitions("165,190,220,150,220,80")};
            var values=new[]{entry.Time.ToLocalTime().ToString("g"),entry.Operation+(entry.Allowlisted?" · Trusted":""),entry.Path,entry.User,entry.Process,entry.ProcessId?.ToString()??"Unknown"};
            for(var i=0;i<values.Length;i++){var text=new TextBlock{Text=Clean(values[i]),TextWrapping=TextWrapping.Wrap,Margin=new Thickness(4)};Grid.SetColumn(text,i);row.Children.Add(text);}events.Children.Add(row);
        }
        if(recentEvents.Length==0)events.Children.Add(new TextBlock{Text="No recent events."});
    }
}
