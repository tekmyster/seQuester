# Lab-only, read-only desktop observer. It never changes agent policy or terminates processes.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$labRoot='D:\Codex\RansomFree\lab\host'
$brandIconPath=Join-Path (Split-Path $PSScriptRoot -Parent) 'Assets\Branding\sequester.ico'
$form=New-Object Windows.Forms.Form;$form.Text='seQuester · Lab observer';$form.Icon=[Drawing.Icon]::new($brandIconPath);$form.Width=1000;$form.Height=600
$list=New-Object Windows.Forms.ListBox;$list.Dock='Fill';$list.HorizontalScrollbar=$true;$form.Controls.Add($list)
$label=New-Object Windows.Forms.Label;$label.Dock='Top';$label.Height=45;$label.Text='Lab observer: local agent events. WebUI: http://127.0.0.1:18080/';$form.Controls.Add($label)
$icon=New-Object Windows.Forms.NotifyIcon;$icon.Icon=[Drawing.Icon]::new($brandIconPath);$icon.Text='seQuester · Lab observer';$icon.Visible=$true
$menu=New-Object Windows.Forms.ContextMenuStrip
$null=$menu.Items.Add('Open activity');$menu.Items[0].add_Click({$form.Show();$form.Activate()})
$null=$menu.Items.Add('Open WebUI');$menu.Items[1].add_Click({Start-Process 'http://127.0.0.1:18080/'})
$null=$menu.Items.Add('Exit lab observer');$menu.Items[2].add_Click({$script:quit=$true;$form.Close()})
$icon.ContextMenuStrip=$menu;$icon.add_DoubleClick({$form.Show();$form.Activate()})
$seen=New-Object 'Collections.Generic.HashSet[string]';$script:first=$true;$script:lastBalloon=[DateTime]::MinValue
$timer=New-Object Windows.Forms.Timer;$timer.Interval=3000
$timer.add_Tick({
    try {
        $file=Join-Path $labRoot 'agent\activity.jsonl'
        if(Test-Path -LiteralPath $file){
            foreach($line in (Get-Content -LiteralPath $file -Tail 100)) {
                try{$event=$line | ConvertFrom-Json}catch{continue}
                if($seen.Add($event.EventId)){
                    $list.Items.Insert(0,($event.Time+' | '+$event.Operation+' | '+$event.Path+' | '+$event.User+' | '+$event.Process))
                    if(!$script:first -and ((Get-Date)-$script:lastBalloon).TotalSeconds -ge 5){$icon.ShowBalloonTip(5000,'Canary activity',($event.Operation+': '+[IO.Path]::GetFileName($event.Path)),[Windows.Forms.ToolTipIcon]::Warning);$script:lastBalloon=Get-Date;Add-Content -LiteralPath (Join-Path $labRoot 'logs\notifier.log') -Value ((Get-Date).ToString('o')+' Balloon requested for '+$event.EventId)}
                }
            }
            while($list.Items.Count -gt 200){$list.Items.RemoveAt($list.Items.Count-1)}
        }
        $script:first=$false
    }catch{$label.Text='Lab observer unavailable: '+$_.Exception.GetType().Name}
})
$form.add_Shown({$form.Hide();$timer.Start();Add-Content -LiteralPath (Join-Path $labRoot 'logs\notifier.log') -Value ((Get-Date).ToString('o')+' Observer started')})
$form.add_FormClosing({param($sender,$eventArgs) if(!$script:quit -and $eventArgs.CloseReason -eq 'UserClosing'){$eventArgs.Cancel=$true;$form.Hide()}})
try{[Windows.Forms.Application]::Run($form)}finally{$timer.Stop();$timer.Dispose();$icon.Visible=$false;$icon.Dispose();$form.Dispose()}
