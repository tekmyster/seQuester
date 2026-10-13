namespace RansomFree;

internal static class UiMessages
{
    public static void Failure(IWin32Window? owner,string message,Exception error)
    {
        using var dialog=new Form{Icon=BrandIcon.Load(),Text="seQuester · Action unavailable",Width=600,Height=210,StartPosition=FormStartPosition.CenterParent,Font=new Font("Segoe UI",10),MinimizeBox=false,MaximizeBox=false};
        var heading=new Label{Text=message,Dock=DockStyle.Top,Height=64,Padding=new Padding(16),AutoEllipsis=true};
        var details=new TextBox{ReadOnly=true,Multiline=true,ScrollBars=ScrollBars.Both,Dock=DockStyle.Fill,Text=error.ToString(),Visible=false};
        var actions=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=48,Padding=new Padding(10)};
        var inspect=new Button{Text="Diagnostics",AutoSize=true};var close=new Button{Text="Close",DialogResult=DialogResult.OK,AutoSize=true};
        inspect.Click+=(_,_)=>{details.Visible=!details.Visible;dialog.Height=details.Visible?440:210;inspect.Text=details.Visible?"Hide diagnostics":"Diagnostics";};
        actions.Controls.AddRange([inspect,close]);dialog.Controls.Add(details);dialog.Controls.Add(heading);dialog.Controls.Add(actions);dialog.AcceptButton=close;dialog.CancelButton=close;dialog.ShowDialog(owner);
    }
}
