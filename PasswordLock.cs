using System.Security.Cryptography;

namespace RansomFree;

internal sealed class PasswordLock
{
    private DateTime unlockedUntil;
    private DateTime retryAfter;
    private int failures;
    public void Lock()=>unlockedUntil=DateTime.MinValue;
    public bool Authorize(IWin32Window owner,PasswordSettings? settings,Action<string> audit)
    {
        if(settings==null || DateTime.UtcNow<unlockedUntil) return true;
        if(DateTime.UtcNow<retryAfter) {MessageBox.Show(owner,$"Try again in {(int)Math.Ceiling((retryAfter-DateTime.UtcNow).TotalSeconds)} seconds.","Settings locked");return false;}
        var password=Prompt(owner,"Unlock administration","Enter the administration password.");
        if(password==null) return false;
        if(!PasswordHash.Verify(password,settings))
        {
            failures++; retryAfter=DateTime.UtcNow.AddSeconds(Math.Min(60,Math.Pow(2,Math.Min(failures,6))));
            audit("Administration unlock denied");MessageBox.Show(owner,"Incorrect password.","Settings locked");return false;
        }
        failures=0;unlockedUntil=DateTime.UtcNow.AddMinutes(5);audit("Administration unlocked for five minutes");return true;
    }
    public static string? Prompt(IWin32Window owner,string title,string description,bool confirm=false)
    {
        using var form=new Form {Icon=BrandIcon.Load(),Text=title,Width=480,Height=confirm?260:220,StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=new Font("Segoe UI",10)};
        var caption=new Label {Text=description,Left=16,Top=16,Width=430,Height=42};
        var field=new TextBox {Left=16,Top=65,Width=430,UseSystemPasswordChar=true};
        var second=new TextBox {Left=16,Top=100,Width=430,UseSystemPasswordChar=true,PlaceholderText="Confirm password",Visible=confirm};
        var ok=new Button {Text="OK",Left=250,Top=confirm?150:110};var cancel=new Button {Text="Cancel",Left=345,Top=ok.Top,DialogResult=DialogResult.Cancel};
        ok.Click+=(_,_)=> {if(confirm && field.Text!=second.Text) {MessageBox.Show(form,"Passwords do not match.");return;} form.DialogResult=DialogResult.OK;};
        form.Controls.AddRange([caption,field,second,ok,cancel]);form.AcceptButton=ok;form.CancelButton=cancel;
        return form.ShowDialog(owner)==DialogResult.OK ? field.Text:null;
    }
}
