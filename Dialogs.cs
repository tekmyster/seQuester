namespace RansomFree;

internal sealed class DeploymentDialog : Form
{
    private readonly TextBox folder=new() { Dock=DockStyle.Fill,ReadOnly=true };
    private readonly DataGridView grid=new() { Dock=DockStyle.Fill,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,AllowUserToAddRows=true,AllowUserToDeleteRows=true,RowHeadersWidth=30 };
    public string DirectoryPath=>folder.Text;
    public List<CanarySpec> Specifications { get; private set; }=[];
    public DeploymentDialog(string initialFolder)
    {
        Icon=BrandIcon.Load(); Text="Create or import canary files"; Width=1100; Height=560; MinimumSize=new Size(900,500); StartPosition=FormStartPosition.CenterParent; Font=new Font("Segoe UI",10);
        var top=new TableLayoutPanel { Dock=DockStyle.Top,Height=48,Padding=new Padding(10),ColumnCount=2 };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100)); top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,100));
        folder.Text=initialFolder; top.Controls.Add(folder,0,0);
        var browse=new Button { Text="Browse…",Dock=DockStyle.Fill }; top.Controls.Add(browse,1,0);
        browse.Click+=(_,_)=> { using var picker=new FolderBrowserDialog(); if(picker.ShowDialog(this)==DialogResult.OK) folder.Text=picker.SelectedPath; };
        grid.Columns.Add(new DataGridViewTextBoxColumn { Name="Name",HeaderText="Filename",FillWeight=75 });
        grid.Columns.Add(new DataGridViewComboBoxColumn { Name="Type",HeaderText="File type",DataSource=CanaryTemplates.Types,FillWeight=25 });
        grid.Columns.Add(new DataGridViewTextBoxColumn {Name="Callback",HeaderText="Trigger URL (HTTPS)",FillWeight=90});
        grid.Columns.Add(new DataGridViewTextBoxColumn {Name="Source",HeaderText="Import source",ReadOnly=true,FillWeight=80});
        var suffix=Guid.NewGuid().ToString("N")[..6];
        grid.Rows.Add("!_Account_Recovery_"+suffix,"docx"); grid.Rows.Add("Financial_Records_"+suffix,"xlsx"); grid.Rows.Add("zz_Confidential_Archive_"+suffix,"pdf");
        grid.DataError+=(_,e)=> { e.ThrowException=false; };
        var bottom=new FlowLayoutPanel { Dock=DockStyle.Bottom,Height=72,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(10) };
        var create=new Button { Text="Create & monitor",AutoSize=true }; bottom.Controls.Add(create);
        var cancel=new Button { Text="Cancel",DialogResult=DialogResult.Cancel }; bottom.Controls.Add(cancel); CancelButton=cancel;
        var import=new Button {Text="Import tokenized files…",AutoSize=true}; bottom.Controls.Add(import);
        import.Click+=(_,_)=>
        {
            using var picker=new OpenFileDialog {Filter="Tokenized documents (*.docx;*.xlsx;*.pdf)|*.docx;*.xlsx;*.pdf",Multiselect=true,CheckFileExists=true};
            if(picker.ShowDialog(this)!=DialogResult.OK)return;
            foreach(var path in picker.FileNames) grid.Rows.Add(Path.GetFileName(path),Path.GetExtension(path)[1..].ToLowerInvariant(),"",path);
        };
        create.Click+=(_,_)=>
        {
            try
            {
                grid.EndEdit();
                if(!Directory.Exists(folder.Text)) throw new ArgumentException("Choose an existing local data folder.");
                Specifications=grid.Rows.Cast<DataGridViewRow>().Where(r=>!r.IsNewRow).Select(r=>new CanarySpec(Convert.ToString(r.Cells[0].Value)??"",Convert.ToString(r.Cells[1].Value)??"",Convert.ToString(r.Cells[2].Value),Convert.ToString(r.Cells[3].Value))).ToList();
                if(Specifications.Count==0) throw new ArgumentException("Add at least one filename and type.");
                foreach(var spec in Specifications) CanaryTemplates.Validate(spec);
                if(Specifications.Any(s=>!string.IsNullOrWhiteSpace(s.CallbackUrl) || !string.IsNullOrWhiteSpace(s.SourcePath)) &&
                    MessageBox.Show(this,"Imported documents are copied without alteration or execution; only basic container checks are performed. Use trusted canary files, not sensitive originals.\n\nCallback URLs must be trigger/image URLs, never management links. Compatible readers may contact that server and disclose network metadata. Copying alone may not trigger it.\n\nRemote alerts go to the token provider, not automatically to this tray or Wazuh. Test the provider's alert delivery separately. Continue?","Deploy callback-capable canaries",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return;
                DialogResult=DialogResult.OK; Close();
            }
            catch(Exception ex) { MessageBox.Show(this,ex.Message,"Check canary settings"); }
        };
        var note=new Label { Dock=DockStyle.Bottom,Height=88,Padding=new Padding(10,3,10,3),Text="Existing files are never overwritten. Use trusted files and trigger URLs.\nOpening imported files may send a network alert; copying alone may not." };
        Controls.Add(grid); Controls.Add(note); Controls.Add(bottom); Controls.Add(top);
    }
}

internal sealed class SyslogDialog : Form
{
    public SyslogOptions Options { get; private set; }
    public SyslogDialog(SyslogOptions current)
    {
        Options=current;
        Icon=BrandIcon.Load(); Text="Syslog / Wazuh connection"; Width=640; Height=490; StartPosition=FormStartPosition.CenterParent; Font=new Font("Segoe UI",10);
        var layout=new TableLayoutPanel { Dock=DockStyle.Fill,Padding=new Padding(16),ColumnCount=2,RowCount=9 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,170)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        var enabled=new CheckBox { Text="Forward alerts",Checked=current.Enabled,AutoSize=true };
        var host=new TextBox { Text=current.Host,Dock=DockStyle.Fill };
        var port=new NumericUpDown { Minimum=1,Maximum=65535,Value=current.Port };
        var transport=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList,DataSource=new[]{"TCP","UDP","TLS"},SelectedItem=current.Transport };
        var format=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList,DataSource=new[]{"RFC3164","RFC5424"},SelectedItem=current.Format };
        var facility=new NumericUpDown { Minimum=0,Maximum=23,Value=current.Facility };
        var severity=new NumericUpDown { Minimum=0,Maximum=7,Value=current.Severity };
        var framing=new CheckBox { Text="Octet-counted TCP framing",Checked=current.OctetCounting,AutoSize=true };
        var controls=new Control[]{enabled,host,port,transport,format,facility,severity,framing};
        var labels=new[]{"Enabled","Manager hostname/IP","Port","Transport","Message format","Facility (16 = local0)","Severity (4 = warning)","Framing"};
        for(var i=0;i<controls.Length;i++) { layout.RowStyles.Add(new RowStyle(SizeType.Absolute,34)); layout.Controls.Add(new Label {Text=labels[i],AutoSize=true},0,i); layout.Controls.Add(controls[i],1,i); }
        var info=new Label { Dock=DockStyle.Fill,AutoSize=false,Text="Use a collector that allows this endpoint. Firewall access must be configured separately." };
        layout.Controls.Add(info,0,8); layout.SetColumnSpan(info,2);
        var buttons=new FlowLayoutPanel { Dock=DockStyle.Bottom,Height=52,Padding=new Padding(10),FlowDirection=FlowDirection.RightToLeft };
        var save=new Button {Text="Save"}; var cancel=new Button {Text="Cancel",DialogResult=DialogResult.Cancel}; var test=new Button {Text="Test send",AutoSize=true}; var preset=new Button {Text="Wazuh preset",AutoSize=true};
        buttons.Controls.AddRange([save,cancel,test,preset]);
        SyslogOptions Read()=>new() {Enabled=enabled.Checked,Host=host.Text.Trim(),Port=(int)port.Value,Transport=transport.Text,Format=format.Text,Facility=(int)facility.Value,Severity=(int)severity.Value,OctetCounting=framing.Checked};
        preset.Click+=(_,_)=> {port.Value=514; transport.SelectedItem="TCP"; format.SelectedItem="RFC3164"; framing.Checked=false;};
        save.Click+=(_,_)=> {try {var value=Read(); if(value.Enabled) value.Validate(); Options=value; DialogResult=DialogResult.OK; Close();} catch(Exception ex) { MessageBox.Show(this,ex.Message); }};
        test.Click+=async(_,_)=>
        {
            test.Enabled=false;
            var value=Read();
            try { MessageBox.Show(this,await SyslogClient.SendAsync(new(DateTime.Now,"Test notification","No file accessed","Ransom Free",Environment.UserName,"Connection test"),value),"Syslog test"); }
            catch(Exception ex) {MessageBox.Show(this,SyslogClient.Explain(ex,value),"Connection test failed");}
            finally {test.Enabled=true;}
        };
        Controls.Add(layout); Controls.Add(buttons); CancelButton=cancel;
        Load+=(_,_)=> {transport.SelectedItem=current.Transport;format.SelectedItem=current.Format;};
    }
}

internal sealed class AllowlistDialog : Form
{
    public List<AllowRule> Rules { get; }
    public AllowlistDialog(IEnumerable<AllowRule> existing)
    {
        Rules=existing.ToList(); Text="Trusted processes"; Width=860; Height=420; StartPosition=FormStartPosition.CenterParent; Font=new Font("Segoe UI",10);
        var list=new ListBox { Dock=DockStyle.Fill,HorizontalScrollbar=true };
        void RefreshList() {list.Items.Clear(); foreach(var r in Rules) list.Items.Add(r.Executable+" | SHA-256 "+r.Hash[..Math.Min(r.Hash.Length,12)]+"…");}
        var info=new Label {Dock=DockStyle.Top,Height=66,Padding=new Padding(12),Text="Trusted matches stay logged but do not show alerts or allow process stopping. Other file changes still alert."};
        var panel=new FlowLayoutPanel {Dock=DockStyle.Bottom,Height=54,Padding=new Padding(10)};
        var add=new Button {Text="Add executable…",AutoSize=true}; var remove=new Button {Text="Remove selected",AutoSize=true}; var save=new Button {Text="Save",DialogResult=DialogResult.OK}; var cancel=new Button {Text="Cancel",DialogResult=DialogResult.Cancel};
        add.Click+=(_,_)=> { using var picker=new OpenFileDialog {Filter="Executable (*.exe)|*.exe",CheckFileExists=true}; if(picker.ShowDialog(this)!=DialogResult.OK)return; try {var rule=new AllowRule(picker.FileName,CanaryMonitor.Hash(picker.FileName)); if(!Rules.Contains(rule))Rules.Add(rule); RefreshList();} catch(Exception ex){MessageBox.Show(this,ex.Message);} };
        remove.Click+=(_,_)=> {if(list.SelectedIndex>=0) {Rules.RemoveAt(list.SelectedIndex);RefreshList();}};
        panel.Controls.AddRange([add,remove,save,cancel]); Controls.Add(list);Controls.Add(info);Controls.Add(panel);RefreshList();CancelButton=cancel;
    }
}
