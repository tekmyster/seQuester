using System.Collections;
using RansomFree.Contracts;
namespace RansomFree;
internal sealed class LocalHistorySort:IComparer
{
    private string field="time";private bool descending=true;
    private readonly Func<object,LocalHistoryKey> key;
    private LocalHistorySort(Func<object,LocalHistoryKey> key){this.key=key;}
    public int Compare(object? x,object? y)=>x is ListViewItem {Tag:not null} a&&y is ListViewItem {Tag:not null} b?LocalHistoryOrder.Compare(key(a.Tag),key(b.Tag),field,descending):0;
    public static void Attach(ListView list,Func<object,LocalHistoryKey> key)
    {
        var comparer=new LocalHistorySort(key);var labels=list.Columns.Cast<ColumnHeader>().Select(x=>x.Text).ToArray();list.ListViewItemSorter=comparer;
        void Sort(int index){if(index<0||index>=LocalHistoryOrder.Fields.Length)return;var field=LocalHistoryOrder.Fields[index];comparer.descending=comparer.field==field?!comparer.descending:false;comparer.field=field;for(var i=0;i<labels.Length;i++)list.Columns[i].Text=labels[i]+(i==index?(comparer.descending?" ▼":" ▲"):"");list.Sort();}
        list.ColumnClick+=(_,e)=>Sort(e.Column);
        // Native menu provides an explicit keyboard-accessible alternative to column clicks.
        var menu=new ContextMenuStrip();for(var i=0;i<LocalHistoryOrder.Fields.Length;i++){var column=i;menu.Items.Add("Sort by "+labels[i],null,(_,_)=>Sort(column));}list.ContextMenuStrip=menu;
        list.Disposed+=(_,_)=>menu.Dispose();
    }
    public static LocalHistoryKey Managed(object value){var e=(AgentConsoleEvent)value;return new(e.EventId,new DateTimeOffset(e.Time),e.Operation,e.Path,e.User,e.Process,e.ProcessId);}
}
