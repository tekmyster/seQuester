using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;

namespace RansomFree;

internal static class ImportedCanaries
{
    internal const int MaxBytes=10*1024*1024;
    public static byte[] Read(string path,string type)
    {
        // Read one stable snapshot. Never open the document in Office, render it, or resolve its resources.
        using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(input.Length is <1 or >MaxBytes) throw new InvalidDataException("Imported canaries must be between 1 byte and 10 MiB.");
        var bytes=new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
        Validate(bytes,type.ToLowerInvariant());
        return bytes;
    }

    internal static void Validate(byte[] bytes,string type)
    {
        if(type=="pdf")
        {
            if(!bytes.AsSpan().StartsWith("%PDF-"u8)) throw new InvalidDataException("The selected file does not have a PDF header.");
            return; // Container check only, not a safety assessment or callback verification.
        }
        if(type is not ("docx" or "xlsx")) throw new ArgumentException("Unsupported imported file type.");
        using var stream=new MemoryStream(bytes,false);
        using var zip=new ZipArchive(stream,ZipArchiveMode.Read);
        if(zip.Entries.Count>4096) throw new InvalidDataException("The Office package contains too many entries.");
        var main=type=="docx"?"word/document.xml":"xl/workbook.xml";
        foreach(var required in new[]{"[Content_Types].xml",main})
        {
            var matches=zip.Entries.Where(e=>e.FullName==required).ToArray();
            if(matches.Length!=1 || matches[0].Length>2*1024*1024) throw new InvalidDataException("Invalid or oversized Office package part: "+required);
            using var part=matches[0].Open();
            using var reader=XmlReader.Create(part,new XmlReaderSettings {DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=2*1024*1024});
            _=XDocument.Load(reader);
        }
        // Do not rewrite ZIP entries: external relationships and opaque provider tokens must remain byte-identical.
    }
}
