using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace RansomFree;

internal static class CallbackDocuments
{
    // No macros, JavaScript, executable content, credential collection, or requests during generation.
    public static byte[] Render(string type,byte[] template,string url)
    {
        url=CanaryTemplates.CallbackUrl(url);
        if(type=="pdf")return Pdf(url);
        if(type=="xlsx")return Xlsx(template,url);
        if(type!="docx")throw new ArgumentException("Unsupported callback document type.");
        using var output=new MemoryStream();output.Write(template);
        using(var zip=new ZipArchive(output,ZipArchiveMode.Update,true))
        {
            XNamespace rel="http://schemas.openxmlformats.org/package/2006/relationships";
            XNamespace r="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
            var part=type=="docx"?"word/document.xml":"xl/worksheets/sheet1.xml";
            var relationships=type=="docx"?"word/_rels/document.xml.rels":"xl/worksheets/_rels/sheet1.xml.rels";
            var id="rfImage"+Guid.NewGuid().ToString("N");
            var relations=Read(zip,relationships)??new XDocument(new XElement(rel+"Relationships"));
            relations.Root!.Add(new XElement(rel+"Relationship",new XAttribute("Id",id),new XAttribute("Type",r.NamespaceName+"/image"),new XAttribute("Target",url),new XAttribute("TargetMode","External")));
            Write(zip,relationships,relations);
            var document=Read(zip,part)??throw new InvalidDataException("Document template part is missing.");
            if(type=="docx")
            {
                XNamespace w="http://schemas.openxmlformats.org/wordprocessingml/2006/main",v="urn:schemas-microsoft-com:vml";
                var paragraph=new XElement(w+"p",new XElement(w+"r",new XElement(w+"pict",
                    new XElement(v+"rect",new XAttribute("id",id),new XAttribute("style","width:1pt;height:1pt"),new XAttribute("stroked","f"),
                        new XElement(v+"imagedata",new XAttribute(r+"id",id))))));
                var body=document.Root!.Element(w+"body")??throw new InvalidDataException("Word body is missing.");
                var section=body.Element(w+"sectPr");if(section!=null)section.AddBeforeSelf(paragraph);else body.Add(paragraph);
            }
            Write(zip,part,document);
        }
        return output.ToArray();
    }
    private static byte[] Xlsx(byte[] template,string url)
    {
        // Excel rejects an external worksheet background image. A DrawingML
        // picture uses r:link to reference the external resource instead.
        // Package generation performs no network requests.
        using var output=new MemoryStream();output.Write(template);
        using(var zip=new ZipArchive(output,ZipArchiveMode.Update,true))
        {
            XNamespace rel="http://schemas.openxmlformats.org/package/2006/relationships";
            XNamespace r="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
            XNamespace x="http://schemas.openxmlformats.org/spreadsheetml/2006/main";
            XNamespace a="http://schemas.openxmlformats.org/drawingml/2006/main";
            XNamespace d="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing";
            XNamespace ct="http://schemas.openxmlformats.org/package/2006/content-types";
            var sheet=Read(zip,"xl/worksheets/sheet1.xml")??throw new InvalidDataException("Worksheet template is missing.");
            if(sheet.Root!.Element(x+"drawing")!=null||sheet.Root.Element(x+"picture")!=null)
                throw new InvalidDataException("Template already contains a drawing or background image.");
            var id="rfImage"+Guid.NewGuid().ToString("N");
            var name=id+".xml";var drawingPart="xl/drawings/"+name;
            var drawing=new XElement(x+"drawing",new XAttribute(r+"id",id));
            var after=sheet.Root.Elements().FirstOrDefault(e=>new[]{"legacyDrawing","legacyDrawingHF","picture","oleObjects","controls","webPublishItems","tableParts","extLst"}.Contains(e.Name.LocalName));
            if(after!=null)after.AddBeforeSelf(drawing);else sheet.Root.Add(drawing);
            Write(zip,"xl/worksheets/sheet1.xml",sheet);
            var relationships="xl/worksheets/_rels/sheet1.xml.rels";
            var relations=Read(zip,relationships)??new XDocument(new XElement(rel+"Relationships"));
            relations.Root!.Add(new XElement(rel+"Relationship",new XAttribute("Id",id),new XAttribute("Type",r.NamespaceName+"/drawing"),new XAttribute("Target","../drawings/"+name)));
            Write(zip,relationships,relations);
            var imageId="rfCanaryImage";
            Write(zip,"xl/drawings/_rels/"+name+".rels",new XDocument(new XElement(rel+"Relationships",
                new XElement(rel+"Relationship",new XAttribute("Id",imageId),new XAttribute("Type",r.NamespaceName+"/image"),new XAttribute("Target",url),new XAttribute("TargetMode","External")))));
            Write(zip,drawingPart,new XDocument(new XElement(d+"wsDr",new XElement(d+"oneCellAnchor",
                new XElement(d+"from",new XElement(d+"col",0),new XElement(d+"colOff",0),new XElement(d+"row",0),new XElement(d+"rowOff",0)),
                new XElement(d+"ext",new XAttribute("cx",9525),new XAttribute("cy",9525)),
                new XElement(d+"pic",
                    new XElement(d+"nvPicPr",new XElement(d+"cNvPr",new XAttribute("id",1),new XAttribute("name","Sequester canary callback")),
                        new XElement(d+"cNvPicPr",new XElement(a+"picLocks",new XAttribute("noChangeAspect",1)))),
                    new XElement(d+"blipFill",new XElement(a+"blip",new XAttribute(r+"link",imageId)),new XElement(a+"stretch",new XElement(a+"fillRect"))),
                    new XElement(d+"spPr",new XElement(a+"xfrm",new XElement(a+"off",new XAttribute("x",0),new XAttribute("y",0)),new XElement(a+"ext",new XAttribute("cx",9525),new XAttribute("cy",9525))),
                        new XElement(a+"prstGeom",new XAttribute("prst","rect"),new XElement(a+"avLst")))),
                new XElement(d+"clientData")))));
            var types=Read(zip,"[Content_Types].xml")??throw new InvalidDataException("Office content types are missing.");
            types.Root!.Add(new XElement(ct+"Override",new XAttribute("PartName","/"+drawingPart),new XAttribute("ContentType","application/vnd.openxmlformats-officedocument.drawing+xml")));
            Write(zip,"[Content_Types].xml",types);
        }
        return output.ToArray();
    }
    private static XDocument? Read(ZipArchive zip,string name)
    {
        var entry=zip.GetEntry(name);if(entry==null)return null;using var stream=entry.Open();return XDocument.Load(stream);
    }
    private static void Write(ZipArchive zip,string name,XDocument document)
    {
        zip.GetEntry(name)?.Delete();using var stream=zip.CreateEntry(name).Open();document.Save(stream);
    }
    private static byte[] Pdf(string url)
    {
        // Page-open URI action; reader security settings can suppress or prompt for network access.
        var literal=url.Replace("\\","\\\\").Replace("(","\\(").Replace(")","\\)");
        const string content="BT /F1 18 Tf 60 740 Td (Account recovery reference) Tj 0 -30 Td /F1 10 Tf (Synthetic security canary. No real credentials.) Tj ET";
        string[] objects=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /AA << /O 6 0 R >> >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",$"<< /Length {Encoding.ASCII.GetByteCount(content)} >>\nstream\n{content}\nendstream",$"<< /S /URI /URI ({literal}) >>"];
        using var output=new MemoryStream();void WriteText(string text)=>output.Write(Encoding.ASCII.GetBytes(text));
        WriteText("%PDF-1.7\n");var offsets=new List<long>();
        for(var i=0;i<objects.Length;i++){offsets.Add(output.Position);WriteText($"{i+1} 0 obj\n{objects[i]}\nendobj\n");}
        var xref=output.Position;WriteText($"xref\n0 {objects.Length+1}\n0000000000 65535 f \n");foreach(var offset in offsets)WriteText(offset.ToString("D10",System.Globalization.CultureInfo.InvariantCulture)+" 00000 n \n");
        WriteText($"trailer\n<< /Size {objects.Length+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");return output.ToArray();
    }
}
