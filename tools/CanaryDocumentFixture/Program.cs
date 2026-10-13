using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using RansomFree;

if(args.Length!=2)throw new ArgumentException("output-directory callback-url");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Preserve existing fixture output");Directory.CreateDirectory(root);
var url=CanaryTemplates.CallbackUrl(args[1]);var checks=0;
void Check(bool ok,string reason){if(!ok)throw new InvalidDataException(reason);checks++;}
XDocument Read(ZipArchive zip,string name){using var s=zip.GetEntry(name)?.Open()??throw new InvalidDataException(name);return XDocument.Load(s);}
XNamespace x="http://schemas.openxmlformats.org/spreadsheetml/2006/main",r="http://schemas.openxmlformats.org/officeDocument/2006/relationships";
XNamespace rel="http://schemas.openxmlformats.org/package/2006/relationships",a="http://schemas.openxmlformats.org/drawingml/2006/main",ct="http://schemas.openxmlformats.org/package/2006/content-types";
var bytes=CanaryTemplates.Render(new("canary","xlsx",url));
using(var stream=new MemoryStream(bytes))using(var zip=new ZipArchive(stream,ZipArchiveMode.Read))
{
 Check(zip.Entries.Select(e=>e.FullName).Distinct().Count()==zip.Entries.Count,"Duplicate package members");
 var sheet=Read(zip,"xl/worksheets/sheet1.xml");var drawing=sheet.Root!.Element(x+"drawing");
 Check(drawing!=null&&sheet.Root.Element(x+"picture")==null,"Worksheet drawing without external background");
 var sheetRels=Read(zip,"xl/worksheets/_rels/sheet1.xml.rels");
 var relation=sheetRels.Root!.Elements(rel+"Relationship").Single(e=>(string?)e.Attribute("Id")== (string?)drawing!.Attribute(r+"id"));
 Check((string?)relation.Attribute("Type")==r.NamespaceName+"/drawing"&&relation.Attribute("TargetMode")==null,"Internal drawing relationship");
 var name=Path.GetFileName((string)relation.Attribute("Target")!);var part="xl/drawings/"+name;
 var drawingDoc=Read(zip,part);var blip=drawingDoc.Descendants(a+"blip").Single();
 Check(blip.Attribute(r+"link")!=null&&blip.Attribute(r+"embed")==null,"External linked picture reference");
 var imageRels=Read(zip,"xl/drawings/_rels/"+name+".rels");var image=imageRels.Root!.Elements(rel+"Relationship").Single();
 Check((string?)image.Attribute("Id")==(string?)blip.Attribute(r+"link")&&(string?)image.Attribute("Target")==url&&(string?)image.Attribute("TargetMode")=="External"&&(string?)image.Attribute("Type")==r.NamespaceName+"/image","Exact linked callback relationship");
 var content=Read(zip,"[Content_Types].xml");
 Check(content.Root!.Elements(ct+"Override").Any(e=>(string?)e.Attribute("PartName")=="/"+part&&(string?)e.Attribute("ContentType")=="application/vnd.openxmlformats-officedocument.drawing+xml"),"Drawing content type");
 foreach(var entry in zip.Entries.Where(e=>e.FullName.EndsWith(".xml")||e.FullName.EndsWith(".rels"))){using var s=entry.Open();_=XDocument.Load(s);checks++;}
 Check(!zip.Entries.Any(e=>e.FullName.Contains("vbaProject",StringComparison.OrdinalIgnoreCase)),"No macro payload");
 // Rendering a second callback into the already linked sheet must fail.
 bool rejected=false;try{CallbackDocuments.Render("xlsx",bytes,url);}catch(InvalidDataException){rejected=true;}
 Check(rejected,"Existing drawing rejected rather than silently overwritten");
}
var docx=CanaryTemplates.Render(new("canary","docx",url));
using(var stream=new MemoryStream(docx))using(var zip=new ZipArchive(stream,ZipArchiveMode.Read))
 Check(Read(zip,"word/_rels/document.xml.rels").Descendants(rel+"Relationship").Any(e=>(string?)e.Attribute("Target")==url&&(string?)e.Attribute("TargetMode")=="External"),"Word callback regression");
File.WriteAllBytes(Path.Combine(root,"canary.xlsx"),bytes);
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,File=Path.Combine(root,"canary.xlsx"),Sha256=Convert.ToHexString(SHA256.HashData(bytes)),Url=url,Scope="Compiled renderer package checks; native Excel opening and actual server callback required separately"}));
