using System.Net;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace RansomFree;

internal record CanarySpec(string Name, string Type, string? CallbackUrl=null, string? SourcePath=null)
{
    public string? ManagedId {get;init;}
    public string? ManagedSignature {get;init;}
}

internal static class CanaryTemplates
{
    public static readonly string[] Types = ["docx", "xlsx", "pdf", "txt", "csv", "rtf", "html", "svg", "json", "xml", "md"];

    public static void Validate(CanarySpec spec)
    {
        _=FileName(spec);
        if(!string.IsNullOrWhiteSpace(spec.SourcePath))
        {
            if(!new[]{"docx","xlsx","pdf"}.Contains(spec.Type.ToLowerInvariant()) ||
                !Path.GetExtension(spec.SourcePath).Equals("."+spec.Type,StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Import only DOCX, XLSX, or PDF with its original file type.");
            if(!string.IsNullOrWhiteSpace(spec.CallbackUrl)) throw new ArgumentException("Imported files retain their existing tokens; leave Callback URL blank.");
        }
        if(!string.IsNullOrWhiteSpace(spec.CallbackUrl))
        {
            if(spec.Type.ToLowerInvariant() is not ("html" or "svg" or "docx" or "xlsx" or "pdf"))
                throw new ArgumentException("Embedded callbacks support DOCX, XLSX, PDF, HTML, and SVG. Other formats use local monitoring.");
            CallbackUrl(spec.CallbackUrl);
        }
    }

    internal static string CallbackUrl(string value)
    {
        if(value.Length>2048 || value.Any(char.IsWhiteSpace) || value.Any(char.IsControl) || value.Contains('\\') ||
            !Uri.TryCreate(value,UriKind.Absolute,out var uri) || uri.Scheme!=Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(uri.Host) || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0)
            throw new ArgumentException("Use a complete HTTPS image/web-bug callback URL, without credentials, whitespace, or a fragment. Never paste a token management URL.");
        return uri.AbsoluteUri;
    }

    public static string FileName(CanarySpec spec)
    {
        var name=spec.Name.Trim();
        var type=spec.Type.ToLowerInvariant();
        if(!Types.Contains(type)) throw new ArgumentException("Unsupported file type.");
        if(name.Length==0 || name.Length>160 || name.IndexOfAny(Path.GetInvalidFileNameChars())>=0 ||
            name.EndsWith('.') || name.EndsWith(' ') || name is "." or "..")
            throw new ArgumentException("Use a filename of 1–160 characters without path separators or Windows reserved characters.");
        var stem=name.Split('.')[0].ToUpperInvariant();
        if(new[]{"CON","PRN","AUX","NUL","CLOCK$"}.Contains(stem) ||
            (stem.Length==4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && "123456789¹²³".Contains(stem[3])))
            throw new ArgumentException("That filename is reserved by Windows.");
        return name.EndsWith("."+type,StringComparison.OrdinalIgnoreCase) ? name : name+"."+type;
    }

    public static byte[] Render(CanarySpec spec)
    {
        Validate(spec);
        if(!string.IsNullOrWhiteSpace(spec.SourcePath)) return ImportedCanaries.Read(spec.SourcePath,spec.Type);
        // Use real, validated document packages embedded in the executable.
        // No Office installation or runtime conversion is required on the endpoint.
        var type=spec.Type.ToLowerInvariant();
        if(type is "docx" or "xlsx" or "pdf")
        {
            using var resource=typeof(CanaryTemplates).Assembly.GetManifestResourceStream("RansomFree.Templates.canary."+type)
                ?? throw new InvalidOperationException("The "+type+" template is missing from this build.");
            using var bytes=new MemoryStream();resource.CopyTo(bytes);return string.IsNullOrWhiteSpace(spec.CallbackUrl)?bytes.ToArray():CallbackDocuments.Render(type,bytes.ToArray(),spec.CallbackUrl);
        }
        var title=WebUtility.HtmlEncode(spec.Name);
        var callback=string.IsNullOrWhiteSpace(spec.CallbackUrl)?null:CallbackUrl(spec.CallbackUrl);
        var image=callback==null?"":$"<img src=\"{WebUtility.HtmlEncode(callback)}\" width=\"1\" height=\"1\" alt=\"\" referrerpolicy=\"no-referrer\">";
        var content=type switch
        {
            "txt" => "Account recovery reference\r\nSynthetic security canary. No real credentials.\r\n",
            "csv" => "Record,Department,Amount\r\nDEMO-001,Finance,0\r\n",
            "rtf" => "{\\rtf1\\ansi Confidential archive\\par Synthetic security canary. No real personal data.}",
            "html" => $"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>{title}</title></head><body><h1>{title}</h1><p>Synthetic security canary. No real personal data.</p>{image}</body></html>",
            "svg" => RenderSvg(spec.Name,callback),
            "json" => JsonSerializer.Serialize(new { title=spec.Name, record="DEMO-RECOVERY-001", classification="Synthetic security canary", credentials="No real credentials" },new JsonSerializerOptions {WriteIndented=true}),
            "xml" => new XDocument(new XElement("RecoveryRegister",new XElement("Title",spec.Name),new XElement("Reference","DEMO-RECOVERY-001"),new XElement("Note","Synthetic security canary. No real credentials."))).ToString(),
            "md" => "# Account recovery register\n\nReference: DEMO-RECOVERY-001\n\nSynthetic security canary. No real credentials or personal data.\n",
            _ => throw new ArgumentException("Unsupported file type.")
        };
        return Encoding.UTF8.GetBytes(content);
    }

    private static string RenderSvg(string name,string? callback)
    {
        XNamespace ns="http://www.w3.org/2000/svg";
        return new XDocument(new XElement(ns+"svg",new XAttribute("width",720),new XAttribute("height",160),new XAttribute("viewBox","0 0 720 160"),
            new XElement(ns+"title",name),
            new XElement(ns+"rect",new XAttribute("width",720),new XAttribute("height",160),new XAttribute("fill","#f5f7fb")),
            new XElement(ns+"text",new XAttribute("x",24),new XAttribute("y",55),new XAttribute("font-size",24),"Archive reference"),
            new XElement(ns+"text",new XAttribute("x",24),new XAttribute("y",95),"Synthetic security canary. No real personal data."),
            callback==null?null:new XElement(ns+"image",new XAttribute("href",callback),new XAttribute("width",1),new XAttribute("height",1),new XAttribute("referrerpolicy","no-referrer")))).ToString();
    }
}
