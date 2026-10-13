using System.Buffers.Binary;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
if(args.Length!=2)throw new ArgumentException("Provide canonical logo and new output directory.");
var source=Path.GetFullPath(args[0]);var output=Path.GetFullPath(args[1]);
if(Directory.Exists(output)||File.Exists(output))throw new IOException("Output must be new; immutable assets are not overwritten.");
using var original=Image.FromFile(source);if(original.Width!=original.Height)throw new InvalidDataException("Expected square canonical artwork; no crop or distortion allowed.");
Directory.CreateDirectory(output);File.Copy(source,Path.Combine(output,"sequester-original.jpg"));
var sizes=new[]{16,24,32,48,64,128,180,192,256,512,1024};var frames=new Dictionary<int,byte[]>();
foreach(var size in sizes)
{
    using var bitmap=new Bitmap(size,size,PixelFormat.Format32bppArgb);using(var g=Graphics.FromImage(bitmap))
    {
        g.Clear(Color.White);g.CompositingQuality=CompositingQuality.HighQuality;g.InterpolationMode=InterpolationMode.HighQualityBicubic;g.SmoothingMode=SmoothingMode.HighQuality;g.PixelOffsetMode=PixelOffsetMode.HighQuality;
        using var attributes=new ImageAttributes();attributes.SetWrapMode(WrapMode.TileFlipXY);g.DrawImage(original,new Rectangle(0,0,size,size),0,0,original.Width,original.Height,GraphicsUnit.Pixel,attributes);
    }
    using var stream=new MemoryStream();bitmap.Save(stream,ImageFormat.Png);frames[size]=stream.ToArray();File.WriteAllBytes(Path.Combine(output,$"sequester-{size}.png"),frames[size]);
}
var icoSizes=new[]{16,24,32,48,64,128,256};
using(var stream=File.Create(Path.Combine(output,"sequester.ico")))using(var writer=new BinaryWriter(stream))
{
    writer.Write((ushort)0);writer.Write((ushort)1);writer.Write((ushort)icoSizes.Length);var offset=6+icoSizes.Length*16;
    foreach(var size in icoSizes){writer.Write((byte)(size==256?0:size));writer.Write((byte)(size==256?0:size));writer.Write((byte)0);writer.Write((byte)0);writer.Write((ushort)1);writer.Write((ushort)32);writer.Write(frames[size].Length);writer.Write(offset);offset+=frames[size].Length;}
    foreach(var size in icoSizes)writer.Write(frames[size]);
}
using(var stream=File.Create(Path.Combine(output,"sequester.icns")))
{
    void Number(int n){Span<byte> bytes=stackalloc byte[4];BinaryPrimitives.WriteInt32BigEndian(bytes,n);stream.Write(bytes);}
    var types=new Dictionary<int,string>{{16,"icp4"},{32,"icp5"},{64,"icp6"},{128,"ic07"},{256,"ic08"},{512,"ic09"},{1024,"ic10"}};
    stream.Write(Encoding.ASCII.GetBytes("icns"));Number(8+types.Sum(x=>8+frames[x.Key].Length));
    foreach(var (size,type) in types){stream.Write(Encoding.ASCII.GetBytes(type));Number(8+frames[size].Length);stream.Write(frames[size]);}
}
// Structural checks against every frame, independent of visual acceptance.
foreach(var size in sizes){using var check=Image.FromFile(Path.Combine(output,$"sequester-{size}.png"));if(check.Width!=size||check.Height!=size)throw new InvalidDataException("PNG size mismatch.");}
using(var ico=new Icon(Path.Combine(output,"sequester.ico"),32,32)){if(ico.Width!=32)throw new InvalidDataException("Windows icon unreadable.");}
var icns=File.ReadAllBytes(Path.Combine(output,"sequester.icns"));if(BinaryPrimitives.ReadInt32BigEndian(icns.AsSpan(4,4))!=icns.Length)throw new InvalidDataException("ICNS length mismatch.");
var files=Directory.GetFiles(output).Order().Select(path=>new{Path=Path.GetFileName(path),Bytes=new FileInfo(path).Length,Sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))}).ToArray();
var manifest=new{Product="Quiver seQuester",SourceSha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source))),Transformation="Whole artwork resized only; white source background preserved. No crop, redraw or recolor.",NativeVisualAcceptance="Pending",Files=files};
File.WriteAllText(Path.Combine(output,"brand-assets.json"),JsonSerializer.Serialize(manifest,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(manifest));Console.WriteLine(output);
