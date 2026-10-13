using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

if(args.Length!=5)throw new ArgumentException("server-dll expected-sha256 template-xlsx callback-url output-directory");
var assemblyPath=Path.GetFullPath(args[0]);
var actual=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assemblyPath)));
if(actual!=args[1])throw new InvalidDataException("Immutable packaged server DLL differs");
var root=Path.GetFullPath(args[4]);if(Directory.Exists(root))throw new IOException("Existing output must be retained");Directory.CreateDirectory(root);
var assembly=Assembly.LoadFrom(assemblyPath);
var renderer=assembly.GetType("RansomFree.CallbackDocuments",true)!;
var method=renderer.GetMethod("Render",BindingFlags.Static|BindingFlags.Public)??throw new MissingMethodException("Actual packaged renderer missing");
var bytes=(byte[])method.Invoke(null,["xlsx",File.ReadAllBytes(args[2]),args[3]])!;
var output=Path.Combine(root,"canary.xlsx");File.WriteAllBytes(output,bytes);
var result=new{Passed=true,ServerDllSha256=actual,ServerVersion=assembly.GetName().Version?.ToString(),File=output,Sha256=Convert.ToHexString(SHA256.HashData(bytes)),Scope="Exact hash-checked packaged server renderer invoked offline; native Excel/server callback still requires independent acceptance"};
var json=JsonSerializer.Serialize(result);File.WriteAllText(Path.Combine(root,"RESULTS.json"),json);Console.WriteLine(json);
