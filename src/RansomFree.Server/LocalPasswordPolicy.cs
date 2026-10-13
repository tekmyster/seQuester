using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

namespace RansomFree.Server;

// Host-controlled settings: changes require protected configuration access and restart.
public sealed class LocalPasswordPolicy
{
    public int MinimumLength { get; init; } = 14;
    public int MaximumLength => 256;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireLowercase { get; init; } = true;
    public bool RequireDigit { get; init; } = true;
    public bool RequireSymbol { get; init; } = true;
    public static LocalPasswordPolicy Load(IConfiguration configuration)
    {
        if(configuration["RF_PASSWORD_POLICY_FILE"] is {} path)
        {
            if(!Path.IsPathFullyQualified(path))throw new InvalidOperationException("RF_PASSWORD_POLICY_FILE must be an absolute path.");
            // This file supplies password settings only, never database/hosting/identity secrets.
            var file=new ConfigurationBuilder().AddJsonFile(path,optional:false,reloadOnChange:false).Build();
            try{return Read(file);}finally{(file as IDisposable)?.Dispose();}
        }
        return Read(configuration);
    }
    private static LocalPasswordPolicy Read(IConfiguration configuration)
    {
        var policy=configuration.GetSection("PasswordPolicy").Get<LocalPasswordPolicy>()??new();
        if(policy.MinimumLength is <8 or >256)throw new InvalidOperationException("PasswordPolicy:MinimumLength must be between 8 and 256.");
        return policy;
    }
    public void Apply(PasswordOptions options)
    {
        options.RequiredLength=MinimumLength;options.RequiredUniqueChars=1;
        options.RequireUppercase=RequireUppercase;options.RequireLowercase=RequireLowercase;
        options.RequireDigit=RequireDigit;options.RequireNonAlphanumeric=RequireSymbol;
    }
    public string TemporaryPassword()
    {
        const string alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%_-+";
        var chars=new char[Math.Max(32,MinimumLength)];
        for(var i=0;i<chars.Length;i++)chars[i]=alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        // Always satisfy every supported category, regardless of relaxed local policy.
        chars[0]="abcdefghijklmnopqrstuvwxyz"[RandomNumberGenerator.GetInt32(26)];
        chars[1]="ABCDEFGHIJKLMNOPQRSTUVWXYZ"[RandomNumberGenerator.GetInt32(26)];
        chars[2]="0123456789"[RandomNumberGenerator.GetInt32(10)];
        chars[3]="!@#$%_-+"[RandomNumberGenerator.GetInt32(8)];
        for(var i=chars.Length-1;i>0;i--){var j=RandomNumberGenerator.GetInt32(i+1);(chars[i],chars[j])=(chars[j],chars[i]);}
        return new string(chars);
    }
}
