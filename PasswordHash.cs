using System.Security.Cryptography;

namespace RansomFree;

internal static class PasswordHash
{
    public static PasswordSettings Create(string password)
    {
        if(password.Length is <12 or >256)throw new ArgumentException("Use a password of 12–256 characters.");
        var salt=RandomNumberGenerator.GetBytes(32);var derived=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);
        return new(Convert.ToBase64String(salt),Convert.ToBase64String(derived));
    }
    public static bool Verify(string password,PasswordSettings settings)
    {
        if(password.Length>256)return false;
        if(settings.Iterations is <100000 or >2000000)throw new InvalidDataException("Invalid password verifier parameters.");
        var salt=Convert.FromBase64String(settings.Salt);var expected=Convert.FromBase64String(settings.Verifier);
        if(salt.Length!=32 || expected.Length!=32)throw new InvalidDataException("Invalid password verifier length.");
        var actual=Rfc2898DeriveBytes.Pbkdf2(password,salt,settings.Iterations,HashAlgorithmName.SHA256,32);
        return CryptographicOperations.FixedTimeEquals(actual,expected);
    }
}
