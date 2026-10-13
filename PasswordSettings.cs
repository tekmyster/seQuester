namespace RansomFree;

internal sealed record PasswordSettings(string Salt,string Verifier,int Iterations=600000);
