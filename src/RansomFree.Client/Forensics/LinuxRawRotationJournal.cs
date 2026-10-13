using Microsoft.Data.Sqlite;
namespace RansomFree.Client.Forensics;
internal sealed partial class LinuxForensicJournal
{
    private static bool IsControlledRawFormat(string value)=>value is "raw-ingress-v3" or "raw-ingress-v4-rotating";
    private static void MigrateRawRotation(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();
        Execute(c,t,"""
            CREATE TABLE source_bank_formats_v13(bank_id TEXT PRIMARY KEY REFERENCES source_banks(bank_id),
              format TEXT NOT NULL CHECK(format IN ('raw-reserve-v2','raw-ingress-v3','raw-ingress-v4-rotating')));
            INSERT INTO source_bank_formats_v13 SELECT bank_id,format FROM source_bank_formats;
            DROP TABLE source_bank_formats;
            ALTER TABLE source_bank_formats_v13 RENAME TO source_bank_formats;
            PRAGMA user_version=13;
            """);
        checkpoint?.Invoke("raw-rotation-migration-before-commit");t.Commit();checkpoint?.Invoke("raw-rotation-migration-after-commit");
    }
}
