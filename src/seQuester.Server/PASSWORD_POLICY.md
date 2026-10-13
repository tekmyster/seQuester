# Local password policy

Host administrators choose settings in protected server configuration under `PasswordPolicy`. Restart the management server after changes. This increment provides configuration settings and read-only policy guidance in the WebUI, not a WebUI policy editor.

| Setting | Default | Allowed |
| --- | --- | --- |
| MinimumLength | 14 | 8–256 |
| RequireUppercase | true | true / false |
| RequireLowercase | true | true / false |
| RequireDigit | true | true / false |
| RequireSymbol | true | true / false |

Maximum password length remains 256. Invalid values stop startup; settings do not silently fall back. ASP.NET Identity enforces policy for bootstrap creation, administrator creation, password changes and recovery resets. Temporary recovery passwords remain at least 32 characters, satisfy all categories and grow to the configured minimum. Policy changes apply to new/reset passwords, not retroactively to existing hashes or directory/SSO credentials. Lockout, MFA, hashing, CSRF and reauthentication are unchanged. Stronger defaults now require categories; pre-existing category-free passwords can still sign in until changed.

Environment equivalents use double underscores, for example `PasswordPolicy__MinimumLength=14`. Alternatively set `RF_PASSWORD_POLICY_FILE` to an absolute JSON path containing the `PasswordPolicy` object. When supplied, this file is authoritative for password policy, with omitted fields using defaults; other configuration sections in it are ignored. Missing/malformed files fail startup. No dynamic reload occurs. The unauthenticated `/password-policy.json` endpoint contains only policy metadata for form guidance, not secrets. Enforcement remains server-side.

Requested development override is prepared at `D:\Codex\RansomFree\lab\password-policy.json`: minimum 8, uppercase/lowercase/digit required, symbol optional. It contains no password. Set `RF_PASSWORD_POLICY_FILE` to that path in the development server process when starting it. The file is not automatically discovered, and no running server was changed by this feature increment. Do not carry this lab override into enterprise deployment by accident. This is separate from endpoint maintenance/uninstall passwords.

Compilation and JavaScript syntax checks completed. Functional policy/account/recovery tests, invalid-configuration regression tests and WebUI/runtime acceptance remain pending in QA.md under the current testing scope.
