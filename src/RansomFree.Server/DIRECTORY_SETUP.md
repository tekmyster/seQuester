# Directory sign-in and account administration

Unsigned development feature. Compilation checked; functional, certificate, integration, and UI acceptance remain pending. Do not expose this build publicly.

## Connection configuration

Directory authentication is off unless explicitly enabled. Configure the server process through a protected configuration provider or environment:

- `Directory__Enabled=true`
- `Directory__Host=<confirmed LDAPS DNS hostname>`
- `Directory__Port=636` (or the confirmed TLS listener port)
- `Directory__SearchBase=<confirmed user search base>`
- `Directory__Domain=cptnyc.com`

`cptnyc.com` is the user-supplied directory domain, not a verified LDAPS host. The user located the vault at `C:\Users\dmessana\Desktop\all servers\All_Servers.kdbx`; it has been found but not decrypted. The adjacent `cptnycdc01/.env` server record provides an IP address, but does not establish the certificate-valid LDAPS hostname or user search base. The authoritative entry and local unlock method remain needed. Do not put vault passwords, directory passwords, or master keys in source code or this document.

The provider uses direct user UPN/password bind over LDAPS, then verifies the configured immutable AD objectGUID and disabled-account flag. No service bind password is required by this implementation. The user must have permission to search their own directory entry under the configured base. Referrals are disabled, LDAP filters escaped, operations bounded, and concurrent binds limited. There is no plaintext fallback or certificate-validation bypass. The platform must trust the server’s chain and validate its hostname. Linux requires compatible native LDAP libraries and correct system trust configuration; cross-compilation does not verify these requirements.

## Account provisioning

An existing Administrator opens Accounts, supplies their own current password and fresh MFA/recovery code when enabled, and creates either:

- Local: an application username, role, and password of 14–256 characters.
- Directory: an application username, directory UPN, immutable AD objectGUID, and application role. No local password is created. Prefer a recognizable sign-in alias; sign in using that configured alias.

Directory authentication never auto-links by email or grants access to every domain user. Account roles are explicitly assigned by the application administrator; directory group-to-role mapping is not implemented. Changing or recreating an AD account with a different GUID does not inherit the link. Directory usernames/UPN changes need administrator-managed link maintenance, which is not yet exposed as an edit workflow.

Accounts lists up to 500 accounts, authentication type, roles, MFA state, and enabled/disabled state. Administrators may change another account’s role/access after reauthentication; they cannot alter their own access with this route. Access changes update security stamps, invalidating existing application sessions on their next request. External AD disable is checked during password verification, not continuously throughout an existing application session; app-side revocation or session expiry is currently required for immediate restriction.

Optional application MFA works with the linked directory password for setup and reauthentication. Directory passwords remain managed by the organization; the app does not change AD passwords. Local account self-service password changes remain available. Administrator local-password/application-MFA recovery is now implemented but untested; see `ACCOUNT_RECOVERY.md`. Organization-wide MFA policy, Entra SSO, and group mapping remain separate unfinished backlog items.

## APIs

- GET `/api/v1/auth/methods`: non-secret enabled-method flags.
- GET `/api/v1/console/accounts`: Administrator only, first 500 accounts.
- POST `/api/v1/console/accounts`: creates local or explicitly linked directory accounts.
- POST `/api/v1/console/accounts/{id}`: changes role/enabled state using a concurrency stamp.

Both mutation routes require CSRF and administrator password/MFA proof, and audit without recording passwords. Directory outages return a service-unavailable response; they never fall back to a local password for a directory-linked identity.

Implementation reference: [Microsoft LdapConnection documentation](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection?view=net-10.0-pp).
