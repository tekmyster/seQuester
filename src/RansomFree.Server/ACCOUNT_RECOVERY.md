# Administrator recovery — unsigned, untested

Implemented and compilation checked only. No runtime, security, integration, or UI acceptance has been performed for this increment.

## Administrator workflow

Open Accounts, choose another account’s Manage account action, and use Account recovery. Select local password reset, MFA reset, or both. Enter an audit reason and the exact username, then provide your own current password and a fresh second factor when your MFA is enabled. Self-recovery is not available through this route.

- Local password reset creates a random temporary password, returned once. Only the password hash is persisted. It expires after 24 hours and must be replaced before management access is allowed.
- MFA reset disables the previous authenticator, replaces its key, and removes old recovery-code records. The user must enroll a new authenticator before regaining management access.
- Both operations invalidate sessions. Disabled accounts stay disabled; recovery does not grant roles or enable access.
- Directory passwords cannot be reset here. Directory users can have application MFA reset, but still need their directory password and a working directory connection to sign in and complete setup.

The temporary password field starts concealed. Share it using an approved secure channel. The UI clears the displayed secret after two minutes, dismissal, navigation, or sign-out. Clearing the display does not revoke the credential. If the response is lost, refresh the account and perform a new authorized recovery; the original password cannot be retrieved.

## User workflow

Sign in using the current or temporary password and any still-required second factor. Recovery flags restrict API access to the account recovery routes and direct the console to Account security. Complete the password change and/or authenticator setup. These operations sign the user out; sign back in with the updated credentials. Full management access remains blocked until both required flags are cleared.

New local accounts created through Accounts also require their initial password to be replaced within 24 hours. Development bootstrap provisioning remains separate so that the first administrator can initialize the system.

## API and persistence

POST `/api/v1/console/accounts/{id}/recover` requires Administrator, CSRF, fresh primary/MFA verification, a matching `concurrencyStamp`, at least one of `resetPassword`/`resetMfa`, and an audit `reason`. Other request fields are `administratorPassword`, optional `code` or `recoveryCode`. No password or reset token is recorded in the audit action.

The additive `AccountRecoveries` table records required password/MFA steps and temporary-password expiry. `/api/v1/auth/me` returns `mustChangePassword` and `mustEnrollMfa`; Accounts also displays these flags. Recovery enforcement is server-side, not just hidden navigation. Identity security stamps invalidate old sessions. The user-facing password endpoint clears only the password requirement; authenticator activation clears only the MFA requirement.

Pending: triple-pass QA, security review, administrator recovery runbook acceptance, secure operational delivery policy, organization-wide MFA policy, and emergency recovery when no functioning administrator remains. This feature does not complete Entra/LDAP integration acceptance or the broader enterprise backlog.
