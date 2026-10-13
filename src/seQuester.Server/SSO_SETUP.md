# SSO and organization MFA — feature build

## Optional provider sign-out — 2026-09-12 increment

Set `EndSessionEnabled=true` on a reviewed provider to expose a separate provider sign-out action in Account security. Register `/signout-callback-oidc/<provider-id>` as its post-logout callback. A CSRF-protected POST clears local cookies and requests the configured OIDC provider's HTTPS end-session endpoint. Local Sign out remains available independently. No arbitrary return URL is accepted.

ID tokens are not retained, so this flow supplies client_id without id_token_hint. Providers may require confirmation or decline the return redirect; test the exact provider configuration. Returning from this flow is not proof that other application sessions ended. Unsolicited front-channel sign-out requests are rejected until validated session-aware support exists. Back-channel logout is still pending. No provider request was made while implementing this feature.

Implemented, unsigned and untested. No provider registration, login, directory bind or tenant change was performed. Production startup remains gated.

## OpenID Connect providers

Configure up to eight entries beneath `Sso:Providers` using secure deployment configuration. Environment-variable nesting uses double underscores; for example `Sso__Providers__0__Id`.

Each enabled entry requires `Enabled=true`, a stable alphanumeric/hyphen `Id`, `Name`, HTTPS `Authority`, exact HTTPS `Issuer`, `ClientId`, and confidential-client `ClientSecret`. Keep secrets out of source control. Each provider's callback is `https://<management-host>/signin-oidc/<Id>`.

For Entra use a tenant-specific authority and exact v2 issuer, not `common` or `organizations`. Register a web/confidential application with the exact callback. The application uses authorization code + PKCE, signature/issuer/audience/nonce validation, no token persistence and no user-info request. Every challenge requests a fresh sign-in using `prompt=login` and `max_age=0`; the token must contain an `auth_time` within five minutes. Providers without that support are intentionally rejected. CSP allows form redirects only to the configured authority origins; a provider with authorization endpoints on a different origin needs a reviewed integration update.

An administrator creates a passwordless SSO account in Accounts, selecting the configured provider and the person's immutable `sub` from a sign-in to **this application**. Unlinked users can see their own provider/subject after verified provider sign-in but get no management session. There is no public registration, email auto-linking, provider-role trust or automatic administrator assignment. The persisted login key binds the provider's exact issuer and subject; changing an issuer requires explicit reprovisioning rather than relinking by matching email.

App MFA is checked after provider authentication when enabled. Sensitive account actions and authenticator enrollment require a provider authentication no older than five minutes. Use Account security > Verify identity again to refresh it. SSO users have no local password fallback and cannot receive a local password reset. Application signout clears application/external cookies; provider-wide single logout and back-channel session revocation remain pending. Sign-in always requests fresh authentication, even if the provider session still exists.

## Organization MFA

Accounts > Organization MFA supports Optional, Administrators and Everyone. The setting is versioned and requires administrator reauthentication; the changing administrator must already have app MFA before enabling enforcement. Existing authenticated sessions without required MFA are restricted to security enrollment/recovery APIs. Required MFA cannot be disabled through the self-service endpoint. Provider MFA does not silently substitute for app MFA in this increment.

## Identity key encryption

Windows defaults to DPAPI protection. Windows or Linux can configure `IdentityKeys:CertificatePath` and a securely supplied `IdentityKeys:CertificatePassword` for a current PKCS#12 certificate containing the private key. Protect the key file and password separately, and retain encryption certificates with backups. Certificate rotation/decryption-key rollover procedures and Linux installation permissions still require acceptance work. Unconfigured Linux file-based keys are not production-approved.

References: [Microsoft OIDC guidance](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0). Runtime acceptance is recorded as pending in QA.md.
