# Directory session enforcement — implemented, untested

This is an opt-in addition to explicit AD account provisioning and password login. It neither retains user passwords nor automatically creates users or grants roles. No connection to the customer's directory was made during implementation.

## Protected configuration

Set `Directory:RevalidateSessions=true` alongside existing `Directory:Enabled`, `Host`, `Port` and `SearchBase`. Supply `Directory:SessionBindUser` and `Directory:SessionBindPassword` through protected server configuration. Use a dedicated read-only directory account. Never place its password in source, reports, command-line arguments or client settings.

The bind must be able to read userPrincipalName, objectGUID, userAccountControl, msDS-User-Account-Control-Computed and accountExpires, and evaluate configured membership queries. Missing required status attributes deny access. TLS trust/hostname verification is mandatory; referrals and plaintext fallback are disabled. Configuration errors prevent startup when enabled. When disabled, existing directory sessions are not revalidated and the Operations page flags that limitation.

`Directory:SessionCacheSeconds` defaults to 60, allowed range 1–300 seconds. Cached decisions delay account/group changes by that interval. Uncached validation uses four bounded query slots; LDAP operations time out after ten seconds, with a total elapsed check between membership operations. Outages fail requests closed after cache expiry; logout remains available. Disabling this option is an operator-controlled policy change, not an automatic outage fallback.

## Role restrictions

Optional `Directory:RoleRestrictions` entries have `GroupDn` and `Role` fields. Valid roles are Administrator, Operator and Reader. Up to 32 rules are accepted; matching any rule for a role allows that role only if it is already assigned locally. For example, an explicitly provisioned Operator still needs membership in a configured Operator group. A directory group alone cannot grant Administrator. Users without any remaining role receive HTTP 403.

Membership uses AD's transitive memberOf matching rule. Primary-group-only membership is not represented by memberOf; use dedicated security groups with explicit membership. This is AD-specific, not a generic LDAP mapping promise. The session API displays effective roles; account administration continues to show provisioned roles. Scheduled executive snapshots also revalidate directory owners before creating a report. An outage defers work rather than treating the owner as authorized.

## Deferred acceptance

Test nested/direct membership, lockout, expiry, rename/reuse, outage/cache behavior, role changes, report jobs, certificate validation and platform LDAP libraries. Test permission/MFA interactions after every policy change. None of these tests has run. General account auto-provisioning and provider SSO session termination are separate remaining features.

Sources: [computed account flags](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed), [AD membership filter semantics](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax).
