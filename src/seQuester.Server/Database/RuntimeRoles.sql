-- Reviewed deployment helper only. Not applied automatically by migration or startup.
-- Run separately in every configured database after schema migration, with an authorized DBA identity.
-- Existing role permissions are not reset; inspect them before assigning real application users.
IF DATABASE_PRINCIPAL_ID(N'RansomFreeManagementRuntime') IS NULL CREATE ROLE RansomFreeManagementRuntime;
IF DATABASE_PRINCIPAL_ID(N'RansomFreeReceiverRuntime') IS NULL CREATE ROLE RansomFreeReceiverRuntime;
GRANT SELECT ON OBJECT::dbo.RansomFreeSchema TO RansomFreeManagementRuntime;
GRANT SELECT ON OBJECT::dbo.RansomFreeSchema TO RansomFreeReceiverRuntime;
DECLARE @name sysname;
DECLARE tables CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.tables WHERE schema_id=SCHEMA_ID(N'dbo') AND name IN
(N'enrollment',N'endpoints',N'events',N'audit',N'reports',N'endpoint_groups',N'policy_revisions',N'endpoint_groups_binding',N'incidents',N'incident_events',N'incident_notes',N'response_commands',N'response_capabilities',N'trust_native_hash_capabilities',N'incident_assignments',N'report_schedules',
 N'AspNetRoles',N'AspNetUsers',N'AspNetRoleClaims',N'AspNetUserClaims',N'AspNetUserLogins',N'AspNetUserRoles',N'AspNetUserTokens',N'UsedMfaCodes',N'RecoveryCodes',N'IdentityAudit',N'DirectoryIdentities',N'AccountControls',N'AccountRecoveries',N'OrganizationSecurity',N'tokens',N'token_options');
OPEN tables;FETCH NEXT FROM tables INTO @name;
WHILE @@FETCH_STATUS=0
BEGIN
  EXEC(N'GRANT SELECT, INSERT, UPDATE, DELETE ON OBJECT::dbo.'+QUOTENAME(@name)+N' TO RansomFreeManagementRuntime;');
  FETCH NEXT FROM tables INTO @name;
END;
CLOSE tables;DEALLOCATE tables;
IF OBJECT_ID(N'dbo.tokens',N'U') IS NOT NULL GRANT SELECT ON OBJECT::dbo.tokens TO RansomFreeReceiverRuntime;
IF OBJECT_ID(N'dbo.token_options',N'U') IS NOT NULL GRANT SELECT ON OBJECT::dbo.token_options TO RansomFreeReceiverRuntime;
IF OBJECT_ID(N'dbo.hits',N'U') IS NOT NULL
BEGIN
  GRANT SELECT ON OBJECT::dbo.hits TO RansomFreeManagementRuntime;
  GRANT SELECT, INSERT ON OBJECT::dbo.hits TO RansomFreeReceiverRuntime;
END;
-- Provision distinct SQL/Windows database users through your existing DBA process.
-- Assign the management service user to RansomFreeManagementRuntime only.
-- Assign the receiver user to RansomFreeReceiverRuntime only.
-- Do not assign either application user to db_owner or any DDL/import role.
