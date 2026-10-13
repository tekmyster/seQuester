# Managed endpoint feature build

Unsigned, development-only and untested. No service or logon task has been installed by this implementation turn.

`RansomFree.exe --managed-tray --tray` selects the service-backed tray. It does not instantiate the legacy per-user monitor or send duplicate monitoring alerts. Closing hides the window; Exit tray closes only the UI. Status and the latest 100 in-memory agent events arrive over a local-only named pipe. The tray requires elevation in this increment, verifies the server PID, exact installed executable path (`Program Files/RansomFree/Agent/RansomFree.Agent.exe`) and LocalSystem identity before sending any request or password.

The service pipe rejects remote clients, grants access only to SYSTEM/local administrators, retains first-instance ownership for its lifetime, bounds message size and request time, and impersonates each client to record the Windows actor. It is disabled in console QA mode. Password-gated process responses reference an event ID held by the service, never an arbitrary client PID. The event must be recent Windows 4663 evidence with a captured process identity; allowlisted, critical, Windows-directory, self and stale-identity processes are excluded. A successful reply means process exit was confirmed. A failed reply can include an unconfirmed termination request, so inspect activity before retrying.

## Future authorized installation

`tools/install-agent-development.ps1` requires explicit unsigned-development acknowledgement and fresh published agent/tray directories. It refuses existing installations, registers a stopped/manual service with recovery actions, and optionally registers an elevated interactive logon task for a specified administrator. It does not start/enroll the service, create canaries or open ports. Installation is not transactional; a partial failure is preserved for diagnosis rather than automatically deleted.

Before an authorized service run, use the installed agent's `--set-admin-password` while the service is stopped. Console password entry is masked; redirected input accepts the current password (blank on first provisioning) followed by the new password, never command-line password arguments. `--enroll --server https://...` remains a separate enrollment operation. Configure approved deployment-folder aliases as described in the server callback setup document. For an authorized boot-start deployment, an administrator must change service startup type after acceptance checks; this development installer deliberately leaves it Manual.

`tools/uninstall-agent-development.ps1` accepts a SecureString, verifies it through the installed agent, and only then stops/removes the service and logon registration. It retains installation files, settings, logs, audit configuration, and all canaries. Revoke credentials/tokens and retire canaries through reviewed management procedures. The script does not kill the tray process.

These gates do not prevent a Windows administrator, SYSTEM, offline disk access or kernel code from bypassing application controls. Kernel tamper protection, non-administrator tray access, automatic signed updates, installer rollback and legacy-state migration remain separate backlog items. No claim of unkillable or uninstall-proof protection is made.
