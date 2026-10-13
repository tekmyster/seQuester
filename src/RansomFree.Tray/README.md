# Read-only user tray — development, untested

This separate WinForms executable uses an asInvoker manifest and contains no administrative settings or response controls. It shows the service's recent 100 events and status, with throttled desktop notifications. Approved users can see monitored paths, usernames and process names: approval is a data-access decision. Closing the tray does not stop monitoring.

The agent's protected `tray-readers.json` contains an array of 1–32 individual local/domain user SIDs. The separate local-only pipe grants those SIDs read/write access and rechecks the impersonated user's SID. Group approval does not substitute for matching the individual user. Only `status` requests without an event ID/password are accepted; response capabilities are stripped. Approvals are loaded at service startup. Missing approvals disable this channel. Administrator IPC remains separate.

The client checks the pipe server PID/executable path against the running RansomFreeAgent SCM registration and LocalSystem account, without requesting the SYSTEM process token. The installed path must be Program Files/RansomFree/Agent/RansomFree.Agent.exe. Standard-user SCM/process-query rights need runtime validation; failure is closed. This is not an administrator-proof trust boundary.

Publish this project to a new directory. `tools/install-readonly-tray-development.ps1` provisions a fresh read-only tray after agent installation, private-state provisioning and authorized service stop. It requires unsigned-development acknowledgement, rejects existing targets/approvals/tasks, grants tray-only read access and registers a limited interactive logon task. It starts nothing. The script is syntax-checked, not executed.

Retirement requires removing the task and user's approval through authorized maintenance, then restarting the agent. Preserve evidence/configuration. Transactional rollback, in-place upgrade and a unified maintenance UI remain separate backlog work. Test SID resolution, ACLs, impersonation, SCM verification, startup/logoff, notifications and disclosure scope before deployment.
