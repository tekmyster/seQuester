# Service-backed tokens — development only

2026-09-12 local QA update: synthetic loopback WebDAV, kubeconfig denial, MCP, UDP/TCP DNS and STARTTLS SMTP receiver checks have now run; see QA.md for precise evidence and remaining native-client/external acceptance. Windows SMTP PFX loading uses DefaultKeySet because Schannel failed with EphemeralKeySet on the development host. Linux retains EphemeralKeySet and remains untested. The Windows crypto provider may use OS-managed temporary key storage on C: despite D:-based application artifacts; no PersistKeySet or trust-store installation is requested. Run under a provisioned service identity with appropriate private-key storage permissions and validate its lifecycle before release. Background-service shutdown/key cleanup after abrupt process termination remains acceptance work.

Implemented code is not verified deployment. Do not activate these in the build-only phase. All receiver services retain the Development-only startup gate. Management and receiver use the shared, pre-provisioned callback registry/inbox described in CALLBACK_SETUP.md. Never use production passwords in decoy configurations.

## Kubeconfig

Management downloads JSON-formatted YAML with a fixed context, an HTTPS receiver URL and a unique decoy bearer credential. No exec plugin or TLS bypass is included. The `/kubernetes/{id}/...` receiver validates that credential, records a hit and returns Kubernetes-shaped HTTP 403. Invalid/revoked credentials receive 401. It does not proxy to Kubernetes, execute commands or collect request bodies/resource names. TLS must be trusted by the client; copying or merely parsing the file is not a guaranteed trigger. This bearer-token implementation differs from the upstream certificate-based mechanism.

## Network Folder

Management downloads an HTTPS WebDAV URL and decoy username/password. Mapping it is an explicit deployment step in an approved client; no drive mappings or Windows service/policy changes occur automatically. `/dav/{id}/...` accepts Basic authentication only over the receiver's HTTPS transport. It supports finite-depth PROPFIND, OPTIONS and read-only GET/HEAD of an in-memory `inventory.txt`. It accepts no uploads, locking, modifications or real filesystem paths. The XML parser prohibits DTD/entity resolution, bounds request size and returns missing-property statuses. Client mapping/authentication/caching behavior needs Windows/macOS validation. No full writable WebDAV conformance is claimed.

## Unique email address

Set management `Callbacks:MailDomain` and receiver `Smtp:Domain` to the same dedicated domain. Receiver `Smtp:Enabled` must be `true`; defaults are `Smtp:BindAddress=127.0.0.1`, `Smtp:Port=2525`. Supply `Smtp:CertificatePath` and, if necessary, `Smtp:CertificatePassword` through protected configuration. The certificate requires a private key and current validity; hostname/trust validation is part of deployment acceptance.

MX routing and public TCP 25 ingress must be provisioned separately through reviewed infrastructure. This build does not configure DNS/firewalls or contact any mail server. Prefer a hardened mail gateway ahead of this bounded sink. It requires STARTTLS before mail acceptance and supports only TLS 1.2/1.3. Plaintext-only senders will not activate this variant; this restricted sink is not a general Internet mail server and does not claim full SMTP interoperability.

Only an active email-token recipient in the dedicated domain is accepted. The sink allows one recipient per transaction, 64 KiB per message, 100 commands and a 45-second session. Sessions are processed sequentially; production throughput/DoS sizing is pending. It implements EHLO/HELO, STARTTLS, MAIL, RCPT, DATA, RSET, NOOP and QUIT. It does not implement AUTH, relaying, forwarding, mailboxes, attachments or outbound responses. Message bytes are transiently read and discarded. Only token ID, timestamp, direct peer address and fixed receipt text are retained after completed DATA. Failed persistence returns a temporary SMTP failure; revocation is rechecked before recording. A sending mail server address is not the original sender's verified identity.

## DNS diagnostic variants

The MySQL artifact executes one LOAD_FILE expression against an NXDOMAIN UNC hostname. It is a Windows-only SQL-import variant requiring existing FILE privilege and compatible secure_file_priv/OS policies. It changes no tables and does not grant privileges. Hex encoding keeps the path independent of SQL backslash modes. Linux support and upstream MySQL protocol parity are not claimed. Never add address records or SMB service for the token hostname; that could initiate outbound authentication.

The Log4shell artifact contains a DNS-only JNDI lookup. It serves no Java classes, references no LDAP/RMI service, executes no commands and interpolates no host/environment values. Place it only in specifically authorized diagnostic workflows. Patched or disabled lookup behavior should prevent activation. Absence of a callback proves neither successful delivery nor absence of vulnerability. The implemented signal is resolver activity, not the upstream hostname enrichment.

Framework informational HTTP logging is suppressed in the receiver to avoid retaining query strings alongside deliberately minimized callback metadata. Reverse proxies, mail gateways and hosting infrastructure need separate logging review before deployment.

## Acceptance and sources

All functional, edge/regression and UI/runtime passes are pending in QA.md, including real Wazuh delivery. Credentials identify decoys, not authorized users, and must never authorize process response.

- https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- https://docs.canarytokens.org/guide/kubeconfig-token.html
- https://docs.canarytokens.org/guide/network-folder-token.html
- https://www.rfc-editor.org/rfc/rfc4918.html
- https://www.rfc-editor.org/rfc/rfc7617.html
- https://docs.canarytokens.org/guide/unique-email-token.html
- https://www.rfc-editor.org/rfc/rfc5321.html
- https://www.rfc-editor.org/rfc/rfc3207.html
- https://dev.mysql.com/doc/refman/8.4/en/string-functions.html#function_load-file
- https://docs.canarytokens.org/guide/mysql-dump-token.html
- https://docs.canarytokens.org/guide/log4shell-token.html
