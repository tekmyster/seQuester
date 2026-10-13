import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { instance } from './node_modules/@viz-js/viz/dist/viz.js';
import xmljs from './node_modules/xml-js/lib/index.js';

// Documentation-only generator. Never contacts product services or token URLs.
const root = path.resolve(import.meta.dirname, '..');
const out = path.join(root, 'lucidchart-import');
const sourceRoot = 'D:/Codex/RansomFree/documentation';
const viz = await instance();
const x = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/\r/g, '&#13;').replace(/\n/g, '&#10;');
const q = s => JSON.stringify(String(s));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const palette = {
  client: ['#E8F1FF','#3769A1'], server: ['#E6F4EF','#367B66'],
  receiver: ['#F0E9FA','#8061A1'], store: ['#EDF0F5','#63748A'],
  decision: ['#FFF4D6','#AA8429'], risk: ['#FDEBEC','#AC535D'],
  pending: ['#FFF1DF','#A96C27'], process: ['#F5F7FA','#6B7C91'],
  end: ['#E7F4F2','#347D75'],
};
const wrap = (s, width = 31) => s.split('\n').flatMap(line => {
  const a=[]; let cur='';
  for (const word of line.split(' ')) {
    if (cur && cur.length + word.length + 1 > width) {a.push(cur);cur=word;}
    else cur += (cur?' ':'') + word;
  }
  a.push(cur); return a;
}).join('\n');
function page(name, nodes, edges, notes, options={}) {
  return { name, nodes: nodes.map(n => {const [id,kind,...text]=n.split('|');return {id,kind,label:text.join('|')};}),
    edges: edges.map(e => {const [from,to,label='',kind='']=e.split('|');return {from,to,label,kind};}), notes, ...options };
}
const architecture = [];
const ap = (...args) => architecture.push(page(...args));
ap('01 System overview and trust boundaries', [
  'human|process|Administrator / Operator / Reader', 'browser|client|Management browser',
  'auth|decision|Session, role, resource and CSRF checks',
  'mgmt|server|Management server\nWindows / Linux\nAccounts, policy, events, cases, reports',
  'identity|store|Identity store\nSQLite or SQL Server', 'data|store|Management store\nSQLite or SQL Server',
  'agent|client|Windows endpoint agent\nMonitoring, local policy, durable queues, safe response',
  'tray|client|Local tray / protected IPC', 'siem|process|External Wazuh / SIEM',
  'artifact|process|Distributed or copied canary', 'native|decision|Compatible activation and permitted network?',
  'receiver|receiver|Separate callback receiver\nHTTPS / optional DNS / SMTP',
  'registry|store|Token registry + callback inbox\nShared server-side storage',
  'cb|server|Callback history + callback syslog worker',
  'boundary|risk|Callback is NOT trusted Windows user/PID evidence or process-stop authority'
], ['human|browser','browser|auth','auth|mgmt|authorized','mgmt|identity','mgmt|data','agent|mgmt|Agent-initiated HTTPS','agent|tray|local IPC','agent|siem|direct syslog, if enabled','artifact|native','native|receiver|conditional callback','receiver|registry|limited lookup / append','mgmt|registry|manage tokens / read hits','registry|cb','cb|siem|callback syslog, if enabled','receiver|boundary||forbidden'],
['Local endpoint events and remote callbacks are separate evidence streams; no automatic trusted incident merge.', 'Endpoint clients require neither direct SQL access nor an inbound management port. Receiver exposes no management authority.']);
ap('02 Startup enrollment and configuration', [
 'start|server|Start management server','gate|decision|Development gate and configuration valid?',
 'stop|risk|Refuse startup / preserve existing state','provider|decision|Database provider?',
 'sqlite|store|SQLite development schema initialization','sql|store|SQL Server explicit schema/version validation',
 'run|server|Start API, WebUI and workers','admin|process|Administrator creates expiring single-use enrollment code',
 'enroll|client|Submit code + machine + version over HTTPS','valid|decision|Code valid, unused and unexpired?',
 'reject|risk|Reject enrollment','issue|server|Consume code transactionally; issue endpoint ID + credential',
 'protect|client|DPAPI-protect endpoint credential','monitor|client|Start monitor and durable delivery loop',
 'heartbeat|client|Heartbeat','policy|client|Retrieve, validate, cache and apply policy',
 'events|client|Send queued events','applied|decision|All requested application succeeded?',
 'receipt|client|Send applied-version receipt','pending|pending|Keep evidence and existing canaries; show pending; no false receipt'
], ['start|gate','gate|stop|no','gate|provider|yes','provider|sqlite|SQLite','provider|sql|SQL Server','sql|stop|incompatible schema','sqlite|run','sql|run|valid schema','run|admin','admin|enroll','enroll|valid','valid|reject|no','valid|issue|yes','issue|protect','protect|monitor','monitor|heartbeat','monitor|policy','monitor|events','policy|applied','applied|receipt|yes','applied|pending|no'],
['Offline monitoring continues from protected local state and cached policy.', 'Revocation rejects authenticated server operations; it does not erase local files or stop the monitor.']);
ap('03 Identity MFA roles and password policy', [
 'open|client|Open management console','method|decision|Sign-in method?',
 'local|server|Local password hash verification; failure counter / lockout',
 'ldap|server|Provisioned directory identity via LDAPS; bind objectGUID + UPN and account state',
 'oidc|server|Entra / generic OIDC; validate protocol and explicit immutable subject mapping',
 'proof|decision|Identity proof and approved binding valid?', 'deny|risk|Deny access and audit',
 'mfa|decision|MFA enabled / required?', 'code|server|Authenticator or unused recovery code',
 'mfavalid|decision|MFA proof valid?', 'recovery|decision|Password change or MFA enrollment required?',
 'restricted|server|Restricted recovery session until completed', 'session|server|Session + assigned local roles',
 'ad|decision|Optional AD session revalidation enabled?', 'reval|server|Bounded cached LDAPS account/group check; intersect local and allowed directory roles',
 'route|decision|Per-route role and resource authorization?', 'action|server|Authorized action + audit',
 'pw|server|Protected password policy configuration\nMinimum 8..256 + upper/lower/digit/symbol',
 'enforce|server|Startup validation; restart; enforce create/change/reset; show form guidance',
 'reset|server|Other authorized administrator + reauthentication + reason: reset password/MFA and invalidate sessions'
], ['open|method','method|local|Local','method|ldap|Directory','method|oidc|SSO','local|proof','ldap|proof','oidc|proof','proof|deny|no','proof|mfa|yes','mfa|code|yes','code|mfavalid','mfavalid|deny|no','mfavalid|recovery|yes','mfa|recovery|no','recovery|restricted|yes','restricted|session|completed','recovery|session|no','session|ad','ad|reval|yes','reval|deny|inactive / unavailable','reval|route|valid','ad|route|no','route|deny|no','route|action|yes','pw|enforce','enforce|local|new password checks','reset|restricted|forced recovery'],
['Defaults: minimum 14 and all four categories. Lab: minimum 8; upper/lower/digit required; symbol optional. No WebUI policy editor yet; existing hashes are not retroactively checked.', 'Roles: Administrator / Operator / Reader. NOC, SOC and CISO are personas, not additional roles. Provider password policies remain provider-controlled.', 'Local logout clears the session; optional OIDC logout redirects to the provider. Tenant isolation, emergency recovery and back-channel logout remain pending.']);
ap('04 Canary planning generation and deployment', [
 'plan|server|Choose endpoint group and approved folder aliases','name|server|Choose names, file types and optional token associations',
 'kind|decision|Local template or passive mechanism?', 'template|client|Local file template', 'token|server|Create opaque token; persist type/name/options; generate linked artifact',
 'resolve|client|Resolve aliases using LOCAL folder approvals', 'validate|decision|Absolute approved path, valid name/type/bounds, no traversal/reparse/collision?',
 'reject|risk|Refuse plan; preserve user data','create|client|Create NEW owned artifact; never overwrite user data',
 'baseline|store|Persist ownership, path and SHA-256 baseline','watch|client|Attach audit rule; watch and check integrity',
 'receipt|client|Applied policy receipt','change|decision|Existing canary changed or missing?',
 'pending|pending|Alert / pending; no silent replacement'
], ['plan|name','name|kind','kind|template|local','kind|token|passive','template|resolve','token|resolve','resolve|validate','validate|reject|invalid','validate|create|valid new destination','create|baseline','baseline|watch','watch|receipt','watch|change','change|pending|yes'],
['Early/middle/late names influence name sort only; they cannot guarantee position in all searches or date/size sorts.', 'Local formats: DOCX, XLSX, PDF, TXT, CSV, RTF, HTML, SVG, JSON, XML, Markdown. File format support is not passive-token support.', 'Deployment IDs fix identity/content/location. Partial failure preserves successful ownership records. Imported token documents preserve bytes, not a guarantee of callback validity or safety.']);
const implemented = ['DOCX external image','XLSX worksheet image','PDF page-open URI / optional DNS','SVG external image','Web image URL','Web bug resource','DNS hostname','QR scan and follow','Fast redirect','Slow redirect','Windows Folder icon DNS','Network Folder WebDAV','JavaScript clone','CSS clone','Kubeconfig bearer','MCP configuration','MySQL Windows DNS','Unique email SMTP','Log4shell DNS-only'];
const pendingTypes = ['Windows Fake File System','Sensitive command','Custom EXE / binary','Entra login canary','SAML IdP app','Fake app','AWS keys','AWS infrastructure','Azure certificate','WireGuard VPN','Credit card','MSSQL table token','SVN repository'];
ap('05 Complete canary mechanism catalog', [
 'catalog|server|Canary mechanism catalog\n19 implemented + 13 pending',
 ...implemented.map((s,i)=>`i${i}|receiver|${String(i+1).padStart(2,'0')} ${s}`),
 'receiver|receiver|Mechanism-specific receiver / durable callback inbox',
 'pending|pending|13 pending mechanisms\n'+pendingTypes.join('\n')
], [...implemented.map((_,i)=>`catalog|i${i}|implemented`), ...implemented.map((_,i)=>`i${i}|receiver|conditional activation`), 'catalog|pending|not implemented'],
['All 19 had local artifact/lifecycle/receiver exercises; native-client activation and external delivery are not fully accepted. QR was signature-checked, not independently decoded.', 'DNS-only variants provide no SMB, LDAP, RMI, classes or commands. WebDAV is synthetic/read-only; MCP has no executable tools; kubeconfig denies real cluster access; SMTP is a sink.', 'CrowdStrike credential catalog availability is unconfirmed and tracked separately. Copying alone is not a guaranteed passive trigger.'], {direction:'LR'});
ap('06 Local file detection and attribution', [
 'touch|client|Process touches owned monitored canary','audit|client|Windows Security audit log','watch|client|FileSystemWatcher notifications','hash|client|Periodic integrity check',
 'request|client|4656: requested access rights','used|client|4663: actual audited rights used','mutation|client|Create / change / delete / rename evidence',
 'diff|decision|Path missing or SHA-256 differs?','changed|client|Integrity change / missing evidence','continue|end|Continue monitoring',
 'actor|client|Account, executable and PID where supplied; capture stable process identity where possible',
 'normalize|client|Normalize local alert with evidence source','fan|client|Independent event fan-out'
], ['touch|audit','touch|watch','touch|hash','audit|request','audit|used','watch|mutation','hash|diff','diff|changed|yes','diff|continue|no','used|actor','actor|normalize','request|normalize','mutation|normalize','changed|normalize','normalize|fan'],
['4656 does not prove successful byte access. Read does not prove copy. A changed hash does not prove ransomware encryption.', 'Watcher/integrity events do not reliably identify the user or process. Audit availability, caching and process races matter.', 'This implementation uses audit/watchers/hashes; it is not a kernel minifilter or global virtual lock.']);
ap('07 Event fan-out offline queues and ingestion', [
 'event|client|Normalized local alert','allow|client|Tag local / managed allowlist match; retain evidence',
 'log|store|Bounded activity JSONL','tray|client|Console history / tray if running','syslog|store|Endpoint syslog outbox','spool|store|Durable management spool',
 'network|decision|Management reachable?', 'retain|client|Retain queue; report; retry', 'send|client|HTTPS bounded event batch',
 'auth|server|Authenticate active endpoint; validate event IDs, timestamps and bounds',
 'known|decision|Event ID already known?', 'persist|store|Persist new event', 'dedup|store|Identical content: deduplicate',
 'conflict|risk|Conflicting content: reject; preserve queue','reply|server|Accepted / duplicate receipt','valid|decision|Receipt valid for queued batch?',
 'remove|client|Remove acknowledged events','ui|server|Event history and case evidence', 'auto|client|Eligible non-allowlisted 4663 -> automatic-response checks'
], ['event|allow','allow|log','allow|tray','allow|syslog','allow|spool','allow|auto|qualified evidence','spool|network','network|retain|no','network|send|yes','send|auth','auth|known','known|persist|new','known|dedup|identical','known|conflict|conflicting','persist|reply','dedup|reply','reply|valid','valid|retain|no','valid|remove|yes','persist|ui'],
['Each sink is attempted independently. Queue corruption or capacity failure is surfaced, not a guarantee of zero collection loss.', 'A batch acknowledgement proves management ingestion, not SIEM receipt or malicious intent.']);
ap('08 Passive receiver validation and persistence', [
 'https|receiver|HTTPS request\nBounded and rate limited','dns|receiver|Own-zone DNS query\nNon-recursive','smtp|receiver|SMTP\nSTARTTLS, bounded single recipient',
 'validate|receiver|Mechanism-specific validation','token|decision|Known active token at recording check?',
 'nohit|end|No new hit; route-specific response','evidence|receiver|Minimal evidence: token, time, transport, peer, sanitized detail',
 'recent|decision|Recent same token / source / transport?', 'coalesce|store|Coalesce duplicate', 'append|store|Append durable callback hit',
 'response|receiver|Pixel / redirect / MCP / WebDAV / 403 / SMTP receipt / DNS NXDOMAIN',
 'history|server|Management callback history','forward|server|Callback syslog worker'
], ['https|validate','dns|validate','smtp|validate','validate|token','token|nohit|no','token|evidence|yes','evidence|recent','recent|coalesce|yes','recent|append|no','coalesce|response','append|response','append|history','append|forward'],
['Out-of-zone DNS is REFUSED. SMTP is not an outbound relay; plaintext envelope is rejected until STARTTLS. Message content is discarded.', 'Storage failure must not produce a false successful receipt. Development loopback HTTP is an explicit exception, not public HTTP support.', 'Peer IP may belong to a resolver, proxy or MTA. A callback is not trusted endpoint process identity.']);
ap('09 Endpoint and callback syslog to Wazuh', [
 'local|client|Local endpoint event','ls|decision|Effective endpoint syslog enabled?', 'outbox|store|Persist event AND destination in endpoint outbox',
 'remote|store|Durable callback inbox','rs|decision|Server callback syslog enabled?', 'cursor|server|Read after durable sequence checkpoint',
 'format|process|RFC3164 / RFC5424 formatting\nFraming, facility and severity','send|process|Configured UDP / TCP / TLS transport',
 'ok|decision|Transport send succeeded?', 'retry|pending|Retain source; retry and expose status',
 'advance|process|Endpoint: remove queued item\nCallback: persist sequence cursor','wazuh|process|External Wazuh manager decoder / rules / indexing',
 'receipt|pending|External receipt, parsing and retention verification pending'
], ['local|ls','ls|outbox|yes','remote|rs','rs|cursor|yes','outbox|format','cursor|format','format|send','send|ok','ok|retry|no','ok|advance|yes','send|wazuh|network delivery','wazuh|receipt'],
['Disabled means no new endpoint enqueue / no callback worker. Both are disabled in the recorded host lab.', 'Local events go directly from endpoint to SIEM, not through a universal server relay. Endpoint queue limit 1,000; full queue reports skipped enqueue.', 'Send success is not Wazuh acknowledgement. Crash after send before checkpoint can replay. Retry intervals: endpoint about 30s; callback about 5s.']);
ap('10 Allowlists and guarded process response', [
 'evidence|client|Observed executable + evidence','rule|decision|Exact path/hash rule with optional folder/expiry matches?',
 'allow|client|Mark allowlisted; preserve event; suppress automatic response','mode|decision|Response route?',
 'local|client|Local administrator tray: identity / IPC / maintenance-password proof',
 'remote|server|Remote administrator: reauthenticate + reason + fresh stored 4663 + active endpoint',
 'queue|store|Durable command with about 2-minute expiry; return on agent poll',
 'auto|client|Automatic policy AND local approval; recent 4663; rights, identity, dedup and rate limit',
 'permission|decision|Required local permission and command validity?', 'deny|risk|Deny; persist reason / receipt where possible',
 'journal|store|Durable response journal\nExact prior command -> recorded result\nNew command -> persist intent',
 'revalidate|decision|Same stable process; fresh eligible event; not allowlisted / unsafe?',
 'stop|client|Stop ONLY exact eligible process','outcome|store|Record outcome / response evidence','receipt|server|Remote result receipt + audit',
 'uncertain|pending|Crash after intent: indeterminate; do not blindly repeat'
], ['evidence|rule','rule|allow|yes','rule|mode|no','mode|local|manual local','mode|remote|manual remote','mode|auto|automatic','remote|queue','queue|permission','auto|permission','permission|deny|no','permission|journal|yes','local|journal|proof accepted','journal|revalidate|new intent','journal|uncertain|uncertain execution','revalidate|deny|no','revalidate|stop|yes','stop|outcome','outcome|receipt|remote command'],
['Callbacks and watcher-only evidence cannot authorize process stopping. Allowlist matches never bypass response checks.', 'Automatic stopping is default OFF and disabled in the lab. Process-tree stopping and publisher-based allowlisting remain pending.']);
ap('11 Tray IPC maintenance and tamper boundary', [
 'service|client|Privileged Windows agent service\nInstalled runtime acceptance pending','adminpipe|client|Administrator-only local pipe; service/process identity checks',
 'admintray|client|Managed administrator tray','password|decision|Supported protected action: password proof valid?',
 'action|client|Authorized settings / response / maintenance action','denied|risk|Deny protected action',
 'readonly|client|Separate read-only pipe; approved individual SIDs, ACL and caller verification','usertray|client|Read-only user tray; status / activity only',
 'event|client|Receive event; update history; throttled desktop balloon',
 'close|client|Close window -> remain in tray\nExit tray -> agent remains independent',
 'lab|client|Lab console agent -> private activity log','observer|pending|Explicit lab-log observer\nLaunch blocked at checkpoint',
 'boundary|risk|Local administrator / SYSTEM can still force changes outside the application'
], ['service|adminpipe','adminpipe|admintray','admintray|password','password|action|yes','password|denied|no','service|readonly','readonly|usertray','admintray|event','usertray|event','event|close','lab|observer','action|boundary|security limit'],
['Ordinary users are constrained by protected state and IPC, not an administrator-proof unkillable/uninstallable lock.', 'Existing older standalone tray is separate from the lab observer. Transactional installer recovery, updater and rollback remain pending.']);
ap('12 Management WebUI personas and glance views', [
 'session|server|Authorized authenticated session','noc|server|NOC\nFleet / Operations','soc|server|SOC\nAlerts / Incidents','ciso|server|CISO\nOverview / Reports',
 'fleet|server|Last contact, version/revocation, desired/applied policy, storage/delivery and stale warnings',
 'triage|server|Event source, actor limits, callback history; link evidence, assign, note and triage',
 'summary|server|Selected period, fleet/event aggregates, incident counts and saved snapshots',
 'diagnose|server|Diagnose connectivity / configuration','response|server|Optional guarded response / case maintenance','export|server|Authorized TXT / formatted PDF',
 'accounts|server|Accounts / MFA / identity recovery','policies|server|Groups / versions / deployments / allowlists / response','canaries|server|Token create / download / revoke; callback history','ops|server|Storage / configuration / delivery status',
 'audit|store|Authorized mutations are audited','ux|pending|Senior UX/UI redesign and formal handoff pending'
], ['session|noc','session|soc','session|ciso','noc|fleet','soc|triage','ciso|summary','fleet|diagnose','triage|response','summary|export','session|accounts','session|policies','session|canaries','session|ops','diagnose|audit','response|audit','accounts|audit','policies|audit','canaries|audit','audit|ux|presentation work'],
['NOC/SOC/CISO are use cases, not backend security roles. Exact route authorization remains authoritative.', 'Functional foundations are not completed enterprise UX. Event counts do not justify invented risk scores or protection percentages.']);
ap('13 Incidents executive reports and schedules', [
 'event|store|Stored local endpoint event','create|server|Analyst selects evidence; create case title + severity',
 'case|store|Case: Open / Investigating / Resolved\nOwner, notes and evidence links','change|server|Authorized status / severity / owner / note change',
 'version|decision|Expected version still current?', 'conflict|pending|Conflict: refresh before changing','persist|store|Persist case + evidence + audit','caseexport|server|Authorized case TXT / formatted PDF',
 'period|client|User selects time period','check|server|Capacity, ownership and role checks','snapshot|store|Immutable aggregate snapshot + history','export|server|Authorized executive TXT / PDF',
 'schedule|store|Interval schedule + owner','due|decision|Due and owner still active / authorized?',
 'pause|pending|Pause / report reason; no false completion','dir|server|Optional directory-owner revalidation','tx|server|Transactional snapshot + next run + audit'
], ['event|create','create|case','case|change','change|version','version|conflict|no','version|persist|yes','persist|caseexport','persist|case|further updates','period|check','check|snapshot','snapshot|export','schedule|due','due|pause|unauthorized / capacity','due|dir|yes','dir|tx|allowed','dir|pause|denied','tx|snapshot'],
['Case statuses are not a strict one-way state machine; authorized updates can change them.', 'Incident escalation, custom report builder, large background exports/cancellation and scheduled external delivery remain pending.']);
ap('14 Server storage migration and scale', [
 'mgmt|server|Management + identity components','receiver|receiver|Receiver restricted registry / inbox access','provider|decision|Configured server-side provider?',
 'sqlite|store|SQLite lab\nmanagement.db / identity.db / tokens.db / hits.db','sql|store|SQL Server\nValidated encrypted connections; explicit schema versions',
 'express|store|Local SQL Server Express instance','scale|store|Dedicated instance / larger edition\nSame application model; configured cutover',
 'dba|process|DBA creates empty database + migration identity','schema|server|Application lock; per-component schema transaction / version / checksum','runtime|server|Restricted runtime identity verifies schema','reject|risk|Reject incompatible / unversioned schema; preserve data',
 'offline|process|Optional SQLite import: stop writers, backup and acknowledge offline cutover','preflight|decision|Source fingerprints / sidecars valid; target empty or identical prior import?',
 'copy|server|Bounded typed copy; preserve IDs; count and fingerprint checks','commit|store|Commit per component and record import; identical retries resume',
 'cutover|process|Preserve identity keys / callback checkpoint; review before startup','ha|pending|Multi-node worker leases, leadership, keys, HA and backup/restore acceptance pending'
], ['mgmt|provider','receiver|provider','provider|sqlite|SQLite','provider|sql|SQL Server','sql|express','express|scale|capacity decision','dba|schema','schema|runtime','runtime|reject|mismatch','offline|preflight','preflight|reject|invalid','preflight|copy|valid','copy|commit','commit|cutover','scale|ha|not automatic HA'],
['SQL is server-side only. LocalDB/user-instance/attached-file modes are rejected; endpoints do not need SQL.', 'Changing provider does not migrate or delete SQLite. Later import failure can leave earlier components committed; no silent merge. Source files remain.', 'Rollback after new SQL writes requires reconciliation. Future schema upgrades require explicit versioned engineering. SQL runtime acceptance remains pending.']);
ap('15 Health errors and recovery', [
 'loop|process|Agent / server background work','audit|pending|Audit unavailable -> degraded attribution; watcher/hash continues',
 'gap|pending|Watcher gap/overflow -> warn; integrity observes changed state, not every missed operation',
 'network|client|Network / TLS / auth failure -> preserve spool and retry appropriately','policy|client|Invalid / unapproved policy -> preserve canaries; no success receipt',
 'capacity|pending|Queue / inbox / report capacity -> visible rejection / pause; preserve evidence',
 'corrupt|pending|Corrupt queue / journal / cursor -> preserve file; restrict affected worker/action',
 'stale|server|Missing heartbeat -> fleet stale; not proof of compromise','read|server|Storage read success -> component readability only',
 'diagnose|client|Read-only server-origin diagnostic','checks|client|DNS -> connect -> TLS -> HTTP -> API contract','result|client|Reachable or classified failure','pending|pending|Unified reachability, receiver-worker readiness and metrics pending'
], ['loop|audit','loop|gap','loop|network','loop|policy','loop|capacity','loop|corrupt','loop|stale','loop|read','diagnose|checks','checks|result','result|pending'],
['Diagnostics do not enroll credentials, write application data or open firewall ports.', 'Liveness success is not successful enrollment, event delivery, production readiness or zero-loss collection.']);
ap('16 Host lab topology and historical evidence', [
 'browser|client|Same-host browser','web|server|HTTP 127.0.0.1:18080\nManagement WebUI / API','agent|client|Windows console agent',
 'api|server|Pinned HTTPS localhost:18443\nAgent management API','targets|store|D:\\Codex\\RansomFree\\LabTargets\nDocuments / Finance / Backups / IT / Shared',
 'files|client|Each folder: DOCX + XLSX + PDF + SVG\n5 x 4 = 20 owned canaries','read|client|Read owned canary -> 4656 / 4663 -> durable spool',
 'db|store|SQLite management / identity data','callback|receiver|HTTPS localhost:18444\nReceiver + SQLite registry / inbox','probe|client|Manual HTTP loopback probe 127.0.0.1:18081',
 'evidence|end|Recorded checkpoint: 42 events; all 20 paths; 21 content reads; one manual callback',
 'limits|pending|Observer launch blocked; Wazuh / automatic stop / DNS / SMTP disabled; no installed reboot-start services'
], ['browser|web','agent|api|agent-initiated HTTPS','agent|targets','targets|files','files|read','read|api','api|db','files|callback|conditional native activation','probe|callback|manual probe','db|evidence','callback|evidence|manual hit only','evidence|limits'],
['Historical 2026-09-12 checkpoint, NOT a live status query. Loopback only; no remote access/firewall openings, profile/OS/share seeding or new trust-store certificate.', 'Package root D:\\Codex\\RansomFree\\lab\\release-20260912; state/logs under lab\\host. No credentials are included.', 'Copies on another machine still point to localhost on THAT machine; cross-machine callbacks to this host are not configured.']);
ap('17 Engineering UX handoff and release gates', [
 'current|process|Current implementation and isolated host lab','backlog|pending|Complete engineering backlog\n13 tokens; deployment lifecycle; tenant isolation; installer/updater/rollback',
 'security|pending|Recovery / SSO sessions; publisher allowlists / process trees; retention / backup; health / HA',
 'reporting|pending|Incident escalation; report builder; large exports / cancellation / external delivery',
 'ux|pending|Senior UX/UI redesign + formal handoff\nClear names; NOC/SOC/CISO glance views; accessible states',
 'qa|decision|Three distinct QA passes for every feature complete?',
 'functional|process|1 Functional\nNormal path + persisted state','edge|process|2 Edge / regression\nFailures, invalid input, preserved user data','ui|process|3 UI / runtime\nScreens, packages, tray and startup',
 'fix|pending|Record failures / pending; fix and rerun affected passes','accept|pending|Integration, scale, restore, security, platform and deployment acceptance',
 'sign|pending|Signing / distribution / release approval','release|end|Production release candidate\nNOT reached by this checkpoint'
], ['current|backlog','backlog|security','security|reporting','reporting|ux','ux|functional','ux|edge','ux|ui','functional|qa','edge|qa','ui|qa','qa|fix|no','fix|qa|rerun affected checks','qa|accept|yes','accept|sign','sign|release'],
['Compilation is not functional QA; three repeats of one suite are not three distinct passes.', 'Generation is not native activation; a transport send is not Wazuh receipt. This project has not completed this release flow.']);
ap('18 Implementation source map', [
 'app|process|Ransom Free source map','server|server|Server / Program.cs\nStartup and API','identity|server|HumanIdentity / LocalPasswordPolicy / DirectorySessions\nAccountAdministration / AccountRecovery',
 'policy|server|Server + Contracts / Policies.cs','agent|client|Agent / Program.cs\nMonitor / Audit / ProcessControls',
 'canary|client|CanaryTemplates / CallbackDocuments\nManagedDeployments / DeploymentPathLease',
 'receiver|receiver|Receiver / Program.cs + tripwires\nCallbackManagement / CallbackStorage',
 'transport|client|ManagementClient / EventSpool\nSyslog / CallbackSyslog','response|client|ResponseCommands / ResponseJournal / AutomaticResponder',
 'tray|client|ManagedDashboard / ManagedAgentConnection\nAgentConsoleService / ReadOnlyConsoleService\nTray / Program.cs / LabLogTray',
 'reports|server|Incidents / IncidentExports\nReports / ReportSchedules','storage|store|DatabaseSettings / SqlServerSchema\nDatabaseMigration / SqliteImport / Database SQL',
 'ops|server|OperationsHealth + client diagnostics','evidence|process|QA.md / CANARYTOKENS_ALIGNMENT.md / LAB-STATUS.md','backlog|pending|CLIENT_SERVER_BACKLOG.md / ENTERPRISE_PLAN.md / UX_HANDOFF.md'
], ['app|server','server|identity','server|policy','app|agent','agent|canary','app|receiver','agent|transport','agent|response','agent|tray','server|reports','server|storage','server|ops','app|evidence','app|backlog'],
['Source filenames are implementation references, not claims of passing runtime acceptance. Older status prose may describe historical checkpoints.']);

const workflows=[]; const wp=(...args)=>workflows.push(page(...args));
wp('01 Client and server interaction map', [
 'provision|client|CLIENT: approved local provisioning','enroll|client|Submit enrollment','credential|client|Protect endpoint credential','monitor|client|Monitor approved owned files',
 'policy|client|Poll policy; validate / cache / apply','events|client|Evidence -> durable event spool','responses|client|Poll commands; check local permission / identity / journal','syslog|client|Local syslog queue',
 'admin|server|SERVER: administrator creates code','validate|server|Validate and consume code','inventory|server|Endpoint inventory / heartbeat','assignment|server|Assigned policy + desired/applied state',
 'ingest|server|Validate / deduplicate / persist events','commands|server|Durable authorized expiring response requests','audit|server|Response outcomes + audit','views|server|Alerts / cases / reports',
 'wazuh|process|EXTERNAL: Wazuh / SIEM','use|process|ANY CLIENT: compatible canary activation','receiver|receiver|ISOLATED RECEIVER','inbox|store|Shared registry / callback inbox','callbacks|server|Callback history + syslog worker'
], ['admin|provision|Code delivered by administrator','provision|enroll','enroll|validate|F01 request','validate|credential|F02 response','credential|monitor','monitor|inventory|F03 heartbeat','monitor|policy','policy|assignment|F04 request / F06 receipt','assignment|policy|F05 response','monitor|events','events|ingest|F07 batch','ingest|events|F08 receipt','ingest|views','responses|commands|F09 poll','commands|responses|F10 response','responses|audit|F11 result','monitor|syslog','syslog|wazuh|F12 syslog','use|receiver|F13 callback','receiver|inbox|restricted lookup / append','inbox|callbacks','callbacks|wazuh|callback syslog'],
['CLIENT means Windows endpoint plus local tray; the management browser is a separate actor. All F01..F11 connections are initiated by the endpoint; reverse arrows are replies, not server push.', 'Callbacks share server-side registry/inbox storage. There is no fabricated receiver-to-management event POST.'],{direction:'LR'});
wp('02 Client-only runtime policy and response', [
 'start|client|Start agent; load protected state / DPAPI credential / inventory / hashes / cached policy / queues / permissions',
 'valid|decision|State readable and valid?', 'failure|pending|Preserve data; report affected failure','monitor|client|Audit 4656 / 4663 + watcher + integrity',
 'event|client|Normalize ID/time/path/operation/source; optional user/process/PID','allow|client|Tag local + managed allowlist match; retain evidence','fan|client|Independent delivery destinations',
 'local|client|Activity log + local console / tray','spool|store|Management spool -> F07/F08','syslog|store|Syslog outbox -> F12',
 'auto|decision|Eligible recent 4663 + policy + local automatic-stop approval?', 'journal|store|Dedup / rate limit / durable intent','identity|decision|Fresh safe stable process identity, not allowlisted?',
 'stop|client|Exact-process stop; persist outcome; no blind replay','policy|client|F05: validate revision / bounds; cache','deploy|client|Resolve LOCAL approved aliases; reject forbidden paths / reparse / collisions',
 'create|client|Create new owned files; persist hash / ownership; audit','receipt|client|F06 only on successful application','manual|client|Manual local: password + IPC\nManual remote F10: local approval + journal -> F11'
], ['start|valid','valid|failure|no','valid|monitor|yes','monitor|event','event|allow','allow|fan','fan|local','fan|spool','fan|syslog','fan|auto','auto|journal|all prerequisites','journal|identity','identity|stop|eligible','identity|failure|reject','policy|deploy','deploy|create|valid new files','deploy|failure|invalid / changed existing','create|receipt','manual|journal|authorized'],
['Monitoring continues while management is unavailable. Missing/changed managed files are not silently replaced; failed policy application has no false success receipt.', 'Automatic response needs no server round trip per event, but requires policy AND local approval. Watcher/callback-only events never authorize stop.']);
wp('03 Server-only API identity storage and workers', [
 'start|server|Development gate; validate config, provider, schema and keys','run|server|Start WebUI / API / workers','human|server|Local / LDAPS / OIDC identity; MFA / recovery / lockout; role checks',
 'actions|server|Accounts, enrollment, policy, tokens, incidents, response, reports, operations','api|server|Endpoint API authentication / active endpoint / request validation','tx|server|Transactional enroll / heartbeat / policy / events / responses',
 'workers|server|Report scheduler / operations probe / callback syslog','state|store|Durable management / identity / registry / inbox state','read|server|Authorized WebUI readback / TXT / PDF',
 'command|server|Admin reauth + reason + fresh eligible stored 4663 -> durable expiring command','poll|server|Wait for F09 agent poll; return F10','result|server|F11 result or visible expiry / no final receipt',
 'schedule|server|Due report: recheck owner access / optional directory validation','snapshot|store|Immutable snapshot + next run + audit','pause|pending|Pause / report failures; no false completion'
], ['start|run','run|human','run|api','run|workers','human|actions','actions|state','api|tx','tx|state','workers|state','state|read','actions|command|guarded response','command|poll','poll|result','result|state','workers|schedule','schedule|snapshot|allowed','schedule|pause|denied / capacity','snapshot|read'],
['Password policy is protected startup configuration; local password rules do not override LDAP/OIDC rules. Optional directory revalidation can reduce local roles, not auto-provision or grant roles.', 'SQLite is current lab storage. SQL Server with explicit schemas is implemented but runtime acceptance is pending. Multi-node coordination / HA remain pending.']);
const contracts = [
 ['F01','CLIENT','MANAGEMENT','POST /api/v1/enroll','One-time code, machine name, agent version. Invalid/expired/consumed -> reject.'],
 ['F02','MANAGEMENT','CLIENT','Enrollment response','Endpoint ID + unique credential. Protect with DPAPI; never log the credential.'],
 ['F03','CLIENT','MANAGEMENT','POST /api/v1/agent/heartbeat','Agent version + health; authenticated endpoint. Update last-seen / inventory.'],
 ['F04','CLIENT','MANAGEMENT','POST /api/v1/agent/policy','Authenticated request for current assigned policy.'],
 ['F05','MANAGEMENT','CLIENT','Assigned-policy response','Group/revision, integrity interval, deployments, tokens, syslog, allowlist, response. Local folder approval still required.'],
 ['F06','CLIENT','MANAGEMENT','POST /api/v1/agent/policy/receipt','Applied group + revision. Reject stale or mismatched desired version.'],
 ['F07','CLIENT','MANAGEMENT','POST /api/v1/agent/events','Bounded unique-ID event batch; optional actor fields. Validate, persist, deduplicate; reject conflicting reused IDs.'],
 ['F08','MANAGEMENT','CLIENT','Batch receipt','Accepted + duplicate counts. Validate against batch before removing queued events; otherwise retain.'],
 ['F09','CLIENT','MANAGEMENT','POST /api/v1/agent/responses','Poll pending unexpired commands for this endpoint.'],
 ['F10','MANAGEMENT','CLIENT','Pending-command response','Command/event IDs, action, requesting actor, reason, timestamps. Agent applies local checks and replay journal.'],
 ['F11','CLIENT','MANAGEMENT','POST /api/v1/agent/responses/receipt','Command ID, outcome, bounded result. Success / failure / rejection / indeterminate; no receipt does not mean success.'],
 ['F12','CLIENT','WAZUH / SIEM','UDP / TCP / TLS syslog','Formatted local event; queued destination. Transport send does not prove SIEM parsing or retention.'],
 ['F13','ACTIVATING CLIENT','ISOLATED RECEIVER','HTTPS / DNS / STARTTLS SMTP','Token request or decoy credential use. Caller may be remote reader, proxy, resolver, MTA or integration; no trusted local PID.'],
];
wp('04 F01-F13 cross-boundary contracts', [], [], ['F01..F11 are endpoint-initiated HTTPS exchanges. F02/F05/F08/F10 are responses on those requests, not server push.', 'Credential values are intentionally omitted. Server-side SQL connections are separate from endpoint contracts.'], {contracts});
wp('05 Passive callback lanes and shared storage', [
 'use|client|ACTIVATING CLIENT\nArtifact / token use','transport|receiver|RECEIVER\nTransport validation','token|receiver|Lookup active token; mechanism checks','minimal|receiver|Minimal callback evidence','inbox|store|Shared callback inbox\nDedup + durable hit',
 'reply|client|Mechanism response\nPixel / redirect / NXDOMAIN / SMTP / WebDAV / MCP / denial','registry|store|Shared token registry','admin|server|MANAGEMENT\nAuthorized token create / revoke / download','history|server|Read callback inbox for UI','worker|server|Read inbox after sequence checkpoint','wazuh|process|External Wazuh / SIEM',
 'routes|receiver|HTTPS resources / redirects / clone images\nDNS tokens / folders / MySQL / Log4shell\nBearer / MCP / WebDAV / SMTP',
 'boundary|risk|No receiver management API, endpoint credential, real share, recursive DNS or SMTP relay'
], ['use|transport|F13','transport|token','registry|token|restricted registry read','token|minimal','minimal|inbox','inbox|reply|response to caller','admin|registry','inbox|history','inbox|worker','worker|wazuh|callback syslog','routes|transport|mechanism route','transport|boundary|authority boundary'],
['Receiver and management share configured registry/inbox access, not an event POST or required push channel.', 'PDF may additionally use token-host DNS. DNS and SMTP are enabled separately. Remote peer IP is not Windows actor identity; callback hits cannot authorize process stopping.'], {direction:'LR'});
wp('06 Browser console workflow', [
 'open|client|BROWSER: open management console','static|server|SERVER: serve static WebUI','signin|client|Choose local / directory / SSO sign-in','identity|server|Identity + MFA + recovery + role checks','session|client|Authenticated or restricted session',
 'read|client|NOC fleet / SOC evidence / CISO reports','data|server|Authorized data queries','mutate|client|Settings / case / response request\nSession + CSRF + required reauthentication','authorize|decision|Per-route permission + resource / input / version valid?',
 'commit|server|Transaction + audit','deny|server|Denial / conflict; no unauthorized mutation','result|client|Render result / conflict / denial','export|client|Request TXT / PDF','ownership|server|Ownership / role checks','download|client|Authorized download'
], ['open|static|HTTP(S)','static|signin|WebUI','signin|identity|identity flow','identity|session|cookie / result','session|read','read|data|request','data|read|authorized response','session|mutate','mutate|authorize','authorize|commit|yes','authorize|deny|no','commit|result','deny|result','session|export','export|ownership','ownership|download|authorized'],
['Management browser is NOT the endpoint agent. Browser changes reach endpoints on their next poll.', 'Browser JavaScript cannot replace local monitoring or local response. NOC/SOC/CISO are presentation personas, not security roles.'],{direction:'LR'});
wp('07 Cross-boundary failure and retry paths', [
 'client|client|Client failure / uncertain state','offline|client|Offline -> keep monitoring and queue; retry','auth|server|Invalid credential -> reject; surface authentication failure',
 'timeout|client|Batch timeout -> retry same IDs; server deduplicates','conflict|risk|Same ID / changed content -> reject and preserve queue',
 'policy|client|Cannot apply policy -> no receipt; desired/applied mismatch','old|server|Stale policy receipt -> reject; client retrieves current policy',
 'identity|client|Stale process -> reject and send result if possible','crash|pending|Crash after intent -> indeterminate; no blind replay','missing|server|Missing result -> expiry / no final receipt, not success',
 'callback|receiver|Callback / delivery failure','token|receiver|Unknown / revoked token -> no new hit; route-specific response','bad|receiver|Malformed / unauthorized -> reject, no new authority','duplicate|store|Recent duplicate -> coalesce','storage|pending|Storage failure -> surface; no false successful receipt','network|pending|No external connectivity -> absence of hit proves nothing','syslog|pending|Send / cursor failure -> preserve source and retry'
], ['client|offline','client|auth','client|timeout','client|conflict','client|policy','client|old','client|identity','client|crash','client|missing','callback|token','callback|bad','callback|duplicate','callback|storage','callback|network','callback|syslog'],
['Event ingestion receipt is not SIEM delivery acknowledgement. Process-action receipt is not proof that ransomware was eradicated.']);
wp('08 Historical lab client-server overlay', [
 'agent|client|CLIENT\nWindows console agent\n20 monitored D: canaries / cached state / audit','api|server|SERVER\nHTTPS localhost:18443\nSQLite management / identity','browser|client|Management browser','web|server|HTTP 127.0.0.1:18080',
 'artifact|client|Preserved embedded token / compatible use','receiver|receiver|HTTPS localhost:18444\nHTTP loopback probe :18081\nSQLite registry / inbox','old|client|Older standalone tray: separate','observer|pending|New lab observer: launch blocked','evidence|end|Checkpoint: Monitoring, 42 events / 20 paths / 21 content reads; one manual callback','disabled|pending|Not enabled / accepted: Wazuh, auto-stop, DNS/SMTP, remote WebUI, installed services, SQL runtime, native-reader matrix'
], ['agent|api|agent-initiated pinned HTTPS','browser|web','artifact|receiver|conditional callback','agent|observer|private activity log','agent|evidence|local evidence persisted','receiver|evidence|manual loopback hit','evidence|disabled'],
['This is the observed 2026-09-12 checkpoint, not a live probe. No services, files, firewall rules or settings are changed by these diagrams.', 'On another machine, localhost points to that machine, not this receiver. Cross-host copied-file callbacks require an explicitly reachable trusted receiver.'],{direction:'LR'});

const canaries=[]; const cp=(...args)=>canaries.push(page(...args));
cp('00 Shared local and remote action paths', [
 'file|client|Artifact path chosen','registered|decision|Registered with functioning endpoint monitor?',
 'no|pending|No local alert promised; remote activation may still work','action|decision|Actual file operation?',
 'handle|client|Request handle -> 4656 requested rights; access may fail','read|client|Read contents -> audited 4663 ReadData','copy|client|Copy -> source read; destination written but NOT automatically monitored','move|client|Rename/move -> visible path events; old path may be missing','write|client|Edit/save/replace -> audited write / watcher / changed hash','encrypt|client|Encrypt -> reads/writes/rename + changed bytes; token may become inert','delete|client|Delete -> audited delete / watcher / missing path; no deletion-specific callback','acl|client|Permissions -> audit/security event if available; hash need not change','search|client|Search/list/preview -> metadata need not read bytes; preview may read/fetch',
 'local|client|L: local evidence -> log / tray / spool / enabled endpoint syslog','response|client|Only eligible local evidence -> guarded response checks',
 'use|process|Compatible interpretation / use of preserved token','active|decision|Active token + reachable trusted receiver + client permits activation?',
 'remote|receiver|R: isolated receiver -> validate / token lookup / dedup -> callback inbox','view|server|Callback history + enabled server callback syslog','none|pending|No callback receipt promised','boundary|risk|R is not trusted user/PID and cannot authorize process stop'
], ['file|registered','registered|no|no','registered|action|yes',...['handle','read','copy','move','write','encrypt','delete','acl','search'].map(id=>`action|${id}`),...['handle','read','copy','move','write','encrypt','delete','acl','search'].map(id=>`${id}|local|if observable`),'local|response|qualified audit evidence','read|use|conditional interpretation','copy|use|later use of preserved copy','search|use|compatible preview','no|use|passive use independent','use|active','active|remote|yes','active|none|no','remote|view','remote|boundary||forbidden'],
['Generation/download does not automatically monitor the saved path. Text/config/script/SQL specimens need explicit local monitoring.', 'Read is not confirmed copy; modification is not confirmed ransomware; callbacks may come from proxies/scanners/resolvers. Local and remote paths may both fire, one may fire, or neither may be observed.']);
const specs = [
 {name:'01 Word DOCX',artifact:'DOCX with external image relationship', action:'Open / preview in Word-compatible reader',condition:'Reader permits external image loading?',steps:['HTTPS token-image request'],response:'Small image response',notes:['Native Word / Protected View / external-image policy and external receipt remain pending. Local QA inspected package/XML/linkage and manually invoked the receiver.']},
 {name:'02 Excel XLSX',artifact:'XLSX with external worksheet-image relationship',action:'Open / preview in Excel-compatible reader',condition:'Worksheet external image fetched?',steps:['HTTPS token-image request'],response:'Small image response',notes:['Recalculation alone is NOT the implemented mechanism. Native Excel/preview/trust-policy activation remains pending.']},
 {name:'03 Acrobat PDF',artifact:'PDF page-open URI action',action:'Reader opens page and interprets URI action',condition:'Reader honors / permits URI action?',steps:['Resolve configured URI host','Common receiver host: HTTPS request; token-specific DNS host: DNS query may record without HTTPS'],response:'URI endpoint response OR DNS NXDOMAIN',notes:['Token-zone NXDOMAIN can prevent HTTPS resolution after a DNS hit. Lab uses localhost HTTPS, not delegated DNS.', 'Reader prompts, native execution and formatting acceptance remain pending.']},
 {name:'04 SVG image',artifact:'SVG XML external-image reference',action:'Render / preview SVG in compatible viewer',condition:'Renderer allows external resources?',steps:['HTTPS external-image fetch'],response:'Small image response',notes:['Opening SVG as text is a local read, not rendering. Image mode and document mode can have different external-resource policies.', 'Actual viewer/browser compatibility remains pending.']},
 {name:'05 Web image',artifact:'Text artifact containing HTTPS token-image URL',action:'Open URL or embed URL as an image',condition:'Client actually fetches token URL?',steps:['HTTPS image request'],response:'Small PNG response',notes:['Reading/copying the URL as text does not fetch it. Copying already-saved PNG bytes does not guarantee token-link activation.', 'Remote tripwire is the URL, not arbitrary raster bytes. Native loading and external delivery remain pending.']},
 {name:'06 Web bug',artifact:'Unique HTTPS resource URL in approved page/document/message',action:'Open embedding content',condition:'Remote resource loaded?',steps:['HTTPS resource request; may originate from proxy / scanner / prefetcher'],response:'Small resource / image response',notes:['Reading token text is not a fetch. Proxy/scanner activation does not establish a human reader, recipient identity or intent.']},
 {name:'07 DNS token',artifact:'Unique hostname under configured token zone',action:'Client requests hostname resolution',condition:'Query reaches authoritative token receiver?',steps:['Resolver / delegation path','UDP or TCP token-zone DNS query'],response:'DNS NXDOMAIN; unrelated zones REFUSED',notes:['Reading hostname text does not resolve it. Resolver caching can suppress repeat queries; source may be a resolver.', 'Local UDP/TCP and zone handling verified; external delegation/resolvers/reachability remain pending.']},
 {name:'08 QR code',artifact:'PNG encoding a token URL',action:'Scan image and decode URL',condition:'Client follows decoded link?',steps:['HTTPS request to decoded token URL'],response:'Token endpoint response',notes:['Image display alone does not navigate. Editing/resizing may damage QR readability; a copied intact image may be scanned later.', 'Independent QR decoding, scan-to-open and external receipt remain pending. Local QA checked PNG signature and receiver route only.']},
 {name:'09 Fast redirect',artifact:'Artifact containing unique redirect URL',action:'Follow token URL',condition:'Active redirect token request accepted?',steps:['Record / coalesce callback BEFORE returning redirect'],response:'HTTP redirect to configured HTTPS destination',after:'Client may follow destination; final destination success is not proven',notes:['Reading/copying URL text is not navigation. Local QA inspected Location without following the destination.']},
 {name:'10 Slow redirect',artifact:'Artifact containing delayed redirect URL',action:'Follow token URL',condition:'Active redirect token request accepted?',steps:['Record / coalesce callback BEFORE delay'],response:'Wait about 2 seconds; if request and token remain active, redirect',after:'Cancellation / revocation may prevent redirect; callback may already exist',notes:['Callback precedes the delay. This is not a scheduled reminder. Local delay/response verified; complete cancellation/browser acceptance pending.']},
 {name:'11 Windows Folder',artifact:'ZIP: folder attributes + desktop.ini remote-icon reference',action:'Extract with required attributes; Explorer browses / previews folder',condition:'OS version / policy / cache permits remote icon resolution?',steps:['Token-host DNS lookup'],response:'NXDOMAIN stops resolution',notes:['Reading/copying ZIP alone need not resolve an icon. Preserved extracted attributes/reference may activate on later browsing.', 'Do NOT add address records or SMB service: this variant is DNS-only and must not introduce Windows authentication collection.', 'Native Explorer, attributes, caching and policy acceptance pending; QA did not extract folders or map remote shares.']},
 {name:'12 Network Folder WebDAV',artifact:'HTTPS WebDAV URL + synthetic decoy credentials',action:'Approved WebDAV client presents Basic credentials over HTTPS',condition:'Exact decoy credential + active token?',steps:['Valid credential presentation records even if later operation is denied'],response:'PROPFIND: finite listing; GET inventory.txt: synthetic text; PUT/DELETE/LOCK: denied',after:'Remote GET may create/coalesce a hit; copied synthetic text has no built-in callback',notes:['OPTIONS without credentials is not the credential-use trigger. No real filesystem, upload store or domain credentials.', 'Deleting local configuration is separate from retiring a mapping. Native WebDAV, trusted TLS and mapping lifecycle remain pending.']},
 {name:'13 JavaScript cloned website',artifact:'Generated JavaScript compares page origin to approved origin',action:'Execute script in page (not merely read script file)',condition:'Page origin differs from approved origin?',steps:['Create Image request; CSP / browser / network can block it'],response:'HTTPS token-image response',notes:['Approved origin produces no image request. Copying or cloning only activates when the script executes in a qualifying context.', 'No form values, page contents or URL query data deliberately collected. Native browser-origin acceptance pending.']},
 {name:'14 CSS cloned website',artifact:'CSS background-image references token receiver',action:'Apply stylesheet; browser fetches image',condition:'Receiver sees other or missing Referer origin?',steps:['Record on other/missing Referer; approved origin suppresses hit'],response:'Return image (including approved-origin suppression case)',notes:['Approved origin returns image without a hit. Missing Referer can falsely alert on the approved site; a hit is not definitive cloning evidence.', 'Local Referer suppression verified; native CSS rendering/caching acceptance pending.']},
 {name:'15 Kubeconfig bearer',artifact:'JSON-formatted YAML: HTTPS receiver + synthetic bearer',action:'Use config for Kubernetes API request',condition:'Exact decoy bearer + active token?',steps:['Present credential; record use regardless of real-cluster operation intent'],response:'403 denial; invalid credential gets 401; NO cluster access',notes:['Read/copy/parse alone need not contact a server. API read/write/delete attempts may all present the credential.', 'No exec plugin, real secret, cluster proxy or insecure-TLS switch. Native kubectl and trusted endpoint acceptance pending.']},
 {name:'16 MCP configuration',artifact:'MCP config with token HTTP endpoint URL',action:'MCP client connects and POSTs JSON-RPC',condition:'Token and preliminary origin/header/body/protocol checks accepted?',steps:['Record minimal method name, NOT parameters; later validation can still fail'],response:'initialize: minimal result; tools/list: empty; ping: empty; unknown method: unavailable',notes:['Browser Origin requests are denied. No commands, filesystem roots, prompts or arbitrary data service.', 'Reading config alone need not connect. A hit does not prove a complete successful MCP session. Full native-client/version compatibility pending.']},
 {name:'17 MySQL Windows DNS variant',artifact:'SQL artifact: hex-encoded token UNC path for LOAD_FILE',action:'Authorized execution in Windows MySQL context',condition:'Existing privileges and path policy allow lookup attempt?',steps:['Attempt UNC lookup','Token-host DNS query'],response:'NXDOMAIN; expected failed file retrieval',notes:['Opening/copying SQL text is not execution. No tables modified. Do not grant privileges, add address records or start SMB just to trigger it.', 'Native authorized MySQL execution pending; local QA decoded the hostname and queried DNS directly.']},
 {name:'18 Unique email address',artifact:'Text artifact containing token mailbox address',action:'Send mail; MTA routes to configured receiver',condition:'STARTTLS and active known single recipient accepted?',steps:['EHLO -> STARTTLS -> EHLO -> MAIL FROM -> RCPT TO','Bounded DATA message completes; discard content'],response:'Persist/coalesce callback then successful SMTP receipt',notes:['Reading/copying address does not send mail. Opening a received message is not this token\'s activation mechanism.', 'No relay, retained mailbox, AUTH, attachment execution or outbound reply. Peer may be MTA, not original sender.', 'Local STARTTLS receipt verified; MX/external MTAs/Linux/service identity acceptance pending.']},
 {name:'19 Log4shell DNS-only diagnostic',artifact:'Diagnostic text containing token-host DNS JNDI reference',action:'Authorized isolated test passes text to compatible logger',condition:'Logger actually evaluates this lookup?',steps:['Token-host DNS resolution'],response:'DNS NXDOMAIN only',notes:['Normal text reading/copying does not execute a lookup. Patched/disabled lookup behavior should not activate.', 'No LDAP/RMI, classes, commands or environment/hostname interpolation. No hit is not evidence of safety or an attempted lookup.', 'Actual isolated logger activation pending; local QA manually queried DNS.']},
];
for (const s of specs) {
  const nodes=[
    `artifact|process|${s.artifact}`, 'operation|decision|Action against the artifact?',
    'read|client|OPEN / READ\nBytes may be read locally; text access alone does not imply remote use',
    'copy|client|COPY\nSource may be read; destination is NOT automatically monitored',
    'move|client|MOVE / RENAME\nPath events; old path may be missing; monitoring is not automatically transferred',
    'edit|client|EDIT / SAVE\nAudited write / watcher / hash change; token may be preserved or stripped',
    'encrypt|client|ENCRYPT\nChanged bytes / rename; token may become unreadable; not proof of ransomware',
    'delete|client|DELETE\nAudited deletion / watcher / missing path; no intrinsic phone-home',
    'monitor|decision|Matching owned path and functioning local monitoring?',
    'local|client|L: observed local event\nOptional actor only from suitable audit evidence',
    'localdest|client|Local log / tray if running / management spool / syslog if enabled',
    `native|process|N: ${s.action}`, `condition|decision|${s.condition}`,
    'none|pending|No passive callback promised\nLocal evidence is independent',
    'nolocal|pending|No local event promised\nPassive activation remains independent',
    'preserved|process|Intact copied / moved / edited token may activate on LATER compatible use',
    ...s.steps.map((label,i)=>({id:`step${i}`,kind:'receiver',label})),
    'remote|receiver|R: active-token validation / minimal evidence / dedup / durable inbox',
    `reply|receiver|${s.response}`, 'views|server|Callback history + enabled server callback syslog',
    'boundary|risk|Callback is NOT trusted Windows user/PID; cannot authorize process stopping',
  ].map(n=>typeof n==='string'?n:`${n.id}|${n.kind}|${n.label}`);
  if(s.after) nodes.push(`after|process|${s.after}`);
  const edges=['artifact|operation',...['read','copy','move','edit','encrypt','delete'].map(id=>`operation|${id}`),
    ...['read','copy','move','edit','encrypt','delete'].map(id=>`${id}|monitor|if locally observable`),
    'monitor|local|yes','monitor|nolocal|no','local|localdest',
    'operation|native|compatible native / protocol USE','read|native|only if interpreted / used',
    'copy|preserved|token bytes preserved','move|preserved|reference survives','edit|preserved|token survives',
    'preserved|native|later use','native|condition','condition|none|no / blocked','condition|step0|yes',
    ...s.steps.slice(1).map((_,i)=>`step${i}|step${i+1}`),
    `step${s.steps.length-1}|remote|valid active token + reachable receiver`,
    'remote|reply','remote|views','remote|boundary||forbidden'];
  if(s.after)edges.push('reply|after');
  cp(s.name,nodes,edges,[...s.notes,'Local monitoring is conditional for every operation; a generated/downloaded specimen is not automatically enrolled. Local and remote streams do not imply each other.'],{direction:'TB'});
}
cp('20 Lifecycle limits lab networking and pending catalog', [
 'original|client|Original monitored artifact','copy|process|Copy: source read may be observed; new path unmonitored','move|process|Move: rename / missing may be observed; no automatic adoption','encrypt|process|Encrypt: changed bytes; embedded trigger may be unusable','delete|process|Delete: missing path; no deletion-specific callback','use|receiver|Preserved copies may activate later','revoke|server|Revoke token in management','future|receiver|Future recording checks reject token; in-flight races need acceptance','local|client|Revocation does NOT delete files, recall copies or stop local monitoring',
 'lab|process|Recorded lab: 20 DOCX/XLSX/PDF/SVG files in five D: folders','url|receiver|All deployed document callbacks use localhost:18444','same|client|Same host: compatible trusted reader may reach receiver','other|risk|Other host: localhost means OTHER host; no path to original receiver','required|pending|Cross-host activation needs explicitly reachable hostname, trusted TLS and authorized network exposure',
 'pending|pending|13 unimplemented catalog mechanisms\n'+pendingTypes.join('\n')
], ['original|copy','original|move','original|encrypt','original|delete','copy|use|intact token + later use','move|use|intact token + later use','revoke|future','revoke|local','lab|url','url|same|same machine','url|other|copied to another machine','other|required','lab|pending|not part of standing deployment'],
['All 20 local files had path evidence at the historical checkpoint. One manually invoked callback is not native-reader activation.', 'Observer launch blocked; syslog/Wazuh and automatic stopping disabled; DNS/SMTP listeners disabled. Other mechanisms had local artifact/receiver exercises only.', 'Management Entra login is not an Entra canary; SQL Server application storage is not an MSSQL table canary. No runtime changes are made by this documentation.']);

// Layout and serialization. Shapes and connectors remain native editable mxCells.
function graphLayout(p) {
  const labels=new Map(p.nodes.map(n=>[n.id,wrap(n.label,n.kind==='decision'?26:34)]));
  const dot=['digraph G {',`graph [rankdir=${p.direction||'TB'}, nodesep=0.42, ranksep=0.78, splines=polyline, pad=0.2, bgcolor="white"];`,
    'node [fontname="Arial", fontsize=14, margin="0.18,0.14", width=2.8, height=0.60];',
    'edge [fontname="Arial", fontsize=11, color="#718198", arrowsize=0.65];',
    ...p.nodes.map(n=>{const [fill,stroke]=palette[n.kind]||palette.process;return `${q(n.id)} [label=${q(labels.get(n.id))},shape=${n.kind==='decision'?'diamond':'box'},style="rounded,filled",fillcolor=${q(fill)},color=${q(stroke)}];`;}),
    ...p.edges.map(e=>`${q(e.from)} -> ${q(e.to)} [label=${q(wrap(e.label,29))}${e.kind==='forbidden'?',color="#B44E58",style=dashed':''}];`),'}'].join('\n');
  const g=viz.renderJSON(dot); const [,,gw,gh]=g.bb.split(',').map(Number);
  const nodes=p.nodes.map(n=>{const o=g.objects.find(o=>o.name===n.id);const [cx,cy]=o.pos.split(',').map(Number);const w=o.width*72,h=o.height*72;return {...n,label:labels.get(n.id),x:cx-w/2+50,y:gh-cy-h/2+130,w,h};});
  const edges=p.edges.map((e,i)=>{const o=g.edges[i];const points=(o._draw_||[]).filter(d=>d.op==='b'||d.op==='B').flatMap(d=>d.points).map(([px,py])=>({x:px+50,y:gh-py+130}));const pos=o.lp?o.lp.split(',').map(Number):null;const end=o.pos?.match(/(?:^| )e,([\d.-]+),([\d.-]+)/);return {...e,points,lp:pos?{x:pos[0]+50,y:gh-pos[1]+130}:null,targetPoint:end?{x:Number(end[1])+50,y:gh-Number(end[2])+130}:points.at(-1)};});
  return {nodes,edges,w:gw+100,h:gh+180};
}
function contractLayout(p) {
  const nodes=[],edges=[]; let y=160;
  for(const [id,from,to,route,payload] of p.contracts){
    const label=wrap(`${id}  ${route}\n${payload}`,65);const lines=label.split('\n').length;const h=Math.max(114,lines*19+24);
    const reverse=from==='MANAGEMENT';
    nodes.push({id:id+'a',kind:'client',label:from==='ACTIVATING CLIENT'?'Any activating client':'Windows endpoint client',x:60,y,w:235,h});
    nodes.push({id:id+'b',kind:to==='ISOLATED RECEIVER'?'receiver':to==='WAZUH / SIEM'?'process':'server',label:to==='CLIENT'?'Management server\n(response only)':to==='MANAGEMENT'?'Management server':to,x:1150,y,w:235,h});
    nodes.push({id:id+'detail',kind:'process',label,x:360,y,w:680,h});
    edges.push({from:reverse?id+'b':id+'a',to:reverse?id+'a':id+'b',label:'',kind:reverse?'reply':'',points:[{x:reverse?1150:295,y:y+h-10},{x:reverse?295:1150,y:y+h-10}]});
    y+=h+45;
  }
  return {nodes,edges,w:1450,h:y+30};
}
function buildPage(p, index, setName, sourceText) {
  const layout=p.contracts?contractLayout(p):graphLayout(p);
  const noteWidth=Math.max(850,Math.min(layout.w-100,1400));
  const noteText=p.notes.map((s,i)=>wrap(`${i+1}. ${s}`,Math.floor(noteWidth/7.4))).join('\n\n');
  const noteH=noteText.split('\n').length*19+50;
  const width=Math.max(layout.w,1000),height=layout.h+noteH+100;
  const cells=['<mxCell id="0"/><mxCell id="1" parent="0"/>'];
  const rect=(id,value,style,g)=>`<mxCell id="${x(id)}" value="${x(value)}" style="${x(style)}" vertex="1" parent="1"><mxGeometry x="${g.x.toFixed(2)}" y="${g.y.toFixed(2)}" width="${g.w.toFixed(2)}" height="${g.h.toFixed(2)}" as="geometry"/></mxCell>`;
  cells.push(rect('title',p.name,'text;html=0;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontFamily=Arial;fontSize=26;fontStyle=1;fontColor=#19334D;', {x:50,y:22,w:width-100,h:45}));
  cells.push(rect('legend','RANSOM FREE  |  2026-09-12 checkpoint  |  Blue: endpoint/browser  Green: management  Purple: receiver  Amber: decision/pending  Red: limit', 'text;whiteSpace=wrap;html=0;strokeColor=none;fillColor=none;align=left;fontFamily=Arial;fontSize=12;fontColor=#56677B;',{x:50,y:75,w:width-100,h:36}));
  for (const n of layout.nodes){
    const [fill,stroke]=palette[n.kind]||palette.process;
    const shape=n.kind==='decision'?'shape=rhombus;perimeter=rhombusPerimeter;':'rounded=1;arcSize=12;';
    cells.push(rect(n.id,n.label,`${shape}whiteSpace=wrap;html=0;align=center;verticalAlign=middle;fontFamily=Arial;fontSize=14;fontColor=#20344B;fillColor=${fill};strokeColor=${stroke};strokeWidth=1.3;spacing=10;`,n));
  }
  for (const [i,e] of layout.edges.entries()) {
    const pts=e.points||[];
    const source=layout.nodes.find(n=>n.id===e.from),target=layout.nodes.find(n=>n.id===e.to);
    const first=pts[0],last=e.targetPoint||pts.at(-1);
    const anchor=first&&last?`exitX=${(first.x-source.x)/source.w};exitY=${(first.y-source.y)/source.h};exitPerimeter=0;entryX=${(last.x-target.x)/target.w};entryY=${(last.y-target.y)/target.h};entryPerimeter=0;`:'';
    const style=`edgeStyle=none;rounded=0;html=0;endArrow=block;endFill=1;fontFamily=Arial;fontSize=11;fontColor=#43556C;labelBackgroundColor=#FFFFFF;strokeColor=${e.kind==='forbidden'?'#B44E58':'#718198'};strokeWidth=1.2;${anchor}${e.kind?'dashed=1;':''}`;
    const offset=e.lp&&first&&last?`<mxPoint x="${(e.lp.x-(first.x+last.x)/2).toFixed(2)}" y="${(e.lp.y-(first.y+last.y)/2).toFixed(2)}" as="offset"/>`:'';
    cells.push(`<mxCell id="edge${i}" value="${x(wrap(e.label,29))}" style="${x(style)}" edge="1" parent="1" source="${x(e.from)}" target="${x(e.to)}"><mxGeometry relative="${offset?'0':'1'}" as="geometry">${offset}${pts.length?`<Array as="points">${pts.map(v=>`<mxPoint x="${v.x.toFixed(2)}" y="${v.y.toFixed(2)}"/>`).join('')}</Array>`:''}</mxGeometry></mxCell>`);
  }
  cells.push(rect('notes','SCOPE AND QUALIFICATIONS\n\n'+noteText,'rounded=1;whiteSpace=wrap;html=0;align=left;verticalAlign=top;fontFamily=Arial;fontSize=14;fontColor=#43556C;fillColor=#F7F9FC;strokeColor=#D6DFEB;spacing=16;',{x:50,y:layout.h+20,w:noteWidth,h:noteH}));
  const xml=`<mxGraphModel dx="0" dy="0" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="${Math.ceil(width)}" pageHeight="${Math.ceil(height)}" math="0" shadow="0"><root>${cells.join('')}</root></mxGraphModel>`;
  // Independent structural assertions against parsed XML, not only model arrays.
  const parsed=xmljs.xml2js(xml,{compact:true}).mxGraphModel;
  const items=parsed.root.mxCell;const ids=new Set();
  for(const c of items){const a=c._attributes;if(ids.has(a.id))throw Error('Duplicate cell '+a.id);ids.add(a.id);}
  for(const c of items){const a=c._attributes;if(a.parent&&!ids.has(a.parent))throw Error('Missing parent');if(a.edge==='1'&&(!ids.has(a.source)||!ids.has(a.target)))throw Error('Dangling edge');if(a.vertex==='1'){const g=c.mxGeometry._attributes;if(['x','y','width','height'].some(k=>!Number.isFinite(Number(g[k]))))throw Error('Invalid geometry');}}
  for(let i=0;i<layout.nodes.length;i++)for(let j=i+1;j<layout.nodes.length;j++){
    const a=layout.nodes[i],b=layout.nodes[j];if(a.x<b.x+b.w-1&&a.x+a.w>b.x+1&&a.y<b.y+b.h-1&&a.y+a.h>b.y+1)throw Error(`Node overlap ${p.name}: ${a.id}/${b.id}`);
  }
  const compressed=zlib.deflateRawSync(Buffer.from(encodeURIComponent(xml))).toString('base64');
  if(decodeURIComponent(zlib.inflateRawSync(Buffer.from(compressed,'base64')).toString())!==xml)throw Error('Compression roundtrip failed');
  const pageId=`${setName}-${String(index+1).padStart(2,'0')}`;
  // Exact original section remains attached as metadata, and complete originals are copied alongside.
  const attrs=`id="${pageId}" name="${x(p.name)}" sourceCheckpoint="2026-09-12" sourceText="${x(sourceText)}"`;
  const svg=previewSvg(p,layout,noteText,noteWidth,width,height,noteH);
  return {raw:`<diagram ${attrs}>${xml}</diagram>`,compressed:`<diagram ${attrs}>${compressed}</diagram>`,svg,
    summary:{page:index+1,name:p.name,nodes:layout.nodes.length,connectors:layout.edges.length,width:Math.ceil(width),height:Math.ceil(height),id:pageId}};
}
function previewSvg(p,l,notes,nw,w,h,nh) {
  const tx=(s,cx,cy,align='middle',size=14,color='#20344B')=>`<text x="${cx}" y="${cy}" text-anchor="${align}" font-family="Arial, sans-serif" font-size="${size}" fill="${color}">${s.split('\n').map((line,i)=>`<tspan x="${cx}" dy="${i?size*1.3:0}">${x(line)}</tspan>`).join('')}</text>`;
  const parts=[`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#718198"/></marker></defs><rect width="100%" height="100%" fill="white"/>`,tx(p.name,50,51,'start',26),tx('RANSOM FREE | 2026-09-12 checkpoint | Editable diagram preview - not a live status query',50,90,'start',14,'#56677B')];
  for(const e of l.edges){const a=l.nodes.find(n=>n.id===e.from),b=l.nodes.find(n=>n.id===e.to);const pts=e.points?.length?e.points:[{x:a.x+a.w/2,y:a.y+a.h},{x:b.x+b.w/2,y:b.y}];parts.push(`<polyline points="${pts.map(p=>`${p.x},${p.y}`).join(' ')}" fill="none" stroke="${e.kind==='forbidden'?'#B44E58':'#718198'}" stroke-width="1.2" marker-end="url(#arrow)" ${e.kind?'stroke-dasharray="5 4"':''}/>`);if(e.label){const m=e.lp||pts[Math.floor(pts.length/2)];const label=wrap(e.label,29);parts.push(tx(label,m.x,m.y-(label.split('\n').length-1)*7.15+4,'middle',11,'#43556C'));}}
  for(const n of l.nodes){const [fill,stroke]=palette[n.kind]||palette.process;parts.push(n.kind==='decision'?`<polygon points="${n.x+n.w/2},${n.y} ${n.x+n.w},${n.y+n.h/2} ${n.x+n.w/2},${n.y+n.h} ${n.x},${n.y+n.h/2}" fill="${fill}" stroke="${stroke}"/>`:`<rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="9" fill="${fill}" stroke="${stroke}"/>`);parts.push(tx(n.label,n.x+n.w/2,n.y+n.h/2-(n.label.split('\n').length-1)*9.1+5));}
  parts.push(`<rect x="50" y="${l.h+20}" width="${nw}" height="${nh}" rx="9" fill="#F7F9FC" stroke="#D6DFEB"/>`,tx('SCOPE AND QUALIFICATIONS\n\n'+notes,66,l.h+47,'start',14,'#43556C'),'</svg>');return parts.join('');
}
fs.mkdirSync(out,{recursive:true});fs.mkdirSync(path.join(out,'previews'),{recursive:true});fs.mkdirSync(path.join(out,'sources'),{recursive:true});
const sets=[['01-application-architecture',architecture,'application-flowchart-20260912.txt'],['02-client-server-workflows',workflows,'client-server-workflows-20260912.txt'],['03-canary-actions-and-triggers',canaries,'canary-action-trigger-diagrams-20260912.txt']];
const manifest={checkpoint:'2026-09-12',format:'Draw.io mxfile (editable shapes and attached connectors)',actualLucidchartImport:'Not exercised; user account/import acceptance pending',sets:[]};
const sourceSection=(text,p,set)=>{
  if(p.contracts)return text.slice(text.indexOf('4. CROSS-BOUNDARY'),text.indexOf('5. PASSIVE'));
  const match=p.name.match(/^(\d+)/);const num=Number(match[1]);
  const lines=text.split(/\r?\n/);const re=new RegExp(`^${set.includes('workflows')?num:String(num).padStart(2,'0')}\\. `);
  const start=lines.findIndex(l=>re.test(l));if(start<0)return num===0?lines.slice(0,lines.findIndex(l=>/^01\. /.test(l))).join('\n'):lines.slice(lines.findIndex(l=>l.startsWith('WHAT IS AND IS NOT'))).join('\n');
  let end=start+1;while(end<lines.length&&!/^\d{1,2}\. /.test(lines[end])&&!lines[end].startsWith('WHAT IS AND IS NOT'))end++;
  return lines.slice(start,end).join('\n');
};
const inventory=[];let totalNodes=0,totalEdges=0;
for(const [name,pages,source] of sets){
  const bytes=fs.readFileSync(path.join(sourceRoot,source));const text=bytes.toString('utf8');fs.copyFileSync(path.join(sourceRoot,source),path.join(out,'sources',source));
  const built=pages.map((p,i)=>buildPage(p,i,name,sourceSection(text,p,name)));
  const envelope=inner=>`<?xml version="1.0" encoding="UTF-8"?><mxfile host="app.diagrams.net" modified="2026-09-12T00:00:00.000Z" agent="Ransom Free documentation generator" version="29.0.0" type="device" pages="${pages.length}">${inner}</mxfile>`;
  const raw=envelope(built.map(b=>b.raw).join(''));const compressed=envelope(built.map(b=>b.compressed).join(''));
  xmljs.xml2js(raw);xmljs.xml2js(compressed);
  fs.writeFileSync(path.join(out,name+'.drawio'),raw);fs.writeFileSync(path.join(out,name+'.xml'),compressed);
  for(const [i,b] of built.entries()){const svgName=`${name}-p${String(i+1).padStart(2,'0')}.svg`;fs.writeFileSync(path.join(out,'previews',svgName),b.svg);inventory.push({set:name,...b.summary,preview:'previews/'+svgName});totalNodes+=b.summary.nodes;totalEdges+=b.summary.connectors;}
  manifest.sets.push({file:name+'.drawio',compressedAlternative:name+'.xml',source:'sources/'+source,sourceSha256:sha(bytes),sha256:sha(raw),compressedSha256:sha(compressed),pageCount:pages.length,pages:built.map(b=>b.summary)});
}
if(architecture.length!==18||workflows.length!==8||specs.length!==19||canaries.length!==21)throw Error('Incomplete coverage');
for(const s of manifest.sets)if(sha(fs.readFileSync(path.join(out,s.source)))!==s.sourceSha256)throw Error('Source copy changed');
manifest.totalPages=inventory.length;manifest.totalNodes=totalNodes;manifest.totalConnectors=totalEdges;
fs.writeFileSync(path.join(out,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
fs.writeFileSync(path.join(out,'PAGE-INDEX.md'),'# Diagram page index\n\n'+manifest.sets.map(s=>`## ${s.file}\n\n`+s.pages.map(p=>`- ${p.page}. ${p.name} (${p.nodes} shapes, ${p.connectors} connectors)`).join('\n')).join('\n\n')+'\n');
fs.writeFileSync(path.join(out,'preview.html'),`<!doctype html><html lang="en"><meta charset="utf-8"><title>Ransom Free diagrams</title><style>body{font:16px system-ui;margin:32px;color:#20344b;background:#f5f7fa}h1{font-size:28px}a{color:#265b91}li{margin:12px 0}section{background:white;border:1px solid #d6dfeb;border-radius:12px;padding:20px;margin:20px 0}</style><h1>Ransom Free — editable diagram package</h1><p>47 pages · ${totalNodes} native shapes · ${totalEdges} attached connectors. Checkpoint: 2026-09-12.</p><p>SVG previews show generated geometry; they are not a verified Lucidchart rendering. Import the .drawio / .xml files, not the previews.</p>${manifest.sets.map(s=>`<section><h2>${x(s.file)}</h2><p><a href="${s.file}">Editable Draw.io file</a> · <a href="${s.compressedAlternative}">Compressed XML alternative</a></p><ol>${inventory.filter(p=>p.set+'.drawio'===s.file).map(p=>`<li><a href="${p.preview}">${x(p.name)}</a></li>`).join('')}</ol></section>`).join('')}</html>`);
fs.writeFileSync(path.join(out,'VALIDATION.md'),`# Diagram validation\n\nCheckpoint: 2026-09-12. Documentation-only checks; no application tests or service changes.\n\n- Coverage: ${inventory.length} pages (18 architecture, 8 client/server, 19 individual canaries + 2 shared/limits pages).\n- Native editable graph content: ${totalNodes} feature shapes and ${totalEdges} attached connectors, plus editable titles and scope notes.\n- XML parse: all uncompressed and compressed documents passed.\n- Cell IDs, parents, edge endpoints and finite geometry: checked on every page.\n- Node-to-node bounding-box overlap: zero on all pages. Connector crossings are possible in dense diagrams.\n- DEFLATE/Base64/URI round trip: every page exactly restored.\n- Original source preservation: byte-identical copies verified with SHA-256. Exact source sections are also preserved in diagram metadata.\n- All 19 canary pages explicitly include open/read, copy, move/rename, edit/save, encrypt and delete branches; native activation and local monitoring are separate.\n- Credentials: none included; historic network addresses are descriptive, never contacted by the generator.\n- Visual review: pending representative preview inspection; SVG is an independent approximation, not the Draw.io/Lucid renderer.\n- Actual Lucidchart import/edit acceptance: NOT executed. No Lucid account connection is available.\n- Product functional, regression, native-canary and UI acceptance: unchanged by this documentation task.\n`);
console.log(JSON.stringify({output:out,pages:inventory.length,nodes:totalNodes,connectors:totalEdges,sets:manifest.sets.map(s=>({file:s.file,pages:s.pageCount}))},null,2));
