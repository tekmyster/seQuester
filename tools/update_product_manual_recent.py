from __future__ import annotations

import argparse
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt


def set_paragraph_text(paragraph, text: str) -> None:
    paragraph.clear()
    run = paragraph.add_run(text)
    run.font.name = "Aptos"
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:ascii"), "Aptos")
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:hAnsi"), "Aptos")


def replace_prefix(doc, prefix: str, text: str) -> None:
    matches = [p for p in doc.paragraphs if p.text.startswith(prefix)]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one paragraph starting {prefix!r}, found {len(matches)}")
    set_paragraph_text(matches[0], text)


def set_cell(cell, text: str, bold: bool = False) -> None:
    cell.text = ""
    p = cell.paragraphs[0]
    r = p.add_run(text)
    r.bold = bold
    r.font.name = "Aptos"
    r.font.size = Pt(9)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    tc_pr = cell._tc.get_or_add_tcPr()
    mar = tc_pr.first_child_found_in("w:tcMar")
    if mar is None:
        mar = OxmlElement("w:tcMar")
        tc_pr.append(mar)
    for edge in ("top", "left", "bottom", "right"):
        item = mar.find(qn(f"w:{edge}"))
        if item is None:
            item = OxmlElement(f"w:{edge}")
            mar.append(item)
        item.set(qn("w:w"), "90")
        item.set(qn("w:type"), "dxa")


def shade(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def add_table(doc, rows: list[list[str]], widths: list[float] | None = None):
    table = doc.add_table(rows=0, cols=len(rows[0]))
    table.style = "Table Grid"
    table.autofit = False
    for ri, values in enumerate(rows):
        cells = table.add_row().cells
        for ci, value in enumerate(values):
            set_cell(cells[ci], value, bold=ri == 0)
            if widths:
                cells[ci].width = Inches(widths[ci])
            if ri == 0:
                shade(cells[ci], "17365D")
                for run in cells[ci].paragraphs[0].runs:
                    run.font.color.rgb = __import__("docx").shared.RGBColor(255, 255, 255)
            elif ri % 2 == 0:
                shade(cells[ci], "EAF2F8")
    table.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    return table


def add_normal(doc, text: str):
    p = doc.add_paragraph(style="Normal")
    set_paragraph_text(p, text)
    return p


def move_new_elements_before(doc, marker, starting_index: int) -> None:
    body = doc._element.body
    nodes = list(body)[starting_index:]
    for node in nodes:
        marker._p.addprevious(node)


def add_recent_section(doc) -> None:
    marker = next(p for p in doc.paragraphs if p.text == "Enterprise product definition")
    body = doc._element.body
    start = len(list(body)) - 1  # exclude sectPr

    title = doc.add_paragraph(style="Heading 1")
    title.paragraph_format.page_break_before = True
    title.add_run("Current implementation update")
    add_normal(doc, "Status timestamp: 13 September 2026, America/New_York. This section supersedes older version and rollout statements where they conflict. It separates source implementation, build evidence, pilot observations and uncompleted acceptance so operators do not turn a partial result into a production claim.")

    doc.add_paragraph("Management event routing", style="Heading 2")
    add_normal(doc, "Every enrolled endpoint event is submitted to the management server over authenticated HTTPS and retained in the endpoint's finite durable queue until acknowledged. The current management source also implements a checkpointed server-side syslog relay for stored endpoint events and passive callback hits. Administrators may configure server-only, client-only or both downstream syslog routes. Server-only is the intended least-privilege topology when only management may reach Wazuh. Do not disable direct client forwarding until the server relay and exact receiver persistence are validated; a successful socket write is not proof that Wazuh decoded or stored the event.")
    add_table(doc, [
        ["Route", "Behavior", "Current status"],
        ["Endpoint to management", "Always used for enrolled endpoint alerts; offline retry is bounded by configured queue and disk capacity.", "Implemented; complete fleet/native acceptance remains pending."],
        ["Management to Wazuh", "Administrator selects endpoint events, callback hits or both; protected revision/checkpoint state; UDP/TCP/TLS and RFC3164/RFC5424 destination options.", "Implemented in source and unsigned development build; real end-to-end Wazuh acceptance pending."],
        ["Endpoint direct to Wazuh", "Independent managed/local client syslog outbox. All alerts still go to management.", "Implemented; optional. Disable only after validated server-relay cutover."],
        ["Both senders", "Duplicates are expected; correlate stable EventId and endpoint identity.", "Supported configuration, not recommended as an unreviewed permanent default."],
    ], [1.35, 3.55, 1.6])

    doc.add_paragraph("Linux x64 audit attribution architecture", style="Heading 2")
    add_normal(doc, "The 0.9.0 direct managed auditd plugin aborted under auditd 3.0.7 when auditd retained MemoryDenyWriteExecute=yes. The replacement design keeps that protection: auditd launches a small C#/.NET Native AOT relay with no JIT, the relay sends bounded frames over a root-only Unix-domain socket, and a separate sandboxed managed service parses the stream with the distribution's libauparse. Parsed exact-canary evidence enters the protected audit inbox, then the endpoint durable queue, management storage and configured integrations.")
    add_normal(doc, "Collector health is not a timestamp-only check. The agent validates collector PIDFD, boot ID and start identity; root ownership and executable/command identity; relay PIDFD, start identity and auditd parent; recent relay frames; and an advancing collector heartbeat. The explicit --audit-verify command reads one administrator-selected existing active canary through its own /usr/bin/cat child, preserves the file hash, and requires a new full-attribution packet with the matching PID, PPID, UID/eUID and executable plus advancing counters. It creates no canary and does not itself prove management or Wazuh delivery.")
    add_normal(doc, "Full attribution requires core actor fields, the expected PATH count, and a record set completed by PROCTITLE or EOE according to libauparse 3.0.7 behavior. Timeout or incomplete sets remain partial. Historical audit PIDs never authorize process termination; response remains tied to a separate live event-bound process handle such as fanotify PIDFD.")

    doc.add_paragraph("Known 0.9.1 pilot blockers", style="Heading 2")
    add_table(doc, [
        ["Finding", "Observed result", "Required disposition"],
        ["Empty args directive", "The package emits `args =`. auditd 3.0.7 reports Wrong number of arguments and skips the plugin.", "Omit the args directive entirely. Preserve the immutable archive as evidence; publish a corrected replacement artifact."],
        ["Shell draft copied as persistent rules", "--audit-rules emits shell commands. Literal single-quoted `path=...` fields are not augenrules syntax and fail as an unknown field.", "Use a format-aware generator/conversion and review every exact path. Do not generically strip quotes from arbitrary paths."],
        ["Home path hidden from auditd", "Ubuntu auditd has ProtectHome=yes. Its augenrules/ExecStartPost namespace could not resolve /home/Shared_Finance and returned No such file or directory.", "Do not disable ProtectHome or MDWE. Package and validate a narrow post-auditd loader or another supported placement strategy before general deployment."],
        ["Partial pipeline evidence", "A later attempt initialized the AOT relay, kept the collector active and advanced transport/parser counters before rollback.", "Do not call this attribution success. A matching canary actor event and management/Wazuh record were not obtained."],
    ], [1.55, 3.0, 1.95])
    add_normal(doc, "The rollout-owned pilot returned to healthy detection-only 0.9.0 after rollback, with auditd MemoryDenyWriteExecute still enabled. The proposed post-auditd root oneshot loader and seQuester-only rules file outside /etc/audit/rules.d are pilot deployment work, not shipped product support. Acceptance must cover service ordering, reboot, failure visibility, exact removal, duplicate prevention and preservation of unrelated audit/Wazuh rules.")

    doc.add_paragraph("Release and platform status", style="Heading 2")
    add_table(doc, [
        ["Platform or component", "Current documented baseline", "Acceptance position"],
        ["Windows endpoint", "Unsigned .NET x64 MSI and read-only tray; audit/watcher monitoring and event-bound response paths.", "Packaging/static checks exist; deployment, UI and fleet acceptance remain incomplete."],
        ["Linux x64 endpoint", "0.9.1 candidate includes Native AOT relay and separate collector. Archive: ransomfree-client-0.9.1-dev.20260913T160836Z-a3ff443b-linux-x64; SHA-256 e534791cfec57e4e3e44e57c0c02d47b5c6ef00d23adeb2bc151e05e1fb6cae9.", "Not deployable unchanged because of plugin/rule-loading defects. Corrected artifact and full pilot required."],
        ["Linux ARM64 endpoint", "Existing 0.9.0 client/desktop baseline; no matching 0.9.1 Native AOT relay.", "Audit replacement build and native acceptance pending."],
        ["macOS endpoint", "Unsigned .NET Intel/Apple Silicon FSEvents baseline.", "C# Endpoint Security adapter, entitlement/signing, process attribution and response acceptance not implemented."],
        ["Management server", "Windows/Linux .NET source with local accounts, MFA, LDAPS/OIDC integration, SQL/SQLite selection, reports, server endpoint syslog relay and callback notification paths.", "Development-only; production hosting, identity providers, SQL scale, real email/Wazuh and UI acceptance incomplete."],
        ["Android and iOS", "SOC companion, approval/investigation and scoped document-deception architecture proposal only.", "No mobile client exists. Mobile sandboxing prevents desktop-equivalent system-wide monitoring/process attribution."],
    ], [1.45, 3.55, 1.5])

    doc.add_paragraph("Command additions for Linux audit", style="Heading 2")
    add_table(doc, [
        ["Command", "Purpose and boundary"],
        ["--audit-collect", "Internal separate root collector service mode. Receives the Native AOT relay over a private socket and writes the protected inbox."],
        ["--audit-health", "Root acceptance check for active collector/relay identities, auditd parent, recent frames and advancing heartbeat. Does not prove rules or receiver delivery."],
        ["--audit-verify ABSOLUTE_CANARY", "Controlled read of one existing active approved canary; requires matching fresh actor evidence and unchanged content. Emits a real alert when the endpoint is running."],
        ["--audit-rules", "Prints a shell command draft only. It is not an augenrules file or automatic policy installer."],
        ["--audit-dispatch", "Diagnostic stdin compatibility mode only. Never configure it as an auditd plugin."],
    ], [2.25, 4.25])

    doc.add_paragraph("Unchanged limits and open requirements", style="Heading 2")
    add_normal(doc, "The recent work does not prove that a read completed a copy, classify every write as encryption, identify remote SMB users, provide macOS actor telemetry, create mobile endpoint parity, or make the product production-ready. Queues and relay buffers are finite. Linux audit rule coverage, kernel/auditd drops and service namespaces require independent checks. Global known-folder placement, per-instance central inventory, automatic correlation/scoring, learning mode, rich signer/parent attribution, advanced containment, signed releases, container deployment and complete provider integrations remain backlog items unless separately evidenced in the current source and QA ledger.")

    move_new_elements_before(doc, marker, start)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("output")
    args = ap.parse_args()
    source, output = Path(args.source), Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = Document(source)

    replace_prefix(doc, "seQuester monitors administrator-approved", "seQuester monitors administrator-approved decoy files and records evidence of unexpected activity. Every enrolled endpoint alert is sent to the management server and queued locally during outages, subject to finite capacity. Administrators can additionally route syslog from the server, the client or both. Passive canaries can report to a separate callback receiver when a compatible reader or protocol activates them.")
    replace_prefix(doc, "The documented builds are unsigned", "The documented builds are unsigned development releases. The management server refuses non-Development startup. Keep management and receiver isolated; this build is not approved for public exposure. The Linux x64 0.9.1 audit candidate is not deployable unchanged because its packaged auditd configuration is invalid and home-path rule persistence remains unresolved. Native Linux/macOS acceptance, complete identity/integration testing, signing and production hardening remain pending.")
    replace_prefix(doc, "5. The server stores received events", "5. The server stores received events for fleet views, investigations and reporting. Administrators can relay stored endpoint events and/or callback hits to syslog. Direct client syslog is an independent optional route; all endpoint events still go to management.")
    replace_prefix(doc, "Evidence baseline: current source inspected", "Evidence baseline: current source and rollout evidence inspected on 13 September 2026. This chapter describes implemented controls, not production certification. The server explicitly refuses startup outside Development. Keep this unsigned build on an isolated development network; do not expose it publicly. Source inspection, a successful build or sender status is not runtime or Wazuh acceptance.")
    replace_prefix(doc, "The C#/.NET 10 management server runs", "The C#/.NET 10 management server runs on Windows or Linux and serves a browser console. Endpoints authenticate independently, submit queued events, report health, retrieve group policy and return response receipts over HTTPS. The server persists received events and implements checkpointed forwarding of endpoint events and/or passive callback hits to syslog. Passive token traffic enters a separate receiver; the management server administers token metadata and notification delivery. None of these routes proves downstream Wazuh persistence without receiver-side evidence.")
    replace_prefix(doc, "Documentation snapshot: 13 September", "Documentation snapshot: 13 September 2026. Linux x64 0.9.1 adds a C# Native AOT auditd relay and separate managed collector. The published archive is not deployable unchanged because its empty args directive is rejected by auditd 3.0.7 and its shell rule draft is not persistent augenrules syntax. Linux ARM64 remains on the earlier client baseline without a matching 0.9.1 relay. macOS packages remain unchanged FSEvents baselines.")
    replace_prefix(doc, "IMPORTANT RELEASE BOUNDARY:", "IMPORTANT RELEASE BOUNDARY: all packages are unsigned development artifacts. Linux x64 0.9.1 build/hash/syntax checks and a narrow relay MDWE startup test passed, but full audit attribution did not. A later pilot initialized the relay/collector and advanced counters, then rolled back when auditd's ProtectHome namespace could not load a /home watch. No matching canary attribution or Wazuh acceptance was obtained. macOS C# Endpoint Security remains unimplemented. Do not claim production or platform parity.")
    replace_prefix(doc, "Candidate targets are glibc-based Linux", "Target intent is glibc Linux x86-64 and ARM64 with systemd, but the 0.9.1 audit replacement currently exists only for x64 and is blocked from unchanged deployment. Ubuntu 22.04+, Debian 12+ and RHEL 9-class systems are intended targets, not a certification matrix. Self-contained .NET still depends on compatible native OS libraries. Alpine/musl, containers, network filesystems and specific kernel/service namespace combinations are not accepted sensor targets.")
    replace_prefix(doc, "1. Select the architecture-matching 0.8.0", "1. Select an architecture-matching release from the current release index and verify its SHA-256 against a separately trusted record. Do not deploy the indexed Linux x64 0.9.1 audit package unchanged; wait for the corrected immutable artifact and approved pilot result. Extract only into root-controlled staging and verify SHA256SUMS. Checksums detect change but do not authenticate an unsigned publisher.")
    replace_prefix(doc, "The following commands are implemented by both agent executables", "The ordinary commands below are implemented by both agent executables. Linux additionally implements --audit-collect, --audit-rules, --audit-health, --audit-verify and diagnostic-only --audit-dispatch; their exact boundaries are in the current implementation update and Linux audit guide. Run private-state operations through supplied wrappers and never start a second monitor against live state.")

    # Document control and platform table.
    table0 = doc.tables[0]
    values = {row.cells[0].text.strip(): row.cells[1] for row in table0.rows}
    set_cell(values["Revision"], "1.2")
    set_cell(values["Product baseline"], "Windows endpoint 0.6.3 development; Linux x64 0.9.1 blocked pilot candidate; Linux ARM64 and macOS 0.9.0 development; current management source with server endpoint syslog relay")
    set_cell(values["Release status"], "Development only; Linux x64 0.9.1 archive not deployable unchanged; documentation is not product acceptance")

    platform = doc.tables[1]
    # First column labels identify rows reliably.
    prows = {row.cells[0].text.strip(): row.cells for row in platform.rows}
    set_cell(prows["Process attribution"][2], "Conditional fanotify PIDFD; optional audit architecture exists but pilot acceptance is blocked")
    set_cell(prows["Deployment artifact"][2], "x64 0.9.1 blocked candidate; ARM64 earlier self-contained archive")

    linux_paths = doc.tables[37]
    for label, value in [
        ("Native AOT audit relay", "/opt/ransomfree-client/current/audit-relay/RansomFree.AuditRelay; auditd child, no arguments"),
        ("Audit collector service", "/etc/systemd/system/sequester-audit-collector.service; separate root:rfclient managed parser"),
        ("Audit evidence inbox", "/var/lib/sequester-audit; root:rfclient mode 2750; bounded packets and identity"),
        ("Audit transport", "/run/sequester-audit/ingest.sock in root-only runtime directory; peer identity checked"),
    ]:
        cells = linux_paths.add_row().cells
        set_cell(cells[0], label)
        set_cell(cells[1], value)

    commands = doc.tables[40]
    for command, purpose, consequence in [
        ("--audit-collect", "Linux-only internal collector service", "Private AF_UNIX input and protected audit inbox writes; not an auditd plugin argument"),
        ("--audit-health", "Linux-only active collector/relay and advancing-heartbeat validation", "Root read-only process/status checks; no canary or delivery proof"),
        ("--audit-verify ABSOLUTE_CANARY", "Linux-only controlled read of one existing active canary", "Emits real event; checks actor identity/hash/counters; does not validate Wazuh by itself"),
        ("--audit-rules", "Linux-only exact-path shell draft", "Prints commands only; not augenrules syntax and does not install rules"),
        ("--audit-dispatch", "Linux-only diagnostic stdin compatibility", "Never use as the auditd plugin; direct JIT child is blocked under MDWE"),
    ]:
        cells = commands.add_row().cells
        for cell, value in zip(cells, (command, purpose, consequence)):
            set_cell(cell, value)

    trouble = doc.tables[44]
    for symptom, checks in [
        ("Linux audit plugin skipped with Wrong number of arguments", "The 0.9.1 archive writes an empty args directive. Omit the directive entirely in the corrected artifact; do not weaken auditd."),
        ("Persistent /home audit rule says No such file or directory", "Ubuntu auditd ProtectHome hides the path from augenrules/ExecStartPost. Do not disable ProtectHome or MDWE. Packaged persistent loader support is pending."),
        ("--audit-rules output rejected in rules.d", "It is a shell draft, not augenrules. Use a format-aware reviewed conversion; do not generically strip quotes from arbitrary paths."),
        ("Audit counters advance but no attributed canary event", "Partial transport/parser evidence only. Require --audit-verify actor match plus the same EventId and fields in management/Wazuh before acceptance."),
    ]:
        cells = trouble.add_row().cells
        set_cell(cells[0], symptom)
        set_cell(cells[1], checks)

    add_recent_section(doc)

    doc.core_properties.title = "seQuester Product Manual"
    doc.core_properties.subject = "Quiver seQuester administrator and operator guide revision 1.2"
    doc.core_properties.comments = "Updated for server endpoint syslog relay and Linux audit compatibility work. Development documentation only."
    settings = doc.settings.element
    update = settings.find(qn("w:updateFields"))
    if update is None:
        update = OxmlElement("w:updateFields")
        settings.append(update)
    update.set(qn("w:val"), "true")

    for section in doc.sections:
        for area in (section.header, section.footer):
            for p in area.paragraphs:
                if "Revision 1.1" in p.text:
                    set_paragraph_text(p, p.text.replace("Revision 1.1", "Revision 1.2"))

    doc.save(output)


if __name__ == "__main__":
    main()
