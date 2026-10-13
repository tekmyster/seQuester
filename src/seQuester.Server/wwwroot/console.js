"use strict";
const $=id=>document.getElementById(id);
async function loadServerVersion(){
    try{
        const response=await fetch("/health/live",{cache:"no-store",signal:AbortSignal.timeout(10000)});
        if(!response.ok)return;
        const version=(await response.json()).serverVersion;
        if(typeof version!=="string"||!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/.test(version))return;
        for(const label of document.querySelectorAll("[data-server-version]"))label.textContent="Server version: "+version;
    }catch{ /* A failed public health request leaves the explicit unavailable label. */ }
}
void loadServerVersion();
let account=null,fleet=[],cursor=0,setupPending=false,sessionEpoch=0,currentReport=null;
async function api(path,body,binary=false,signal,publicErrors=null){const epoch=sessionEpoch,options={credentials:"same-origin",headers:{}};if(signal)options.signal=signal;if(body!==undefined){const csrf=await fetch("/api/v1/auth/csrf",{credentials:"same-origin"});if(!csrf.ok)throw new Error("Connection unavailable. Try again.");options.method="POST";options.headers={"Content-Type":"application/json","X-CSRF":(await csrf.json()).token};options.body=JSON.stringify(body);}const response=await fetch(path,options);if(epoch!==sessionEpoch)throw Object.assign(new Error("Session changed"),{cancelled:true});if(!response.ok){const error=new Error(response.status===401?"Sign-in or verification failed.":response.status===403?"You don’t have access to this action.":response.status===429?"Too many attempts. Try again later.":"Request failed. Check your input and try again.");if(response.status===400&&publicErrors){try{const body=await response.json();if(typeof body.code==="string"&&Object.hasOwn(publicErrors,body.code))error.message=publicErrors[body.code];}catch{ /* Preserve the generic error for malformed responses. */ }}if(epoch!==sessionEpoch)throw Object.assign(new Error("Session changed"),{cancelled:true});error.status=response.status;throw error;}const value=response.status===204?null:binary?await response.blob():await response.json();if(epoch!==sessionEpoch)throw Object.assign(new Error("Session changed"),{cancelled:true});return value;}
function clearSecrets(){for(const form of document.forms)form.reset();$("authenticator-key").textContent="";$("recovery-codes").textContent="";document.getElementById("report-history")?.replaceChildren();setupPending=false;document.dispatchEvent(new Event("session-cleared"));}
function showLogin(){sessionEpoch++;account=null;fleet=[];currentReport=null;clearSecrets();$("report-preview").hidden=true;$("report-summary").textContent="";$("report-id").textContent="";$("fleet-rows").replaceChildren();$("alert-rows").replaceChildren();$("workspace").hidden=true;$("recovery").hidden=true;$("login").hidden=false;}
function factor(value){const code=(value||"").trim();return code.length===32?{recoveryCode:code}:{code:code||null};}
function cell(row,value){const td=document.createElement("td");td.textContent=value??"Unknown";row.append(td);return td;}
function time(value){return new Date(value).toLocaleString(undefined,{timeZoneName:"short"});}
async function guarded(button,work,errorId="notice"){button.disabled=true;$(errorId).textContent="";try{await work();}catch(error){if(error.cancelled)return;showRequestFailure($(errorId),error);if(error.status===401 && account){showLogin();$("login-error").textContent="Session expired or verification failed. Sign in again.";}}finally{button.disabled=false;}}
async function enter(){account=await api("/api/v1/auth/me");$("user").textContent=account.userName;$("login").hidden=true;$("workspace").hidden=false;const recovering=account.mustChangePassword||account.mustEnrollMfa;for(const nav of document.querySelectorAll("nav button"))nav.hidden=recovering&&nav.dataset.view!=="security"||nav.dataset.view==="accounts"&&!account.roles.includes("Administrator");await view(recovering?"security":"overview");if(recovering)$("notice").textContent=account.mustChangePassword?"Change your temporary password to continue. It expires 24 hours after issue.":"Set up your authenticator to restore management access.";}
async function view(name){
    if(account?.mustChangePassword||account?.mustEnrollMfa)name="security";
    for(const panel of document.querySelectorAll(".view"))panel.hidden=panel.id!==name;
    for(const nav of document.querySelectorAll("nav button"))nav.classList.toggle("selected",nav.dataset.view===name);
    $("page-title").textContent={overview:"Overview",fleet:"Sensors",alerts:"Alerts",reports:"Reports",security:"Account security",policies:"Policies",incidents:"Incidents",callbacks:"Canary tokens",accounts:"Accounts"}[name];
    document.dispatchEvent(new CustomEvent("view-changed",{detail:name}));
    if(name==="overview")await loadOverview();if(name==="fleet")await loadFleet();if(name==="alerts")await loadAlerts(true);
    if(name==="security"){
        account=await api("/api/v1/auth/me");setupPending=false;$("mfa-form").reset();$("mfa-key").hidden=true;$("authenticator-key").textContent="";$("mfa-challenge").hidden=!account.mfaEnabled;
        $("mfa-status").textContent=(account.mfaEnabled?"Enabled":"Not enabled")+(account.mfaRequired?" · required by organization policy":"");
        $("mfa-action").textContent=account.mfaEnabled?"Disable MFA":"Set up authenticator";$("mfa-action").disabled=account.mfaEnabled&&account.mfaRequired;
        const password=$("mfa-form").querySelector('[name="password"]');password.required=account.authentication!=="SSO";password.closest("label").hidden=account.authentication==="SSO";
        document.dispatchEvent(new Event("security-rendered"));
    }
}
async function loadOverview(){const s=await api("/api/v1/console/overview?days="+$("overview-days").value),reported=s.protectionReportingClients??0,active=s.protectionActiveClients??0,attention=s.protectionNeedsAttentionClients??0;$("overview-total").textContent=reported.toLocaleString();$("overview-active").textContent=active.toLocaleString();$("overview-alerts").textContent=(s.nonWhitelistedAlerts??0).toLocaleString();$("overview-unknown").textContent=(s.policyUnknownAlerts??0).toLocaleString();$("overview-informational").textContent=(s.informationalActivity??0).toLocaleString()+" retained";const badge=$("overview-protection-state");badge.textContent=reported===0?"Not reported":attention===0?"Monitoring active":"Needs attention";badge.className="badge "+(reported===0?"unknown":attention===0?"healthy":"warning");$("overview-protection-detail").textContent=reported===0?"No client has submitted structured protection state.":`${reported.toLocaleString()} reporting clients · ${active.toLocaleString()} active · ${attention.toLocaleString()} needing attention · ${(s.deployedCanaryAndHoneypotFiles??0).toLocaleString()} deployed canary and honeypot files.`;$("overview-asof").textContent="Snapshot: "+time(s.asOfUtc)+" · "+(s.scope||"Client reports received by this management server");document.dispatchEvent(new Event("overview-rendered"));}
$("overview-days").addEventListener("change",()=>guarded($("overview-days"),loadOverview));
function selectReport(report){currentReport=report;const s=report.snapshot;$("report-summary").textContent=`${s.days}-day activity window · Endpoints: ${s.registered.toLocaleString()} · Events: ${(s.totalEvents??s.events).toLocaleString()}. Snapshot: ${time(s.asOfUtc)}.`;$("report-id").textContent="Report "+report.id;$("report-preview").hidden=false;$("report-download-status").textContent="";}
const reportHistory=document.createElement("section");reportHistory.id="report-history";$("reports").append(reportHistory);
async function loadReports(){const reports=await api("/api/v1/console/reports");reportHistory.replaceChildren();const heading=document.createElement("h3");heading.textContent="Your saved reports";const note=document.createElement("p");note.className="muted";note.textContent=reports.length?"Most recent 100 snapshots. Select one to export.":"No saved reports yet.";reportHistory.append(heading,note);for(const report of reports){const button=document.createElement("button");button.className="secondary";button.textContent=`${time(report.snapshot.asOfUtc)} · ${report.snapshot.days} days · ${report.id.slice(0,8)}`;button.addEventListener("click",()=>selectReport(report));reportHistory.append(button);}}
$("report-form").addEventListener("submit",event=>{event.preventDefault();const days=Number(new FormData(event.currentTarget).get("days"));guarded(event.currentTarget.querySelector("button"),async()=>{selectReport(await api("/api/v1/console/reports",{days}));await loadReports();},"report-error");});
async function downloadReport(format){if(!currentReport)return;const report=currentReport;const blob=await api(`/api/v1/console/reports/${report.id}/export`,{format},true);const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download=`ransom-free-summary-${report.id}.${format}`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);$("report-download-status").textContent="Download prepared. Check your browser downloads.";}
$("export-text").addEventListener("click",()=>guarded($("export-text"),()=>downloadReport("txt"),"report-error"));$("export-pdf").addEventListener("click",()=>guarded($("export-pdf"),()=>downloadReport("pdf"),"report-error"));
const fleetEmptyDefault=$("fleet-empty").textContent;
let fleetLoadInFlight=null;
function loadFleet(){
    if(fleetLoadInFlight)return fleetLoadInFlight;
    fleetLoadInFlight=(async()=>{
        const epoch=sessionEpoch,controller=new AbortController();let timeoutId;
        try{
            const current=await Promise.race([
                api("/api/v1/console/endpoints",undefined,false,controller.signal),
                new Promise((_,reject)=>{timeoutId=setTimeout(()=>{controller.abort();reject(new Error("Sensor status request timed out."));},15000);})
            ]);
            if(epoch!==sessionEpoch)return;
            fleet=current;$("fleet-empty").textContent=fleetEmptyDefault;refreshSensorFilterChoices();renderFleet();
        }catch(error){
            if(!error.cancelled&&epoch===sessionEpoch){fleet=[];$("fleet-rows").replaceChildren();$("fleet-empty").textContent="Current sensor status is unavailable. Refresh to try again.";$("fleet-empty").hidden=false;}
            throw error;
        }finally{clearTimeout(timeoutId);}
    })().finally(()=>{fleetLoadInFlight=null;});
    return fleetLoadInFlight;
}
async function refreshFleetInBackground(){
    if(!account||document.hidden||$("fleet").hidden)return;
    try{await loadFleet();}catch(error){
        if(error.cancelled)return;
        if(error.status===401){showLogin();$("login-error").textContent="Session expired. Sign in again.";}
    }
}
setInterval(refreshFleetInBackground,30000);
document.addEventListener("visibilitychange",()=>{if(!document.hidden)void refreshFleetInBackground();});
let fleetSort="status",fleetDescending=false;const sensorFilters={};
const sensorColumns=[["name","Host","text"],["os","OS","select"],["status","Status","select"],["protection","Monitoring","select"],["items","Canary / honeypot files","text"],["version","Version","text"],["seen","Last contact","text"],["access","Access","select"]];
const fleetHeaders=$("fleet-rows").closest("table").tHead.rows[0],fleetFilterRow=$("sensor-filters");fleetHeaders.replaceChildren();fleetFilterRow.replaceChildren();
for(const [key,label,kind] of sensorColumns){const th=document.createElement("th"),button=document.createElement("button");th.scope="col";th.dataset.sort=key;button.textContent=label;button.className="history-sort";button.addEventListener("click",()=>{fleetDescending=fleetSort===key?!fleetDescending:false;fleetSort=key;renderFleet();});th.append(button);fleetHeaders.append(th);const filterCell=document.createElement("th"),control=kind==="select"?document.createElement("select"):document.createElement("input");filterCell.dataset.label=label;control.dataset.sensorFilter=key;control.setAttribute("aria-label",`Filter ${label}`);if(kind==="text"){control.type="search";control.placeholder="Filter";}else control.append(new Option("All",""));control.addEventListener("input",()=>{if(control.value)sensorFilters[key]=control.value;else delete sensorFilters[key];renderFleet();});filterCell.append(control);fleetFilterRow.append(filterCell);}
function sensorValue(item,key){const protection=item.protection,state=endpointHealthVisual(item);return key==="name"?item.machineName:key==="os"?endpointOsName(item.operatingSystem):key==="status"?state.label:key==="protection"?(protection?({active:"Active",degraded:"Degraded",stopped:"Stopped","not-configured":"Not configured"}[protection.monitoringState]||"Status unavailable"):"Status unavailable"):key==="items"?(protection?String(protection.deployedCanaryAndHoneypotFiles):"Status unavailable"):key==="version"?item.agentVersion:key==="seen"?time(item.lastSeenUtc):item.revoked?"Revoked":"Enrolled";}
function refreshSensorFilterChoices(){for(const select of fleetFilterRow.querySelectorAll("select")){const key=select.dataset.sensorFilter,current=select.value,values=[...new Set(fleet.map(item=>sensorValue(item,key)))].sort((a,b)=>a.localeCompare(b));select.replaceChildren(new Option("All",""),...values.map(value=>new Option(value,value)));select.value=values.includes(current)?current:"";if(!select.value)delete sensorFilters[key];}}
function renderFleet(){const items=fleet.filter(item=>Object.entries(sensorFilters).every(([key,value])=>sensorValue(item,key).toLocaleLowerCase().includes(value.toLocaleLowerCase()))).sort((a,b)=>compareEndpoints(a,b,fleetSort,fleetDescending));for(const th of fleetHeaders.cells)th.setAttribute("aria-sort",th.dataset.sort===fleetSort?fleetDescending?"descending":"ascending":"none");const active=Object.keys(sensorFilters).length;$("sensor-filter-status").textContent=active?`${active} ${active===1?"filter":"filters"} active`:"No filters";$("fleet-rows").replaceChildren();for(const item of items){const row=document.createElement("tr"),protection=item.protection;row.dataset.endpointId=item.endpointId;cell(row,item.machineName);osCell(row,item.operatingSystem);healthCell(row,item);cell(row,sensorValue(item,"protection"));cell(row,sensorValue(item,"items"));cell(row,item.agentVersion);cell(row,time(item.lastSeenUtc));const badge=document.createElement("span");badge.className="badge"+(item.revoked?" revoked":"");badge.textContent=item.revoked?"Revoked":"Enrolled";cell(row,"").append(badge);for(const [index] of sensorColumns.entries())row.cells[index].dataset.label=sensorColumns[index][1];$("fleet-rows").append(row);}$("fleet-empty").hidden=items.length!==0;document.dispatchEvent(new Event("fleet-rendered"));}
function attributionDetails(event){
    const details=document.createElement("details"),summary=document.createElement("summary"),a=event.attribution;
    summary.textContent="Evidence details";details.append(summary);
    const fields=[["Attribution",a?.level||"Not reported"],["Provider",a?.provider],["User",event.user],["Executable",event.process],["PID",event.processId],["Parent PID",a?.parentProcessId],["Process",a?.processName],["UID",a?.userId],["Effective UID",a?.effectiveUserId],["Filesystem UID",a?.fileSystemUserId],["Login UID",a?.loginUserId],["Account",a?.userName],["Effective account",a?.effectiveUserName],["Login account",a?.loginUserName],["Account name source",a?.accountNameSource],["Session",a?.sessionId],["SHA-256",a?.executableSha256],["Command line",a?.commandLine],["Process start ticks",a?.processStartTicks],["Evidence ID",a?.evidenceId],["Syscall",a?.syscall],["Outcome",a?.outcome],["Path role",a?.pathRole],["Evidence basis",a?.basis]];
    const list=document.createElement("dl");
    for(const [label,value] of fields){if(value===null||value===undefined||value==="")continue;const term=document.createElement("dt"),definition=document.createElement("dd");term.textContent=label;definition.textContent=String(value);definition.style.overflowWrap="anywhere";list.append(term,definition);}
    details.append(list);return details;
}
async function loadAlerts(reset=false){return EventHistory.load(reset);}
$("login-form").addEventListener("submit",event=>{event.preventDefault();const form=event.currentTarget,values=new FormData(form);guarded(form.querySelector("button"),async()=>{await api("/api/v1/auth/login",{userName:values.get("userName"),password:values.get("password"),...factor(values.get("factor"))});form.reset();await enter();},"login-error");});
$("logout").addEventListener("click",()=>guarded($("logout"),async()=>{await api("/api/v1/auth/logout",{});showLogin();}));
for(const nav of document.querySelectorAll("nav button"))nav.addEventListener("click",()=>guarded(nav,async()=>{await view(nav.dataset.view);if(nav.dataset.view==="reports")await loadReports();}));
$("logout").addEventListener("click",()=>reportHistory.replaceChildren());
$("refresh-fleet").addEventListener("click",()=>guarded($("refresh-fleet"),loadFleet));$("clear-sensor-filters").addEventListener("click",()=>{for(const key of Object.keys(sensorFilters))delete sensorFilters[key];for(const control of fleetFilterRow.querySelectorAll("input,select"))control.value="";renderFleet();});
$("reload-alerts").addEventListener("click",()=>guarded($("reload-alerts"),()=>loadAlerts(true)));$("next-alerts").addEventListener("click",()=>guarded($("next-alerts"),()=>EventHistory.next()));$("previous-alerts").addEventListener("click",()=>guarded($("previous-alerts"),()=>EventHistory.previous()));$("history-page-size").addEventListener("change",()=>guarded($("history-page-size"),()=>loadAlerts(true)));
$("mfa-form").addEventListener("submit",event=>{event.preventDefault();const values=new FormData(event.currentTarget),password=values.get("password");guarded($("mfa-action"),async()=>{if(account.mfaEnabled){await api("/api/v1/auth/mfa/disable",{password,...factor(values.get("factor"))});showLogin();return;}if(!setupPending){const setup=await api("/api/v1/auth/mfa/setup",{password});$("authenticator-key").textContent=setup.key;$("mfa-key").hidden=false;$("mfa-challenge").hidden=false;$("mfa-action").textContent="Enable MFA";setupPending=true;return;}const result=await api("/api/v1/auth/mfa/enable",{password,code:String(values.get("factor")||"").trim()});showLogin();$("login").hidden=true;$("recovery").hidden=false;$("recovery-codes").textContent=result.recoveryCodes.join("\n");},"mfa-error");});
$("recovery-done").addEventListener("click",showLogin);
enter().catch(error=>{
    if(error.cancelled)return;
    // A failed initial dashboard request must not clear a verified signed-in session.
    if(error.status===401||!account){showLogin();if(error.status!==401)showRequestFailure($("login-error"),error);}
    else showRequestFailure($("notice"),error);
});
