"use strict";

// Presentation helpers never grant permissions or reinterpret unknown failures.
function helpDetails(title,text){
    const details=document.createElement("details"),summary=document.createElement("summary"),body=document.createElement("p");
    details.className="help-details";summary.textContent=title;body.textContent=text;
    details.append(summary,body);return details;
}
function actorEvidenceState(event){
    const present=value=>typeof value==="string"&&value.trim()!==""&&!/^(unknown|unavailable|not reported)$/i.test(value.trim());
    const fields=[present(event.user),present(event.process),Number.isInteger(event.processId)&&event.processId>0];
    return fields.every(Boolean)?"Complete":fields.some(Boolean)?"Partial":"Unavailable";
}
function actorEvidenceSummary(event){
    const summary=document.createElement("div"),state=actorEvidenceState(event),label=document.createElement("strong"),source=document.createElement("p");
    summary.className="actor-evidence";summary.dataset.actorEvidence=state;
    label.textContent=`Actor details: ${state}`;source.textContent=`Source: ${event.source||"Not reported"}`;
    summary.append(label,source);
    if(state!=="Complete"){
        const note=document.createElement("p");note.className="muted";
        note.textContent=/inotify|FileSystemWatcher/i.test(event.source||"")?"This file notification did not include all actor fields. Audit events are listed separately.":"This event did not report all three actor fields. The available evidence is retained.";
        summary.append(note);
    }
    return summary;
}
function knownLabel(labels,key,fallback){return Object.hasOwn(labels,key)?labels[key]:fallback;}
function windowsSyscallPanel(s){
    const n=s.native,token=t=>`SID: ${t.sid??"Unavailable"}\nToken / logon: ${t.tokenId??"Unavailable"} / ${t.authenticationId??"Unavailable"}\nType / impersonation level: ${t.type??"Unavailable"} / ${t.impersonationLevel??"Unavailable"}\nIntegrity / elevation: ${t.integrityRid??"Unavailable"} / ${t.elevated??"Unavailable"}\nCollection mask: ${t.captured} · Query status: ${t.queryStatus.join(", ")}`;
    const node=helpDetails("Windows syscall accessing-thread evidence",`Scope: ${s.scope}\nPID / thread: ${n.processId} / ${n.threadId}\nProcess creation FILETIME: ${n.processCreatedFileTime}\nImpersonating: ${n.threadImpersonating}\nProcess owner:\n${token(n.processOwner)}\nEffective accessing thread:\n${token(n.threadEffective)}\nNative result: ${n.outcome} · ${n.returnStatus}\nSource / sequence: ${s.sourceInstance} / ${n.sequence}\nEntry / return clock: ${n.entryMonotonic} / ${n.returnMonotonic}\nTarget name: ${s.targetStatus.state} · ${s.targetStatus.reason}\nTarget queried: ${s.targetQueriedUtc}\nLost records: ${s.lostRecords}\nRaw record SHA-256: ${n.rawRecordSha256}\nA pending submission is not a completed operation. The target name was queried later. This experimental scope does not establish general sensor coverage.`);
    node.append(helpDetails("Structured syscall evidence",JSON.stringify(s,null,2)));
    node.classList.add("kernel-evidence","windows-syscall-evidence");return node;
}
function windowsAcquisitionPanel(a){
    const recovery=a.version===2?`Recovery provider / epoch: ${a.recoveryProvider??'Unavailable'} / ${a.recoveryEpoch??'Unavailable'}\nRecovery observed: ${a.recoveryObservedUtc??'Unavailable'}\nPrior native query attempt: Unknown after recovery\n`:'';
    const state=knownLabel({0:"No exact executable association",1:"Executable collection refused before process binding",2:"Executable copy pending",3:"Executable copy failed after process binding",4:"Bound executable bytes unavailable",5:"Executable bytes pinned for this operation"},a.state,"Collection observation unavailable");
    const node=helpDetails("Windows executable collection",`${state}\nCollection status: ${a.status?.state??"Unavailable"} · ${a.status?.reason??"Unavailable"}\nReason: ${a.reasonCode??"Unavailable"}\nFailure stage: ${a.failureStage??"Unavailable"} · Native status: ${a.nativeStatus??"Unavailable"}\nProvider / epoch: ${a.provider??"Unavailable"} / ${a.epoch??"Unavailable"}\nOperation: ${a.instance??"Unavailable"} / ${a.sequence??"Unavailable"}\nProcess generation: ${a.processGeneration??"Unavailable"}\nNegative association: ${a.negativeAssociation??"Unavailable"}\nOrigin candidate / generation: ${a.originCandidate??"Unavailable"} / ${a.originGeneration??"Unavailable"}\nObservation clock: ${a.observedQpc??"Unavailable"}\nCompanion SHA-256: ${a.rawSha256??"Unavailable"}\nOperation record SHA-256: ${a.operationRecordSha256??"Unavailable"}\n${recovery}These collection observations do not establish executable safety or successful forensic preservation. Inspect executable hash and preservation evidence separately.`);
    node.classList.add("kernel-evidence","windows-acquisition-evidence");return node;
}
function requestFailureText(error){
    const status=knownLabel({400:"Check your input and try again.",401:"Sign-in or verification failed.",403:"You don’t have access to this action.",404:"This item is no longer available. Refresh the page.",409:"This item changed. Refresh before saving.",413:"The request is too large.",429:"Too many attempts. Try again later."},error?.status,null);
    if(status)return status;
    if(error?.status>=500)return "Request outcome unconfirmed. Check before retrying.";
    const known=["Connection unavailable. Try again.","Cannot start sign-in.","Enter a valid event number.","Enter your password in Administrator verification."];
    return known.includes(error?.message)?error.message:"Couldn’t complete the request. Check the result before retrying.";
}
function showRequestFailure(target,error){
    target.textContent=requestFailureText(error);
    if(error?.message&&error.message!==target.textContent)target.append(helpDetails("Diagnostics",error.message));
}
function emailDeliveryText(state){
    return knownLabel({Accepted:"Sent · receipt unconfirmed",Disabled:"Disabled",Waiting:"Waiting for alerts",Sending:"Sending",Pending:"Delivery pending",Blocked:"Delivery blocked"},state,"Delivery status unavailable");
}
function operationPresentation(item){
    const component=knownLabel({Management:"Management","Management storage":"Management database","Identity storage":"Account database","Callback storage":"Token inbox","Callback inbox":"Token inbox","Callback syslog":"Token syslog","Endpoint syslog relay":"Endpoint syslog","Callback email":"Token email","Directory sessions":"Directory sign-in checks","Storage topology":"Database","Identity key protection":"Sign-in key protection",Release:"Release"},item?.component,"Other service");
    let state=knownLabel({Readable:"Read access available",Unconfigured:"Not configured",Unavailable:"Unavailable",Pending:"Pending",Blocked:"Blocked",Unknown:"Status unavailable",Configured:"Configured",Disabled:"Disabled",SqlServer:"SQL Server",Sqlite:"SQLite","Not approved":"Development build"},item?.state,"Status unavailable");
    if(item?.state==="Reported")state=deliveryText(String(item.detail||"").split("; checkpoint ")[0]);
    if(item?.component==="Callback email")state=emailDeliveryText(item.state);
    return {component,state:state||"Status unavailable"};
}
function operationsSummaryText(data,now=Date.now()){
    const checked=Date.parse(data?.checkedUtc);
    if(!Number.isFinite(checked)||checked>now+60000)return "Status unavailable";
    if(now-checked>90000)return "Status out of date";
    return data.storageReadable===true?"Storage readable":"Storage needs attention";
}
function endpointHealthText(raw,lastSeenUtc,now=Date.now()){
    if(lastSeenUtc!==undefined){
        const seen=Date.parse(lastSeenUtc);
        if(!Number.isFinite(seen)||seen>now+60000)return "Status unavailable | Protection unconfirmed";
        if(now-seen>=300000)return "Status stale | Protection unconfirmed";
    }
    const ready="Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)";
    const modes=["File activity: inotify; actor evidence supplied separately by Linux Audit when enabled","File activity: fanotify PIDFD + inotify names"];
    if(modes.some(mode=>raw===`Canary monitoring configured | ${mode} | ${ready}`))return "Canary monitoring active | User/process attribution active";
    for(const prefix of ["Canary monitoring active | ",...modes.map(mode=>`Canary monitoring configured | ${mode} | `)]){
        if(!raw?.startsWith(prefix))continue;
        const state=raw.slice(prefix.length);
        if(state.startsWith("Linux Audit degraded:")||state.startsWith("Audit unavailable:"))return "Canary monitoring active | User/process attribution needs attention";
        if(state==="Audit disabled")return "Canary monitoring active | User/process attribution disabled";
        if(state==="Audit connection not verified"||state==="Linux Audit: root checks passed; awaiting heartbeat advancement"||state==="Linux Audit: root checks passed; awaiting next heartbeat")return "Canary monitoring active | Checking user/process attribution";
    }
    if(!raw?.trim())return "Status unavailable";
    if(["Monitoring","Starting","Canary monitoring active | User/process attribution active","No canaries configured"].includes(raw))return raw;
    if(/queue.*full/i.test(raw))return "Alert storage full · New alerts at risk";
    if(/queue.*failed/i.test(raw))return "Alert storage failed · Review Diagnostics";
    if(/\bgap\b|\bloss\b|overflow|input drops [1-9]/i.test(raw))return "Monitoring incomplete · Review Diagnostics";
    if(/stopped/i.test(raw))return "Monitoring stopped";
    if(/failed|failure|\berror\b/i.test(raw))return "Monitoring failed · Review Diagnostics";
    if(/degraded|warning|unavailable|disabled|pending|unverified|checking|configured|offline/i.test(raw))return "Needs attention · Review Diagnostics";
    return "Status unconfirmed · Review Diagnostics";
}
function deliveryText(message){
    if(message==="Waiting for callback activity"||message==="Waiting for alerts")return "Waiting for alerts";
    if(message?.startsWith("Disabled"))return "Disabled · alerts retained";
    if(/^(UDP|TCP|TLS) sent to .+; (delivery|collector persistence) is unconfirmed\.$/.test(message||""))return "Sent · receipt unconfirmed";
    if(/pending|blocked|failed|unavailable/i.test(message||""))return "Delivery pending · See Diagnostics";
    return message?"Delivery unconfirmed · See Diagnostics":"Status unavailable";
}
function endpointHealthVisual(itemOrRaw,lastSeenUtc,revoked=false,now=Date.now()){
    const item=typeof itemOrRaw==="object"&&itemOrRaw!==null?itemOrRaw:{health:itemOrRaw,lastSeenUtc,revoked},raw=item.health||"",protection=item.protection;
    const seen=Date.parse(item.lastSeenUtc);if(item.revoked)return {kind:"failed",label:"Monitoring stopped",detail:"This sensor no longer has management access.",rank:0};
    if(Number.isFinite(seen)&&now-seen>=300000)return {kind:"failed",label:"Offline",detail:"This sensor has not checked in recently.",rank:0};
    if(!Number.isFinite(seen)||seen>now+60000||!protection)return {kind:"unknown",label:"Status unavailable",detail:"This sensor has not reported enough current information to confirm monitoring.",rank:1};
    if(protection.monitoringState==="stopped")return {kind:"failed",label:"Monitoring stopped",detail:"This sensor reports that monitoring is stopped.",rank:0};
    if(protection.monitoringState==="not-configured")return {kind:"unknown",label:"Status unavailable",detail:"This sensor has not reported active monitoring.",rank:1};
    if(/policy pending/i.test(raw))return {kind:"warning",label:"Needs attention",detail:/automatic response paused/i.test(raw)?"Monitoring and alerts are working. The latest policy has not arrived, so automatic blocking is paused.":"Monitoring is working. The latest policy update is delayed.",rank:1};
    if(protection.monitoringState==="degraded"||/failed|failure|\berror\b|\bgap\b|overflow|input drops [1-9]|degraded|warning/i.test(raw))return {kind:"warning",label:"Needs attention",detail:"Monitoring is running, but part of the sensor needs attention.",rank:1};
    if(protection.monitoringState==="active")return {kind:"healthy",label:"Monitoring",detail:/user\/process attribution active/i.test(raw)?"Monitoring and alerts are working. User and process details are available.":"Monitoring and alerts are working.",rank:3};
    return {kind:"unknown",label:"Status unavailable",detail:"This sensor has not reported enough current information to confirm monitoring.",rank:1};
}
function tooltipIcon(label,detail=label){
    const wrapper=document.createElement("span"),tooltip=document.createElement("span");wrapper.className="accessible-icon";wrapper.tabIndex=0;wrapper.setAttribute("role","img");wrapper.setAttribute("aria-label",`${label}. ${detail}`);wrapper.title=detail;tooltip.className="icon-tooltip";tooltip.textContent=detail;tooltip.setAttribute("aria-hidden","true");wrapper.append(tooltip);
    wrapper.addEventListener("keydown",event=>{if(event.key==="Escape")wrapper.classList.add("tooltip-dismissed");});for(const event of ["focus","mouseenter"])wrapper.addEventListener(event,()=>{wrapper.classList.remove("tooltip-dismissed");positionIconTooltip(wrapper);});return wrapper;
}
function positionIconTooltip(wrapper){const tip=wrapper.querySelector(".icon-tooltip"),rect=wrapper.getBoundingClientRect();if(!tip)return;tip.style.left=Math.max(8,Math.min(rect.right+4,document.documentElement.clientWidth-tip.offsetWidth-8))+"px";tip.style.top=Math.max(8,Math.min(rect.top,document.documentElement.clientHeight-tip.offsetHeight-8))+"px";}
if(typeof document!=="undefined"){const reposition=()=>{for(const wrapper of document.querySelectorAll(".accessible-icon:is(:hover,:focus-visible)"))positionIconTooltip(wrapper);};document.addEventListener("scroll",reposition,true);window.addEventListener("resize",reposition);}
function endpointStatusIcon(item){
    const state=endpointHealthVisual(item),wrapper=tooltipIcon(state.label,state.detail),ns="http://www.w3.org/2000/svg",svg=document.createElementNS(ns,"svg");wrapper.classList.add("status-"+state.kind);svg.setAttribute("viewBox","0 0 24 24");svg.setAttribute("aria-hidden","true");svg.setAttribute("focusable","false");
    wrapper.dataset.endpointHealth=item.health||"";wrapper.dataset.endpointSeen=item.lastSeenUtc||"";wrapper.dataset.endpointRevoked=String(!!item.revoked);wrapper.dataset.endpointProtection=item.protection?.monitoringState||"";wrapper.dataset.endpointItems=String(item.protection?.deployedCanaryAndHoneypotFiles??"");
    const shape=document.createElementNS(ns,"circle");shape.setAttribute("cx","12");shape.setAttribute("cy","12");shape.setAttribute("r","11");shape.setAttribute("fill","currentColor");svg.append(shape);
    if(state.kind==="healthy"||state.kind==="failed"){const mark=document.createElementNS(ns,"path");mark.setAttribute("d",state.kind==="healthy"?"m6 12 4 4 8-8":"m8 8 8 8m0-8-8 8");mark.setAttribute("fill","none");mark.setAttribute("stroke","white");mark.setAttribute("stroke-width","2.5");mark.setAttribute("stroke-linecap","round");mark.setAttribute("stroke-linejoin","round");svg.append(mark);}else{const mark=document.createElementNS(ns,"text");mark.setAttribute("x","12");mark.setAttribute("y","17");mark.setAttribute("text-anchor","middle");mark.setAttribute("font-size","17");mark.setAttribute("font-weight","bold");mark.setAttribute("fill",state.kind==="warning"?"#172b41":"white");mark.textContent=state.kind==="warning"?"!":"?";svg.append(mark);}wrapper.prepend(svg);return wrapper;
}
function endpointOsName(value){return knownLabel({windows:"Windows",linux:"Linux",macos:"macOS"},value,"Unknown OS");}
function endpointOsIcon(value){
    const label=endpointOsName(value),wrapper=tooltipIcon(label),file=knownLabel({windows:"windows",linux:"linux",macos:"apple"},value,null);wrapper.classList.add("os-icon");if(file){const image=document.createElement("img");image.src=`/icons/os/${file}.svg`;image.alt="";image.setAttribute("aria-hidden","true");image.width=image.height=24;wrapper.prepend(image);}else{const mark=document.createElement("span");mark.textContent="?";mark.className="unknown-os";mark.setAttribute("aria-hidden","true");wrapper.prepend(mark);}return wrapper;
}
function osCell(row,value){const td=document.createElement("td"),name=document.createElement("span");name.className="os-name";name.textContent=endpointOsName(value);name.setAttribute("aria-hidden","true");td.append(endpointOsIcon(value),name);row.append(td);return td;}
function compareEndpoints(a,b,sort,descending=false){
    const key=item=>sort==="status"?endpointHealthVisual(item).rank:sort==="protection"?(item.protection?.monitoringState??null):sort==="items"?(item.protection?.deployedCanaryAndHoneypotFiles??null):sort==="os"?endpointOsName(item.operatingSystem):sort==="seen"?(Number.isFinite(Date.parse(item.lastSeenUtc))?Date.parse(item.lastSeenUtc):null):sort==="version"?item.agentVersion:sort==="access"?(item.revoked?"Revoked":"Enrolled"):item.machineName;
    const x=key(a),y=key(b);if(x==null&&y!=null)return 1;if(y==null&&x!=null)return -1;
    const value=x==null?0:typeof x==="number"?x-y:String(x).localeCompare(String(y));return (descending?-value:value)||a.endpointId.localeCompare(b.endpointId);
}
function healthCell(row,item){
    const td=document.createElement("td"),state=endpointHealthVisual(item),label=document.createElement("span");label.className="sensor-status-label";label.textContent=state.label;td.append(endpointStatusIcon(item),label);
    if(item.health)td.append(helpDetails("Technical details",item.health));
    row.append(td);return td;
}
