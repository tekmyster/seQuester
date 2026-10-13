"use strict";
(() => {
    const make=(tag,text,cls)=>{const el=document.createElement(tag);if(text)el.textContent=text;if(cls)el.className=cls;return el;};
    const canEdit=()=>account?.roles?.some(role=>role==="Administrator"||role==="Operator");
    const options=(values)=>{const select=make("select");for(const value of values){const option=make("option",value);option.value=value;select.append(option);}return select;};
    const label=(text,input)=>{const el=make("label",text);el.append(input);return el;};
    let selected=null,epoch=0;
    const nav=make("button","Incidents");nav.dataset.view="incidents";document.querySelector("nav").append(nav);
    const page=make("section");page.id="incidents";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    const caseCard=$("overview").querySelectorAll(".insights article")[1];
    async function updateSummary(){
        caseCard.replaceChildren(make("h3","Analyst cases"),make("p","Loading case counts…","muted"));
        try{const counts=await api("/api/v1/console/incidents/summary");caseCard.replaceChildren(make("h3","Analyst cases"),make("p",`Open: ${counts.open} · Investigating: ${counts.investigating} · Resolved: ${counts.resolved}`),make("p",`Active critical cases: ${counts.criticalActive}`),helpDetails("About case counts","Includes all analyst-created cases, independent of the selected period. Severity is analyst-assigned, not an automatic threat score."));}
        catch(error){if(error.cancelled)return;caseCard.replaceChildren(make("h3","Analyst cases"),make("p","Case counts unavailable. Refresh the overview.","muted"));}
    }
    document.addEventListener("overview-rendered",updateSummary);
    page.append(make("h2","Incident workspace"),helpDetails("About incidents","Analysts create cases and assign severity using linked events. A label alone does not confirm an attack."));
    const notice=make("p");notice.id="incident-notice";notice.setAttribute("role","status");page.append(notice);
    const filter=options(["All","Open","Investigating","Resolved"]),refresh=make("button","Refresh","secondary"),tools=make("div",null,"report-controls");tools.append(label("Status",filter),refresh);page.append(tools);
    const create=make("form",null,"security-card incident-create"),title=make("input"),eventId=make("input"),severity=options(["Medium","Low","High","Critical"]),createButton=make("button","Create incident");
    title.required=true;title.maxLength=200;eventId.type="number";eventId.min="1";eventId.step="1";eventId.required=true;
    const eventKind=options(["Endpoint","Service"]);
    create.append(make("h3","New incident"),label("Title",title),label("Event type",eventKind),label("Starting event number",eventId),label("Severity",severity),createButton);page.append(create);
    const layout=make("div",null,"policy-layout"),list=make("section"),detail=make("section",null,"security-card");detail.hidden=true;layout.append(list,detail);page.append(layout);
    const detailTitle=make("h3"),metadata=make("p",null,"muted"),update=make("form"),status=options(["Open","Investigating","Resolved"]),editSeverity=options(["Low","Medium","High","Critical"]),note=make("textarea"),save=make("button","Save update");note.required=true;note.maxLength=4000;note.rows=4;
    update.append(label("Status",status),label("Severity",editSeverity),label("Analyst note",note),save);
    const links=make("section"),linkForm=make("form",null,"report-controls"),linkInput=make("input"),linkButton=make("button","Link event","secondary");linkInput.type="number";linkInput.min="1";linkInput.step="1";linkInput.required=true;linkForm.append(label("Additional event number",linkInput),linkButton);
    const linkKind=options(["Endpoint","Service"]);linkForm.prepend(label("Event type",linkKind));
    const evidence=make("section"),notes=make("section");detail.append(detailTitle,metadata,update,links,linkForm,evidence,notes);
    const assignment=make("form",null,"report-controls"),assignee=options(["Unassigned"]),assignmentNote=make("input"),assign=make("button","Assign","secondary"),ownerText=make("p");assignmentNote.required=true;assignmentNote.maxLength=500;
    assignment.append(label("Owner",assignee),label("Assignment note",assignmentNote),assign);detail.insertBefore(ownerText,update);detail.insertBefore(assignment,update);
    assignment.addEventListener("submit",event=>{event.preventDefault();if(!selected)return;const item=selected;guarded(assign,async()=>{await api(`/api/v1/console/incidents/${item.id}/assignment`,{expectedVersion:item.version,assignedTo:assignee.value||null,note:assignmentNote.value.trim()});await load();await open(item.id);notice.textContent="Incident assignment saved.";},notice.id);});
    const exports=make("div",null,"report-controls");detail.insertBefore(exports,update);
    for(const [format,title] of [["txt","Export text"],["pdf","Export PDF"]]){const button=make("button",title,"secondary");button.addEventListener("click",()=>guarded(button,async()=>{
        if(!selected)return;const item=selected,generation=epoch;const blob=await api(`/api/v1/console/incidents/${item.id}/export`,{format},true);if(generation!==epoch)return;
        const url=URL.createObjectURL(blob),link=make("a");link.href=url;link.download=`ransom-free-incident-${item.id}.${format}`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    },notice.id));exports.append(button);}
    async function load(){const generation=++epoch;const items=await api("/api/v1/console/incidents"+(filter.value==="All"?"":"?status="+filter.value));if(generation!==epoch)return;
        create.hidden=!canEdit();list.replaceChildren(make("h3","Recent incidents"),make("p","Latest 100 matching cases","muted"));
        for(const item of items){const button=make("button",`${item.title} · ${item.severity} · ${item.status}`,"secondary group-choice");button.addEventListener("click",()=>guarded(button,()=>open(item.id),notice.id));list.append(button);}if(!items.length)list.append(make("p","No incidents match this view.","muted"));
    }
    async function open(id){const generation=++epoch;const [data,owners]=await Promise.all([api("/api/v1/console/incidents/"+id),api("/api/v1/console/incidents/assignees")]);if(generation!==epoch)return;
        selected=data.incident;detail.hidden=false;detailTitle.textContent=selected.title;metadata.textContent=`${selected.severity} · ${selected.status} · revision ${selected.version} · updated ${time(selected.updatedUtc)}`;
        assignee.replaceChildren();const unassigned=make("option","Unassigned");unassigned.value="";assignee.append(unassigned);for(const owner of owners){const option=make("option",owner.userName);option.value=owner.id;assignee.append(option);}if(selected.assignedTo&&!owners.some(x=>x.id===selected.assignedTo)){const option=make("option","Unavailable owner · "+selected.assignedTo);option.value=selected.assignedTo;assignee.append(option);}assignee.value=selected.assignedTo||"";ownerText.textContent="Owner: "+(owners.find(x=>x.id===selected.assignedTo)?.userName||selected.assignedTo||"Unassigned");assignment.hidden=!canEdit();assignmentNote.value="";
        status.value=selected.status;editSeverity.value=selected.severity;note.value="";linkInput.value="";update.hidden=!canEdit();linkForm.hidden=!canEdit();evidence.replaceChildren();
        links.replaceChildren(make("h3","Linked evidence"));
        for(const sequence of data.eventSequenceTexts??data.eventSequences.filter(Number.isSafeInteger).map(String)){const service=sequence.startsWith("-"),caption=(service?"Service event ":"Event ")+sequence.replace(/^-/ ,""),button=make("button",caption,"secondary");button.addEventListener("click",()=>guarded(button,async()=>{
            const caseId=selected?.id,requestEpoch=epoch;const record=await api(`/api/v1/console/evidence/${encodeURIComponent(sequence)}`);if(selected?.id!==caseId||epoch!==requestEpoch)return;
            evidence.replaceChildren(make("h3",caption));
            const context=record.event.serviceContext;
            const lines=[...(service?["Service: "+(context?.name??"Unknown service"),"Source address: "+(context?.sourceAddress??"Unknown")]:["Endpoint: "+record.endpointId,"File: "+record.event.path,"User: "+(record.event.user??"Unknown"),"Process: "+(record.event.process??"Unknown")]),"Observed: "+time(record.event.observedUtc),"Activity: "+record.event.operation];
            for(const line of lines)evidence.append(make("p",line,"incident-evidence"));
            if(context)for(const [label,value] of [["Location",context.location],["Description",context.description],["Note",context.note]])if(value)evidence.append(make("p",label+": "+value,"incident-evidence"));
            evidence.append(attributionDetails(record.event),helpDetails("Diagnostics",`Received: ${time(record.receivedUtc)}\nSource: ${record.event.source}`));
        },notice.id));links.append(button);}
        notes.replaceChildren(make("h3","Recent analyst notes"),make("p","Latest 100 notes · newest first","muted"));for(const item of data.notes){const entry=make("article");entry.append(make("p",time(item.timeUtc)+" · "+item.actor,"muted"),make("p",item.note,"incident-note"));notes.append(entry);}
    }
    const sequence=(field,kind)=>{const value=Number(field.value);if(!Number.isSafeInteger(value)||value<1)throw new Error("Enter a valid event number.");return kind.value==="Service"?-value:value;};
    create.addEventListener("submit",event=>{event.preventDefault();guarded(createButton,async()=>{const result=await api("/api/v1/console/incidents",{title:title.value.trim(),severity:severity.value,eventSequence:sequence(eventId,eventKind)});create.reset();await load();await open(result.id);notice.textContent="Incident created.";},notice.id);});
    update.addEventListener("submit",event=>{event.preventDefault();if(!selected)return;const item=selected;guarded(save,async()=>{await api("/api/v1/console/incidents/"+item.id,{expectedVersion:item.version,status:status.value,severity:editSeverity.value,note:note.value});await load();await open(item.id);notice.textContent="Incident updated.";},notice.id);});
    linkForm.addEventListener("submit",event=>{event.preventDefault();if(!selected)return;const item=selected;guarded(linkButton,async()=>{await api(`/api/v1/console/incidents/${item.id}/events`,{expectedVersion:item.version,eventSequence:sequence(linkInput,linkKind)});await load();await open(item.id);notice.textContent="Evidence linked.";},notice.id);});
    async function show(){await view("incidents");$("page-title").textContent="Incidents";await load();}
    nav.addEventListener("click",()=>guarded(nav,show,notice.id));refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));filter.addEventListener("change",()=>guarded(filter,load,notice.id));
    document.addEventListener("alerts-rendered",()=>{if(!canEdit())return;for(const row of $("alert-rows").rows){const button=make("button","Create incident","secondary revoke-access");const seq=row.dataset.eventSequence;button.disabled=!Number.isSafeInteger(Number(seq))||Number(seq)===0;button.addEventListener("click",()=>guarded(button,async()=>{await show();eventKind.value=seq.startsWith("-")?"Service":"Endpoint";eventId.value=seq.replace(/^-/ ,"");title.focus();},notice.id));row.querySelector("[data-event-evidence]")?.append(button);}});
    document.addEventListener("session-cleared",()=>{epoch++;selected=null;list.replaceChildren();links.replaceChildren();evidence.replaceChildren();notes.replaceChildren();detailTitle.textContent="";metadata.textContent="";detail.hidden=true;create.reset();update.reset();linkForm.reset();notice.textContent="";});
    for(const button of document.querySelectorAll("nav button"))if(button!==nav)button.addEventListener("click",()=>{epoch++;note.value="";});
})();
