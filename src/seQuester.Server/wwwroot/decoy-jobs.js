"use strict";
(()=>{
    const $=id=>document.getElementById(id),form=$("job-form"),fields=$("job-fields"),notice=$("job-notice"),reviewForm=$("job-review-form");
    let requestId=crypto.randomUUID().replaceAll("-",""),admin=false,generation=0,detailGeneration=0,reviewTarget=null,saved=false,sessionEpoch=0,reviewBusy=false;
    const input=name=>form.elements.namedItem(name);
    function factor(code){return code.length===32?{recoveryCode:code}:{code:code||null};}
    async function api(path,body){
        const epoch=sessionEpoch,options={credentials:"same-origin",cache:"no-store"};
        if(body){const csrf=await fetch("/api/v1/auth/csrf",options);if(!csrf.ok)throw new Error("Sign in again in the management console.");options.method="POST";options.headers={"Content-Type":"application/json","X-CSRF":(await csrf.json()).token};options.body=JSON.stringify(body);}
        const response=await fetch(path,options);if(epoch!==sessionEpoch)throw new Error("Session changed. Refresh after signing in.");if(!response.ok){if(response.status===401||response.status===403){sessionEpoch++;generation++;detailGeneration++;admin=false;$("job-editor").hidden=true;$("job-review").hidden=true;$("job-rows").replaceChildren();$("jobs-empty").hidden=true;$("job-evidence").removeAttribute("aria-busy");$("job-details").textContent="Sign-in required.";input("password").value="";input("code").value="";}
            throw new Error(response.status===409?"Job or evidence changed. Refresh before trying again.":response.status===401||response.status===403?"Sign in with an authorized account in the management console.":"Request failed. Check the fields and connection, then retry.");}
        const result=response.status===204?null:await response.json();if(epoch!==sessionEpoch)throw new Error("Session changed. Refresh after signing in.");return result;
    }
    function cell(row,value){const td=document.createElement("td");td.dataset.label=["Sensor ID","Decoy / user","Action","Status","Last check","Details"][row.children.length];td.textContent=value??"—";row.append(td);return td;}
    const node=(tag,text)=>{const element=document.createElement(tag);if(text!==undefined)element.textContent=text;return element;};
    const actionLabels={create:"Create disabled",observe:"Check state",activate:"Activate",disable:"Disable",repair:"Repair",retire:"Retire"};
    const eventLabels={Approved:"Approved",Offered:"Sent to sensor",Expired:"Expired","User receipt":"User session result","Native session observation":"Native state check","Administrator review":"Administrator review"};
    const value=(object,key)=>object?.[key[0].toLowerCase()+key.slice(1)]??object?.[key];
    const parse=payload=>{try{const parsed=typeof payload==="string"?JSON.parse(payload):payload;return parsed&&typeof parsed==="object"&&!Array.isArray(parsed)?parsed:null;}catch{return null;}};
    const date=value=>{if(!value)return "Not recorded";const parsed=new Date(value);return Number.isNaN(parsed.getTime())?"Not recorded":parsed.toLocaleString();};
    function historyMessage(text){$("job-details").replaceChildren(node("p",text));}
    function renderHistory(item,events){
        const box=$("job-details"),job=item.assignment.job;box.replaceChildren(node("h3",job.name));
        const context=node("p",`${actionLabels[job.action]||job.action} · ${item.state}`);context.className="muted";box.append(context);
        if(!events.length){box.append(node("p","No history recorded for this job."));return;}
        const list=node("ol");list.className="job-timeline";
        for(const event of events){
            const entry=node("li"),payload=parse(event.payload),heading=node("h4",eventLabels[event.kind]||event.kind),when=node("p",date(event.createdUtc));when.className="muted";entry.append(heading,when);
            const details=node("dl"),add=(label,content)=>{if(content!==null&&content!==undefined&&content!==""){details.append(node("dt",label),node("dd",String(content)));}};
            add("Recorded by",event.actor);add("Sequence",event.sequence);
            if(!payload){add("Evidence","Details unavailable. Open diagnostics to inspect the recorded payload.");}
            else{
                const receipt=value(payload,"Receipt"),definition=value(payload,"Job");
                add("Result",value(receipt||payload,"State"));add("Resource state",value(receipt||payload,"ResourceState"));
                add("Resource revision",value(receipt||payload,"Revision"));add("Policy revision",value(payload,"PolicyRevision"));
                add("Windows user",value(payload,"UserSid")||value(definition,"UserSid"));add("Session ID",value(payload,"SessionId"));add("Logon ID",value(payload,"LogonId"));
                add("Checked",value(payload,"ObservedUtc")?date(value(payload,"ObservedUtc")):null);add("Review notes",value(payload,"Reason"));
                if(definition){add("Action",actionLabels[value(definition,"Action")]||value(definition,"Action"));add("Type",{V02:"Virtual drive",V03:"Library"}[value(definition,"Kind")]||value(definition,"Kind"));add("Drive letter",value(definition,"Drive"));add("Decoy folder",value(definition,"ApprovedRoot"));add("Expected revision",value(definition,"ExpectedRevision"));add("Expires",value(payload,"ExpiresUtc")?date(value(payload,"ExpiresUtc")):null);}
            }
            entry.append(details);
            // Raw evidence is an explicit diagnostic view; the payload string is retained unchanged.
            const diagnostics=node("details"),summary=node("summary","Diagnostics"),raw=node("pre");raw.setAttribute("aria-label","Recorded payload (JSON)");diagnostics.append(summary);diagnostics.addEventListener("toggle",()=>{if(diagnostics.open&&!raw.isConnected){raw.textContent=typeof event.payload==="string"?event.payload:"No raw payload recorded.";diagnostics.append(raw);}});entry.append(diagnostics);list.append(entry);
        }
        box.append(list);
        const download=node("button","Download raw history");download.type="button";download.className="secondary";download.addEventListener("click",()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(events,null,2)],{type:"application/json"})),link=node("a");link.href=url;link.download=`decoy-job-${item.jobId}-history.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});box.append(download);
    }
    function updateFields(){const drive=input("kind").value==="V02",revision=!["create","observe"].includes(input("action").value);input("drive").disabled=!drive;input("drive").required=drive;input("revision").disabled=!revision;input("revision").required=revision;}
    function newJob(){form.reset();requestId=crypto.randomUUID().replaceAll("-","");input("decoy").value=crypto.randomUUID().replaceAll("-","");saved=false;form.querySelector('[type="submit"]').disabled=false;updateFields();}
    // Authentication retries must retain the exact command identity even after a lost response.
    form.addEventListener("input",event=>{if(!saved&&!['password','code'].includes(event.target.name))requestId=crypto.randomUUID().replaceAll("-","");updateFields();});
    $("job-new").addEventListener("click",newJob);
    async function refresh(){
        const stamp=++generation;const rows=await api("/api/v1/console/decoy-jobs");if(stamp!==generation)return;$("job-rows").replaceChildren();$("jobs-empty").hidden=rows.length!==0;
        for(const item of rows){const row=document.createElement("tr"),job=item.assignment.job;cell(row,item.endpointId);cell(row,`${job.name} · ${job.userSid}`);cell(row,actionLabels[job.action]||job.action);cell(row,item.state);
            const observed=parse(item.observation);cell(row,observed?`${value(observed,"State")||"Not recorded"} · ${date(value(observed,"ObservedUtc"))}`:item.observation?"Check details unavailable":"Pending");
            const actions=cell(row,"");const details=document.createElement("button");details.type="button";details.textContent="History";details.className="secondary";details.addEventListener("click",async()=>{const selection=++detailGeneration;notice.textContent="";historyMessage(`Loading history for ${job.name}…`);$("job-evidence").setAttribute("aria-busy","true");try{const events=await api(`/api/v1/console/decoy-jobs/${item.jobId}/history`);if(selection===detailGeneration){renderHistory(item,events);$("job-evidence").focus();}}catch(error){if(selection===detailGeneration){historyMessage("History could not be loaded. Select History to retry.");notice.textContent=error.message;}}finally{if(selection===detailGeneration)$("job-evidence").removeAttribute("aria-busy");}});actions.append(details);
            if(admin&&item.state==="Needs review"){const review=document.createElement("button");review.type="button";review.textContent="Review";review.addEventListener("click",()=>{if(reviewBusy)return;reviewTarget=item;reviewForm.reset();$("job-review-target").textContent=`${job.name} · ${item.endpointId}`;$("job-review").hidden=false;});actions.append(review);}$("job-rows").append(row);
        }
    }
    form.addEventListener("submit",async event=>{
        event.preventDefault();if(!admin||saved)return;const expected=input("revision").disabled?null:Number(input("revision").value);if(expected!==null&&(!Number.isSafeInteger(expected)||expected<1)){notice.textContent="Enter a supported whole-number revision.";return;}
        const body={endpointId:input("endpoint").value.trim(),job:{jobId:requestId,userSid:input("sid").value.trim(),stateDirectory:input("state").value.trim(),approvedRoot:input("root").value.trim(),action:input("action").value,decoyId:input("decoy").value.trim(),kind:input("kind").value,name:input("name").value.trim(),drive:input("kind").value==="V02"?input("drive").value:null,expectedRevision:expected},administratorPassword:input("password").value,...factor(input("code").value.trim())};
        fields.disabled=true;try{await api("/api/v1/console/decoy-jobs",body);saved=true;form.querySelector('[type="submit"]').disabled=true;notice.textContent="Job approved. The endpoint will retrieve it when connected.";await refresh();}catch(error){notice.textContent=error.message;}finally{fields.disabled=false;input("password").value="";input("code").value="";updateFields();}
    });
    reviewForm.addEventListener("submit",async event=>{event.preventDefault();if(!admin||!reviewTarget||reviewBusy)return;const target=reviewTarget;const value=name=>reviewForm.elements.namedItem(name).value;reviewBusy=true;$("job-review-fields").disabled=true;
        try{await api("/api/v1/console/decoy-jobs/review",{endpointId:target.endpointId,jobId:target.jobId,policyRevision:target.assignment.policyRevision,observationDigest:target.observationDigest,reason:value("reason"),administratorPassword:value("password"),...factor(value("code").trim())});if(reviewTarget===target){$("job-review").hidden=true;reviewTarget=null;}notice.textContent="Review recorded. Evidence retained.";await refresh();}catch(error){notice.textContent=error.message;}finally{reviewBusy=false;$("job-review-fields").disabled=false;reviewForm.elements.namedItem("password").value="";reviewForm.elements.namedItem("code").value="";}});
    $("job-refresh").addEventListener("click",()=>refresh().catch(error=>notice.textContent=error.message));
    newJob();api("/api/v1/auth/me").then(account=>{admin=account.roles.includes("Administrator")&&!account.mustChangePassword&&!account.mustEnrollMfa;$("job-editor").hidden=!admin;notice.textContent=admin?"":"Read-only access.";return refresh();}).catch(error=>notice.textContent=error.message);
})();
