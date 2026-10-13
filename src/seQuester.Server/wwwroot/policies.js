"use strict";
(() => {
    const make=(tag,text,cls)=>{const el=document.createElement(tag);if(text)el.textContent=text;if(cls)el.className=cls;return el;};
    const admin=()=>account?.roles?.includes("Administrator");
    let groups=[],statuses=[],endpoints=[],selected=null,generation=0,deployments=[],tokens=[],allowlist=[];
    const nav=make("button","Policies");nav.dataset.view="policies";document.querySelector("nav").append(nav);
    const page=make("section");page.id="policies";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    page.append(make("h2","Group policies"),make("p","Set monitoring intervals and deploy canaries to locally approved folders. Existing files are never overwritten.","muted"));
    const notice=make("p");notice.id="policy-notice";notice.setAttribute("role","status");page.append(notice);
    const refresh=make("button","Refresh","secondary");page.append(refresh);
    const createForm=make("form",null,"report-controls"),nameLabel=make("label","New group"),nameInput=make("input");nameInput.required=true;nameInput.maxLength=100;nameInput.name="name";nameLabel.append(nameInput);
    const create=make("button","Create group");createForm.append(nameLabel,create);page.append(createForm);
    const layout=make("div",null,"policy-layout"),groupList=make("section"),editor=make("section",null,"security-card");layout.append(groupList,editor);page.append(layout);editor.hidden=true;
    const heading=make("h3"),revision=make("p",null,"muted"),policyForm=make("form"),intervalLabel=make("label","Integrity check interval (seconds)"),interval=make("input");
    interval.type="number";interval.min="15";interval.max="3600";interval.step="15";interval.required=true;intervalLabel.append(interval);
    const publish=make("button","Publish policy"),publishNote=helpDetails("When changes apply","Assigned endpoints apply changes when they next synchronize. Offline endpoints keep their last valid policy.");
    const deploymentList=make("div"),addDeployment=make("button","Add canary","secondary");addDeployment.type="button";
    policyForm.append(intervalLabel,make("h3","Canary deployment"),make("p","Choose approved folders and file types. Removing a row does not remove existing files.","muted"),helpDetails("Canary deployment details","Folder aliases must be approved on each endpoint. Removed plan entries remain monitored locally. Tokens must match the file type; document readers may block callbacks."),deploymentList,addDeployment,publishNote,publish);const history=make("section");editor.append(heading,revision,policyForm,history);
    const queueSection=make("fieldset"),queueCount=make("input"),queueBytes=make("input");
    queueSection.append(make("legend","Offline alert storage"));
    for(const [input,title,min,max,value] of [[queueCount,"Maximum alerts",1000,1000000,10000],[queueBytes,"Maximum payload (MiB)",32,1024,128]]){
        const label=make("label",title);input.type="number";input.min=min;input.max=max;input.step=1;input.required=true;input.value=value;label.append(input);queueSection.append(label);
    }
    queueSection.append(make("p","A full queue cannot accept new alerts.","muted"),helpDetails("Storage requirements","Requires a compatible queue-enabled client. Lower limits retain existing alerts. Reserve additional disk space for database overhead."));policyForm.insertBefore(queueSection,publishNote);
    const forensicSection=make("fieldset"),forensicControls={};forensicSection.append(make("legend","Actor executable evidence"),make("p","Sensors hash the executable that touched a monitored file. The actor size limit controls preserved copies; readable actors above that limit are still hashed. Target files are not hashed or copied by this collector. Preserved actors are queued for protected server storage. Check the server receipt in Event History to confirm transfer; local evidence remains on the sensor.","muted"));
    for(const [key,title,type,min,max,value] of [["preserveActorOnAlert","Preserve actor executable on alerts","checkbox",0,0,true],["preservationThreshold","Preservation threshold","select",0,0,"alert"],["maximumActorMiB","Maximum actor size (MiB)","number",1,1024,256],["evidenceStoreMiB","Evidence store limit (MiB)","number",64,102400,1024],["cacheEntries","Executable cache entries","number",1,4096,256]]){
        const label=make("label",title),input=make(type==="select"?"select":"input");input.setAttribute("aria-label",title);if(type==="select")for(const choice of ["alert","high","critical"])input.append(new Option(choice,choice));else input.type=type;
        if(type==="number"){input.min=min;input.max=max;input.step=1;input.required=true;}if(type==="checkbox")input.checked=value;else input.value=value;label.append(input);forensicSection.append(label);forensicControls[key]=input;
    }
    forensicSection.append(helpDetails("Evidence limitations","SHA-256 or a valid signature is evidence, not proof of safety. A stopped process, inaccessible image, full store or collection race can leave metadata without an executable copy. High/critical thresholds require detections with those severities; current monitored-file alerts use the alert threshold. Audit events do not always supply actor thread tokens, offsets or final file state."));policyForm.insertBefore(forensicSection,publishNote);
    function renderDeployments(){
        deploymentList.replaceChildren();addDeployment.hidden=!admin();
        deployments.forEach((item,index)=>{
            const row=make("fieldset"),legend=make("legend",`Canary ${index+1}`);row.append(legend);
            for(const [key,title,max] of [["folderAlias","Folder alias",64],["fileName","File name",160]]){
                const label=make("label",title),input=make("input");input.value=item[key];input.required=true;input.maxLength=max;input.disabled=!admin()||!!item.published;
                input.addEventListener("input",()=>{item[key]=input.value;});label.append(input);row.append(label);
            }
            const label=make("label","File type"),type=make("select");for(const value of ["docx","xlsx","pdf","txt","csv","rtf","html","svg","json","xml","md"]){const option=make("option",value.toUpperCase());option.value=value;type.append(option);}type.value=item.fileType;type.disabled=!admin()||!!item.published;type.addEventListener("change",()=>{item.fileType=type.value;});label.append(type);row.append(label);
            type.addEventListener("change",()=>{item.callbackTokenId=null;item.callbackUrl=null;renderDeployments();});
            const tokenLabel=make("label","Embedded callback"),tokenSelect=make("select"),local=make("option","Local monitoring only");local.value="";tokenSelect.append(local);
            for(const token of tokens.filter(t=>!t.revoked&&t.type===item.fileType||t.id===item.callbackTokenId)){const option=make("option",token.name+(token.revoked?" (revoked)":""));option.value=token.id;tokenSelect.append(option);}tokenSelect.value=item.callbackTokenId||"";tokenSelect.disabled=!admin()||!!item.published;tokenSelect.addEventListener("change",()=>{item.callbackTokenId=tokenSelect.value||null;item.callbackUrl=null;});tokenLabel.append(tokenSelect);row.append(tokenLabel);
            if(admin()){const remove=make("button","Remove from plan","secondary");remove.type="button";remove.addEventListener("click",()=>{deployments.splice(index,1);renderDeployments();});row.append(remove);}deploymentList.append(row);
        });addDeployment.disabled=deployments.length>=100;
    }
    addDeployment.addEventListener("click",()=>{if(deployments.length>=100)return;deployments.push({id:crypto.randomUUID().replaceAll("-",""),folderAlias:"",fileName:"",fileType:"docx"});renderDeployments();});
    const syslogSection=make("fieldset"),syslogMode=make("select"),syslogFields=make("div"),syslogControls={};syslogSection.append(make("legend","Client syslog / Wazuh"),helpDetails("Syslog routing","These settings control client forwarding. Configure server forwarding in Notifications. Disable client forwarding for server-only delivery. Both senders can produce duplicates."));
    for(const [value,text] of [["local","Use client settings"],["enabled","Send to this destination"],["disabled","Disabled"]]){const option=make("option",text);option.value=value;syslogMode.append(option);}const modeLabel=make("label","Client sender");modeLabel.append(syslogMode);syslogSection.append(modeLabel,syslogFields);
    for(const [key,title,kind,choices] of [["host","Host","text"],["port","Port","number"],["transport","Transport","select",["TCP","TLS","UDP"]],["format","Format","select",["RFC3164","RFC5424"]],["octetCounting","Octet-counted framing","checkbox"],["facility","Facility","number"],["severity","Severity","number"]]){const label=make("label",title),input=make(kind==="select"?"select":"input");if(kind==="select")for(const value of choices){const option=make("option",value);option.value=value;input.append(option);}else input.type=kind;if(key==="host")input.maxLength=253;if(key==="port"){input.min=1;input.max=65535;}if(key==="facility"){input.min=0;input.max=23;}if(key==="severity"){input.min=0;input.max=7;}label.append(input);syslogFields.append(label);syslogControls[key]=input;}
    function renderSyslog(){syslogFields.hidden=syslogMode.value!=="enabled";for(const input of Object.values(syslogControls))input.disabled=!admin()||syslogMode.value!=="enabled";syslogControls.host.required=syslogMode.value==="enabled";}syslogMode.addEventListener("change",renderSyslog);
    const allowSection=make("fieldset"),allowRows=make("div"),addAllow=make("button","Add allowed process","secondary");addAllow.type="button";allowSection.append(make("legend","Trusted processes"),helpDetails("Trust rule scope","Match the exact executable path and SHA-256. Use a folder and expiry to limit the rule. Events remain recorded."),allowRows,addAllow);
    function renderAllowlist(){allowRows.replaceChildren();addAllow.hidden=!admin();addAllow.disabled=allowlist.length>=100;allowlist.forEach((rule,index)=>{const row=make("fieldset");row.append(make("legend",`Rule ${index+1}`));for(const [key,title,limit] of [["executable","Executable path",1024],["sha256","SHA-256",64],["folder","Canary folder (optional)",1024],["expiresUtc","Expiry UTC (optional, ISO 8601)",40]]){const label=make("label",title),input=make("input");input.value=rule[key]||"";input.maxLength=limit;input.required=key==="executable"||key==="sha256";input.disabled=!admin();input.addEventListener("input",()=>rule[key]=input.value||null);label.append(input);row.append(label);}if(admin()){const remove=make("button","Remove rule","secondary");remove.type="button";remove.addEventListener("click",()=>{allowlist.splice(index,1);renderAllowlist();});row.append(remove);}allowRows.append(row);});}
    addAllow.addEventListener("click",()=>{if(allowlist.length>=100)return;allowlist.push({executable:"",sha256:"",folder:null,expiresUtc:null});renderAllowlist();});
    policyForm.insertBefore(syslogSection,publishNote);policyForm.insertBefore(allowSection,publishNote);
    const automaticSection=make("fieldset"),automaticControls={},automaticProof=make("div"),automaticPassword=make("input"),automaticCode=make("input");
    automaticSection.append(make("legend","Automatic process response"),make("p","Off by default. Requires separate endpoint approval. Stopping an application can lose unsaved work; remote callbacks never trigger this action.","muted"));
    for(const [key,title] of [["enabled","Enable automatic process stopping"],["onRead","File reads"],["onWrite","Content writes"],["onDelete","Delete access"],["onPermissionChange","Permission changes"]]){const input=make("input"),label=make("label",title);input.type="checkbox";label.append(input);automaticControls[key]=input;automaticSection.append(label);}
    const automaticLimit=make("input"),limitLabel=make("label","Maximum attempts per minute");automaticLimit.type="number";automaticLimit.min=1;automaticLimit.max=10;automaticLimit.value=3;limitLabel.append(automaticLimit);automaticSection.append(limitLabel);
    automaticPassword.type="password";automaticPassword.maxLength=256;automaticPassword.autocomplete="current-password";automaticCode.maxLength=32;automaticCode.autocomplete="one-time-code";
    const automaticPasswordLabel=make("label","Administrator password"),automaticCodeLabel=make("label","App MFA code (if enabled)");automaticPasswordLabel.append(automaticPassword);automaticCodeLabel.append(automaticCode);automaticProof.append(helpDetails("Verify this change","Use your administrator password or a recent SSO sign-in, plus MFA when enabled."),automaticPasswordLabel,automaticCodeLabel);automaticSection.append(automaticProof);policyForm.insertBefore(automaticSection,publishNote);
    function renderAutomatic(){const enabled=automaticControls.enabled.checked;automaticProof.hidden=!enabled||!admin();automaticPasswordLabel.hidden=account?.authentication==="SSO";automaticPassword.required=enabled&&admin()&&account?.authentication!=="SSO";for(const input of Object.values(automaticControls))input.disabled=!admin();automaticLimit.disabled=!admin();}
    automaticControls.enabled.addEventListener("change",renderAutomatic);
    const assignments=make("section");assignments.className="policy-assignments";page.append(assignments);
    function clear(){generation++;groups=[];statuses=[];endpoints=[];selected=null;groupList.replaceChildren();history.replaceChildren();assignments.replaceChildren();editor.hidden=true;createForm.reset();notice.textContent="";createForm.hidden=true;}
    async function load(){
        const epoch=++generation;const values=await Promise.all([api("/api/v1/console/groups"),api("/api/v1/console/policy-status"),api("/api/v1/console/endpoints"),api("/api/v1/console/callbacks/tokens")]);if(epoch!==generation)return;
        [groups,statuses,endpoints,tokens]=values;createForm.hidden=!admin();editor.hidden=true;selected=null;groupList.replaceChildren(make("h3","Endpoint groups"));
        if(!groups.length)groupList.append(make("p","No groups yet. Unassigned agents use a 15-second integrity interval.","muted"));
        for(const group of groups){const button=make("button",`${group.name} · ${group.endpointCount} endpoints · revision ${group.revision}`,"secondary group-choice");button.addEventListener("click",()=>guarded(button,()=>select(group),notice.id));groupList.append(button);}
        renderAssignments();
    }
    async function select(group){
        const epoch=++generation;selected=group;deployments=(group.settings.deployments||[]).map(x=>({...x,published:true}));renderDeployments();heading.textContent=group.name;revision.textContent="Current revision: "+group.revision;interval.value=group.settings.integrityIntervalSeconds;interval.disabled=!admin();publish.hidden=!admin();editor.hidden=false;history.replaceChildren(make("p","Loading history…","muted"));
        queueCount.value=group.settings.eventQueue?.maxEvents??10000;queueBytes.value=group.settings.eventQueue?.maxPayloadMiB??128;queueCount.disabled=!admin();queueBytes.disabled=!admin();
        for(const [key,input] of Object.entries(forensicControls)){const value=group.settings.forensics?.[key]??({preserveActorOnAlert:true,preservationThreshold:"alert",maximumActorMiB:256,evidenceStoreMiB:1024,cacheEntries:256}[key]);if(input.type==="checkbox")input.checked=value;else input.value=value;input.disabled=!admin();}
        const syslog=group.settings.syslog;syslogMode.value=syslog==null?"local":syslog.enabled?"enabled":"disabled";syslogMode.disabled=!admin();for(const [key,input] of Object.entries(syslogControls)){const value=syslog?.[key]??({host:"",port:514,transport:"TCP",format:"RFC3164",octetCounting:false,facility:16,severity:4}[key]);if(input.type==="checkbox")input.checked=value;else input.value=value;}renderSyslog();allowlist=(group.settings.allowlist||[]).map(x=>({...x}));renderAllowlist();
        const automatic=group.settings.automaticResponse||{enabled:false,onRead:false,onWrite:true,onDelete:true,onPermissionChange:false,maxStopsPerMinute:3};for(const [key,input] of Object.entries(automaticControls))input.checked=automatic[key];automaticLimit.value=automatic.maxStopsPerMinute;automaticPassword.value="";automaticCode.value="";renderAutomatic();
        const revisions=await api(`/api/v1/console/groups/${group.id}/history`);if(epoch!==generation)return;history.replaceChildren(make("h3","Published revisions"));
        if(!revisions.length)history.append(make("p","No revisions published; using the default policy.","muted"));
        for(const item of revisions){const row=make("p",`Revision ${item.revision} · ${item.settings.integrityIntervalSeconds}s · ${time(item.createdUtc)}`);history.append(row);}
    }
    function renderAssignments(){
        assignments.replaceChildren(make("h3","Sensor assignments"),helpDetails("Policy receipt","Acknowledged means the sensor reports loading the policy. Check Sensors for monitoring status."));
        const wrap=make("div",null,"table-wrap"),table=make("table"),head=make("thead"),hr=make("tr"),body=make("tbody");
        for(const title of ["Endpoint","Group","Policy receipt","Last receipt"]){const th=make("th",title);th.scope="col";hr.append(th);}head.append(hr);
        for(const state of statuses){const endpoint=endpoints.find(x=>x.endpointId===state.endpointId);const row=make("tr");cell(row,endpoint?.machineName??state.endpointId);
            const control=make("select");control.setAttribute("aria-label","Group for "+(endpoint?.machineName??state.endpointId));const none=make("option","Unassigned");none.value="";control.append(none);
            for(const group of groups){const option=make("option",group.name);option.value=group.id;control.append(option);}control.value=state.groupId??"";control.disabled=!admin();
            const groupCell=cell(row,"");groupCell.append(control);
            if(admin()){const save=make("button","Assign","secondary");save.addEventListener("click",()=>guarded(save,async()=>{await api(`/api/v1/console/endpoints/${state.endpointId}/group`,{groupId:control.value||null,expectedGroupId:state.groupId});await load();notice.textContent="Group assigned. Waiting for synchronization.";},notice.id));groupCell.append(save);}
            const acknowledged=state.appliedRevision!==null && state.appliedRevision===state.desiredRevision;
            cell(row,acknowledged?`Acknowledged revision ${state.desiredRevision}`:`Pending revision ${state.desiredRevision}`);cell(row,state.reportedUtc?time(state.reportedUtc):"Not received");body.append(row);
        }
        table.append(head,body);wrap.append(table);assignments.append(wrap);
    }
    createForm.addEventListener("submit",event=>{event.preventDefault();guarded(create,async()=>{await api("/api/v1/console/groups",{name:nameInput.value.trim()});createForm.reset();await load();notice.textContent="Group created.";},notice.id);});
    policyForm.addEventListener("submit",event=>{
        event.preventDefault();if(!selected)return;const group=selected;const seconds=Number(interval.value);
        const plan=deployments.map(({id,folderAlias,fileName,fileType,callbackTokenId})=>({id,folderAlias,fileName,fileType,callbackTokenId:callbackTokenId||null}));
        const syslog=syslogMode.value==="local"?null:{enabled:syslogMode.value==="enabled",...Object.fromEntries(Object.entries(syslogControls).map(([key,input])=>[key,input.type==="checkbox"?input.checked:input.type==="number"?Number(input.value):input.value]))};
        const automaticResponse={...Object.fromEntries(Object.entries(automaticControls).map(([key,input])=>[key,input.checked])),maxStopsPerMinute:Number(automaticLimit.value)};
        if(automaticResponse.enabled&&!group.settings.automaticResponse?.enabled&&!confirm("Enable automatic process stopping for this group? Applications can lose unsaved work. Each endpoint must also approve this locally."))return;
        guarded(publish,async()=>{
            try{await api(`/api/v1/console/groups/${group.id}/policy`,{expectedRevision:group.revision,administratorPassword:automaticResponse.enabled?automaticPassword.value:null,...factor(automaticCode.value),settings:{...group.settings,integrityIntervalSeconds:seconds,deployments:plan,syslog,allowlist:allowlist.map(x=>({...x})),automaticResponse,forensics:Object.fromEntries(Object.entries(forensicControls).map(([key,input])=>[key,input.type==="checkbox"?input.checked:input.type==="number"?Number(input.value):input.value])),eventQueue:{maxEvents:Number(queueCount.value),maxPayloadMiB:Number(queueBytes.value)}}});}
            finally{automaticPassword.value="";automaticCode.value="";}
            await load();notice.textContent="Policy published. Waiting for endpoint confirmation.";
        },notice.id);
    });
    nav.addEventListener("click",()=>guarded(nav,async()=>{await view("policies");$("page-title").textContent="Policies";await load();},notice.id));
    refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));document.addEventListener("session-cleared",clear);
    document.addEventListener("view-changed",()=>{automaticPassword.value="";automaticCode.value="";});
    for(const button of document.querySelectorAll("nav button"))if(button!==nav)button.addEventListener("click",()=>{generation++;});
})();
