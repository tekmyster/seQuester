"use strict";
(()=>{
    const el=(tag,text)=>{const node=document.createElement(tag);if(text)node.textContent=text;return node;};
    const nav=el("button","Canary tokens");nav.dataset.view="callbacks";document.querySelector("nav").append(nav);
    const page=el("section");page.id="callbacks";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    const status=el("p"),notice=el("p"),form=el("form"),nameLabel=el("label","Token name"),name=el("input"),typeLabel=el("label","Type"),type=el("select"),create=el("button","Create token"),refresh=el("button","Refresh");
    notice.id="callback-notice";notice.setAttribute("role","status");name.required=true;name.maxLength=160;nameLabel.append(name);typeLabel.append(type);form.append(nameLabel,typeLabel,create);form.className="report-controls";
    const destinationLabel=el("label","Destination URL (HTTPS)"),destination=el("input");destination.type="url";destination.maxLength=2048;destinationLabel.append(destination);form.insertBefore(destinationLabel,create);
    const locationLabel=el("label","Location"),location=el("input"),descriptionLabel=el("label","Description"),description=el("textarea"),noteLabel=el("label","Note"),note=el("textarea"),emailLabel=el("label","Email alerts"),email=el("input"),cancelEdit=el("button","Cancel edit");
    location.maxLength=256;location.placeholder="Site / server / folder or business context";description.maxLength=1000;description.rows=3;note.maxLength=2000;note.rows=3;email.type="checkbox";email.checked=true;emailLabel.className="notification-check";emailLabel.append(email);
    locationLabel.append(location);descriptionLabel.append(description);noteLabel.append(note);for(const item of [locationLabel,descriptionLabel,noteLabel,emailLabel])form.insertBefore(item,create);
    cancelEdit.type="button";cancelEdit.className="secondary";cancelEdit.hidden=true;form.append(cancelEdit);
    let editing=null,tokenIndex=new Map();
    function resetEditor(){editing=null;form.reset();email.checked=true;name.disabled=false;type.disabled=false;create.textContent="Create token";cancelEdit.hidden=true;destinationMode();}
    cancelEdit.addEventListener("click",resetEditor);
    function destinationMode(){const needed=["fast-redirect","slow-redirect","js-clone","css-clone"].includes(type.value);destinationLabel.hidden=!needed;destination.required=needed;destination.disabled=!needed;}type.addEventListener("change",destinationMode);
    const inventory=el("section"),hits=el("section"),next=el("button","Next callbacks"),catalog=el("details");catalog.append(el("summary","Supported token types"));
    page.append(el("h2","Canary tokens"),status,helpDetails("About token alerts","Tokens report network activity, not verified user/process identity. Configure email in Notifications. Location and context are administrator-entered, not verified file inventory."),notice,form,refresh,inventory,hits,next,catalog);
    const delivery=el("p");delivery.setAttribute("role","status");status.after(delivery);
    let generation=0,cursor=0;
    const admin=()=>account?.roles.includes("Administrator");
    async function downloadToken(token,epoch){
        const blob=await api(`/api/v1/console/callbacks/tokens/${token.id}/download`,{},true);if(epoch!==generation)return;
        const extension={docx:"docx",xlsx:"xlsx",pdf:"pdf",svg:"svg",qr:"png","js-clone":"js","css-clone":"css",mcp:"json","windows-folder":"zip",kubeconfig:"yaml",mysql:"sql"}[token.type]||"txt";
        const url=URL.createObjectURL(blob),link=el("a");link.href=url;link.download=`canary-${token.id}.${extension}`;
        document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
    async function load(){
        const epoch=++generation;const [configuration,tokens,forwarding]=await Promise.all([api("/api/v1/console/callbacks/catalog"),api("/api/v1/console/callbacks/tokens"),api("/api/v1/console/callbacks/delivery")]);if(epoch!==generation)return;
        tokenIndex=new Map(tokens.map(t=>[t.id,t]));resetEditor();
        delivery.replaceChildren(document.createTextNode("Syslog: "+deliveryText(forwarding.message)),helpDetails("Delivery diagnostics",`${forwarding.message} · Last sent sequence: ${forwarding.lastSentSequence}. Collector receipt is unconfirmed.`));
        status.textContent=configuration.enabled?"Receiver configured":"Configure a receiver to create tokens";form.hidden=!admin()||!configuration.enabled;type.replaceChildren();
        catalog.replaceChildren(el("summary","Supported token types"));
        for(const mechanism of configuration.mechanisms){catalog.append(el("p",`${mechanism.name} — ${mechanism.state}. Trigger: ${mechanism.trigger}.`));if(mechanism.state.startsWith("Implemented")&&(!["dns","windows-folder","mysql","log4shell"].includes(mechanism.id)||configuration.dnsEnabled)&&(mechanism.id!=="email"||configuration.emailEnabled)){const option=el("option",mechanism.name);option.value=mechanism.id;type.append(option);}}destinationMode();
        inventory.replaceChildren(el("h3","Token inventory"),el("p","Latest 1,000 tokens."),helpDetails("Download safety","Downloaded artifacts contain active tripwires. Previewing or fetching them can trigger an alert."));
        const table=el("table"),head=el("thead"),header=el("tr"),body=el("tbody");for(const title of ["Name / context","Type","Created","State","Email","Actions"]){const th=el("th",title);th.scope="col";header.append(th);}head.append(header);
        for(const token of tokens){
            const row=el("tr"),context=cell(row,token.name);if(token.location)context.append(el("p","Location: "+token.location));if(token.description)context.append(el("p",token.description));if(token.note)context.append(el("p","Note: "+token.note));
            cell(row,token.type);cell(row,time(token.created));cell(row,token.revoked?"Revoked":"Enabled");cell(row,token.emailAlerts?"On":"Off");const actions=cell(row,"");
            if(admin()){
                const edit=el("button","Edit details");edit.className="secondary";edit.addEventListener("click",()=>{editing=token.id;name.value=token.name;name.disabled=true;type.value=token.type;type.disabled=true;destination.value=token.destination||"";destination.disabled=true;destination.required=false;destinationLabel.hidden=true;location.value=token.location||"";description.value=token.description||"";note.value=token.note||"";email.checked=!!token.emailAlerts;create.textContent="Save details";cancelEdit.hidden=false;location.focus();form.scrollIntoView({block:"nearest"});});actions.append(edit);
            }
            if(admin()&&!token.revoked){
                const download=el("button","Download"),revoke=el("button","Revoke");download.addEventListener("click",()=>guarded(download,()=>downloadToken(token,epoch),notice.id));
                revoke.addEventListener("click",()=>guarded(revoke,async()=>{if(!confirm(`Revoke ${token.name}? Existing documents remain, but future callbacks will no longer be recorded.`))return;await api(`/api/v1/console/callbacks/tokens/${token.id}/revoke`,{});await load();},notice.id));actions.append(download,revoke);
            }
            body.append(row);
        }
        table.append(head,body);inventory.append(table);cursor=0;await loadHits(epoch);
    }
    async function loadHits(epoch=generation){const rows=await api("/api/v1/console/callbacks/hits?after="+cursor);if(epoch!==generation)return;hits.replaceChildren(el("h3","Canary token activated (application/resource access)"),helpDetails("Activity details","Repeated token/source/transport activity is grouped for 60 seconds. A callback proves application or resource access, not a filesystem copy. Context reflects administrator-entered details. User/process identity requires endpoint evidence."));const table=el("table"),head=el("thead"),header=el("tr"),body=el("tbody");for(const title of ["Received","Canary / location","Transport","Source","Detail","Sequence"]){const th=el("th",title);th.scope="col";header.append(th);}head.append(header);for(const hit of rows){const row=el("tr"),token=tokenIndex.get(hit.tokenId);cell(row,time(hit.received));cell(row,token?token.name+(token.location?" — "+token.location:""):hit.tokenId);cell(row,hit.transport);cell(row,hit.sourceAddress);cell(row,hit.detail);cell(row,String(hit.sequence));body.append(row);}table.append(head,body);hits.append(table);if(rows.length)cursor=rows[rows.length-1].sequence;next.hidden=rows.length<100;}
    form.addEventListener("submit",event=>{event.preventDefault();guarded(create,async()=>{const details={location:location.value.trim(),description:description.value.trim(),note:note.value.trim(),emailAlerts:email.checked};const updating=editing;if(updating)await api("/api/v1/console/callbacks/tokens/"+updating+"/details",details);else await api("/api/v1/console/callbacks/tokens",{name:name.value.trim(),type:type.value,destination:destination.disabled?null:destination.value.trim(),...details});resetEditor();await load();notice.textContent=updating?"Details saved.":"Token created. Download it or add it to a deployment policy.";},notice.id);});
    nav.addEventListener("click",()=>guarded(nav,async()=>{await view("callbacks");if(page.hidden)return;$("page-title").textContent="Canary tokens";await load();},notice.id));refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));next.addEventListener("click",()=>guarded(next,()=>loadHits(),notice.id));
    document.addEventListener("session-cleared",()=>{generation++;cursor=0;tokenIndex.clear();inventory.replaceChildren();hits.replaceChildren();delivery.textContent="";status.textContent="";notice.textContent="";resetEditor();});document.addEventListener("view-changed",event=>{if(event.detail!=="callbacks"){generation++;resetEditor();}});
})();
