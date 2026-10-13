"use strict";
(() => {
    const element=(tag,text,className)=>{const node=document.createElement(tag);if(text)node.textContent=text;if(className)node.className=className;return node;};
    const administrator=()=>account?.roles?.includes("Administrator");
    let enrollment=null,expiryTimer=null,selectedEndpoint=null,displayGeneration=0;
    const panel=element("section",null,"endpoint-admin");panel.hidden=true;
    const title=element("h2","Endpoint access");
    const actions=element("div",null,"downloads");
    const issue=element("button","Create enrollment code"),auditButton=element("button","Activity log","secondary");
    actions.append(issue,auditButton);
    const status=element("p");status.id="endpoint-admin-status";status.setAttribute("role","status");
    const codePanel=element("div",null,"enrollment-code");codePanel.hidden=true;
    const codeLabel=element("label","Single-use enrollment code");
    const code=element("textarea");code.readOnly=true;code.rows=3;code.spellcheck=false;codeLabel.append(code);
    const expires=element("p",null,"muted");
    const instructions=helpDetails("Enrollment instructions","Run the endpoint agent with --enroll --server and this console’s HTTPS address. Paste the code at the prompt; never include it in command arguments.");
    const warning=element("p","Keep this code private. Hide does not revoke it.","muted");
    const cancelCode=element("button","Invalidate unused code","secondary"),hideCode=element("button","Hide code","secondary");
    const codeActions=element("div",null,"downloads");codeActions.append(cancelCode,hideCode);
    codePanel.append(codeLabel,expires,instructions,warning,codeActions);
    const auditPanel=element("section");auditPanel.hidden=true;
    panel.append(title,actions,status,codePanel,auditPanel);$("fleet").prepend(panel);

    function forgetCode(){displayGeneration++;enrollment=null;code.value="";expires.textContent="";codePanel.hidden=true;clearTimeout(expiryTimer);expiryTimer=null;issue.disabled=false;}
    function showCode(result){
        forgetCode();enrollment=result;code.value=result.code;codePanel.hidden=false;
        expires.textContent="Expires "+time(result.expiresUtc)+" · one endpoint only";issue.disabled=true;
        expiryTimer=setTimeout(()=>{forgetCode();status.textContent="Enrollment code expired.";},Math.max(0,new Date(result.expiresUtc).getTime()-Date.now()));
    }
    issue.addEventListener("click",()=>guarded(issue,async()=>{const generation=displayGeneration;const result=await api("/api/v1/console/enrollment-codes",{});if(generation===displayGeneration)showCode(result);},status.id).finally(()=>{issue.disabled=!!enrollment;}));
    hideCode.addEventListener("click",()=>{forgetCode();status.textContent="Code hidden. It remains valid until used, invalidated, or expired.";});
    cancelCode.addEventListener("click",()=>guarded(cancelCode,async()=>{
        if(!enrollment)return;
        const cancelledCode=enrollment.code;await api("/api/v1/console/enrollment-codes/cancel",{code:cancelledCode});if(enrollment?.code===cancelledCode)forgetCode();
        status.textContent="Unused code invalidated. An already enrolled endpoint is unaffected.";
    },status.id));
    auditButton.addEventListener("click",()=>guarded(auditButton,async()=>{
        const entries=await api("/api/v1/console/management-audit");auditPanel.replaceChildren(element("h3","Recent management activity"),element("p","Latest 100 entries","muted"));
        const wrap=element("div",null,"table-wrap"),table=element("table"),head=element("thead"),headRow=element("tr"),body=element("tbody");
        for(const label of ["Time","Action","Context"]){const th=element("th",label);th.scope="col";headRow.append(th);}head.append(headRow);
        for(const entry of entries){const row=element("tr");cell(row,time(entry.timeUtc));cell(row,entry.action);cell(row,entry.subject);body.append(row);}
        table.append(head,body);wrap.append(table);auditPanel.append(wrap);if(!entries.length)auditPanel.append(element("p","No management activity yet.","muted"));auditPanel.hidden=false;
    },status.id));

    const dialog=element("dialog",null,"revoke-dialog");dialog.setAttribute("aria-labelledby","revoke-heading");
    const heading=element("h2","Revoke endpoint access?");heading.id="revoke-heading";
    const target=element("p"),impact=element("p","This blocks future management requests. It does not stop local monitoring, uninstall the agent, or delete collected events.","muted");
    const form=element("form"),confirmationLabel=element("label","Type the endpoint name to confirm"),confirmation=element("input");confirmation.autocomplete="off";confirmation.required=true;confirmationLabel.append(confirmation);
    const buttons=element("div",null,"downloads"),confirm=element("button","Revoke access","danger"),cancel=element("button","Cancel","secondary");cancel.type="button";
    const error=element("p",null,"error");error.id="revoke-error";error.setAttribute("role","alert");
    buttons.append(confirm,cancel);form.append(confirmationLabel,buttons,error);dialog.append(heading,target,impact,form);document.body.append(dialog);
    const close=()=>{dialog.close();selectedEndpoint=null;form.reset();target.textContent="";error.textContent="";};
    cancel.addEventListener("click",close);dialog.addEventListener("cancel",event=>{event.preventDefault();close();});
    form.addEventListener("submit",event=>{
        event.preventDefault();if(!selectedEndpoint || confirmation.value!==selectedEndpoint.machineName){error.textContent="Enter the endpoint name exactly as shown.";return;}
        const endpoint=selectedEndpoint;guarded(confirm,async()=>{
            await api(`/api/v1/console/endpoints/${encodeURIComponent(endpoint.endpointId)}/revoke`,{});
            close();await loadFleet();status.textContent="Endpoint access revoked. Local monitoring is unchanged.";
        },error.id);
    });
    document.addEventListener("fleet-rendered",()=>{
        panel.hidden=!administrator();if(!administrator())return;
        for(const row of $("fleet-rows").rows){const endpoint=fleet.find(item=>item.endpointId===row.dataset.endpointId);if(!endpoint || endpoint.revoked)continue;
            const button=element("button","Revoke access","secondary revoke-access");button.setAttribute("aria-label","Revoke access for "+endpoint.machineName);
            button.addEventListener("click",()=>{selectedEndpoint=endpoint;target.textContent=endpoint.machineName+" · "+endpoint.endpointId;form.reset();error.textContent="";dialog.showModal();confirmation.focus();});row.lastElementChild.append(button);
        }
    });
    document.addEventListener("session-cleared",()=>{forgetCode();close();auditPanel.replaceChildren();auditPanel.hidden=true;status.textContent="";panel.hidden=true;});
    for(const nav of document.querySelectorAll("nav button"))nav.addEventListener("click",()=>{if(nav.dataset.view!=="fleet"){forgetCode();close();}});
    window.addEventListener("pagehide",()=>{forgetCode();close();});
})();
