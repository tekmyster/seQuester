"use strict";
(()=>{
    const make=(tag,text)=>{const node=document.createElement(tag);if(text)node.textContent=text;return node;};
    const nav=make("button","Responses");nav.dataset.view="responses";document.querySelector("nav").append(nav);
    const page=make("section");page.id="responses";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    const notice=make("p"),refresh=make("button","Refresh"),list=make("section");notice.id="response-notice";notice.setAttribute("role","status");
    page.append(make("h2","Endpoint responses"),make("p","Manage process-stop requests."),helpDetails("Response requirements","Endpoints must allow remote process stopping. Requests require fresh process evidence. A missing receipt means the outcome is unconfirmed."),notice,refresh,list);
    const dialog=make("dialog"),form=make("form"),reason=make("input"),password=make("input"),code=make("input"),submit=make("button","Request process stop"),cancel=make("button","Cancel"),context=make("p"),error=make("p");error.id="response-dialog-error";error.setAttribute("role","alert");
    function field(title,input){const label=make("label",title);label.append(input);return label;}
    reason.required=true;reason.maxLength=500;password.type="password";password.maxLength=256;password.autocomplete="current-password";code.maxLength=32;code.autocomplete="one-time-code";cancel.type="button";
    const passwordLabel=field("Administrator password",password);form.append(make("h2","Confirm process response"),context,make("p","Stopping this application can lose unsaved work."),field("Reason",reason),passwordLabel,field("App authenticator or recovery code (if enabled)",code),error,submit,cancel);dialog.append(form);document.body.append(dialog);
    let selected=null,generation=0,requestId=null,submitting=false;
    const admin=()=>account?.roles.includes("Administrator");
    function clear(){generation++;selected=null;requestId=null;form.reset();error.textContent="";if(dialog.open)dialog.close();}
    async function load(){const epoch=++generation,items=await api("/api/v1/console/responses");if(epoch!==generation)return;list.replaceChildren(make("h3","Latest 100 requests"));for(const item of items){const row=make("article");row.append(make("h3",item.status),make("p",`Endpoint ${item.endpointId} · ${time(item.command.createdUtc)}`),make("p",item.command.reason));if(!item.result)row.append(make("p","Outcome unconfirmed"));row.append(helpDetails("Diagnostics",`Request ${item.command.id}\n${item.result||"No final receipt"}`));if(admin()&&item.status==="Pending"){const button=make("button","Cancel pending request");button.addEventListener("click",()=>guarded(button,async()=>{await api(`/api/v1/console/responses/${item.command.id}/cancel`,{});await load();},notice.id));row.append(button);}list.append(row);}}
    document.addEventListener("alerts-rendered",()=>{
        if(!admin())return;for(const row of $("alert-rows").rows){const button=make("button","Request process stop…");button.disabled=row.dataset.responseCandidate!=="true"||!Number.isSafeInteger(Number(row.dataset.eventSequence))||!["Windows audit 4663","Linux fanotify","macOS Endpoint Security"].some(source=>row.dataset.eventSource===source);button.addEventListener("click",()=>{
            clear();selected=Number(row.dataset.eventSequence);requestId=crypto.randomUUID().replaceAll("-","");context.textContent=`Event ${selected}: ${row.dataset.eventContext||row.cells[1].textContent}`;
            passwordLabel.hidden=account?.authentication==="SSO";password.required=account?.authentication!=="SSO";dialog.showModal();reason.focus();
        });(row.querySelector("[data-event-evidence]")??row.lastElementChild).append(button);}
    });
    form.addEventListener("submit",event=>{event.preventDefault();if(!selected||!requestId||submitting)return;guarded(submit,async()=>{
        submitting=true;cancel.disabled=true;
        try{await api("/api/v1/console/responses",{requestId,eventSequence:selected,reason:reason.value.trim(),administratorPassword:password.value,...factor(code.value)});
            clear();await view("responses");$("page-title").textContent="Responses";await load();notice.textContent="Request sent. Waiting for endpoint confirmation.";
        }finally{password.value="";code.value="";submitting=false;cancel.disabled=false;}
    },error.id);});
    cancel.addEventListener("click",()=>{if(!submitting)clear();});dialog.addEventListener("cancel",event=>{if(submitting)event.preventDefault();else clear();});dialog.addEventListener("close",()=>{password.value="";code.value="";});
    nav.addEventListener("click",()=>guarded(nav,async()=>{await view("responses");if(page.hidden)return;$("page-title").textContent="Responses";await load();},notice.id));refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));
    document.addEventListener("session-cleared",()=>{clear();list.replaceChildren();});document.addEventListener("view-changed",()=>{generation++;if(dialog.open)clear();});
    document.addEventListener("history-reset",()=>{if(!submitting)clear();});
})();
