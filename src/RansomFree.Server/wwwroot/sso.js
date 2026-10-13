"use strict";
(()=>{
    const make=(tag,text)=>{const node=document.createElement(tag);if(text)node.textContent=text;return node;};
    const login=make("section"),security=make("section"),notice=make("div");notice.id="sso-notice";notice.setAttribute("role","status");login.append(make("h3","Single sign-on"));$("login").querySelector("section").append(login);$("security").append(security);
    security.append(make("h3","Verify identity"),make("p","Sign in again to approve account changes. MFA may also be required."));
    const providers=make("div"),securityProviders=make("div");login.append(providers,notice);security.append(securityProviders);security.hidden=true;
    async function postNavigation(path){
        const response=await fetch("/api/v1/auth/csrf",{credentials:"same-origin"});if(!response.ok)throw new Error("Cannot start sign-in.");const token=(await response.json()).token;
        const form=make("form"),field=make("input");form.method="post";form.action=path;field.type="hidden";field.name="__RequestVerificationToken";field.value=token;form.append(field);document.body.append(form);form.submit();
    }
    async function begin(id){await postNavigation("/api/v1/auth/sso/start/"+encodeURIComponent(id));}
    const providerLogout=make("button","Sign out of identity provider");providerLogout.hidden=true;providerLogout.type="button";security.append(providerLogout);let logoutEpoch=0;
    providerLogout.addEventListener("click",()=>guarded(providerLogout,async()=>{if(confirm("End this app session and request provider sign-out? This may affect other applications using that provider."))await postNavigation("/api/v1/auth/sso/logout");},"mfa-error"));
    fetch("/api/v1/auth/sso/providers",{credentials:"same-origin"}).then(r=>r.ok?r.json():[]).then(items=>{
        login.hidden=items.length===0;for(const item of items)for(const target of [providers,securityProviders]){const button=make("button",item.name);button.type="button";button.addEventListener("click",()=>guarded(button,()=>begin(item.id),target===providers?notice.id:"mfa-error"));target.append(button);}
    }).catch(()=>{notice.textContent="SSO provider list unavailable.";});
    const finish=make("form"),factorLabel=make("label","App authenticator or recovery code (if enabled)"),factorInput=make("input"),complete=make("button","Complete SSO sign-in");factorInput.maxLength=32;factorInput.autocomplete="one-time-code";factorLabel.append(factorInput);finish.append(factorLabel,complete);login.append(finish);
    finish.hidden=new URLSearchParams(location.search).get("sso")!=="pending";
    if(new URLSearchParams(location.search).get("sso")==="failed")notice.textContent="SSO sign-in could not complete. Check provider configuration or try again.";
    if(new URLSearchParams(location.search).get("sso")==="signedout")notice.textContent="Signed out. Other application sessions may remain active.";
    if(new URLSearchParams(location.search).get("sso")==="logout-unavailable")notice.textContent="App session ended. Provider sign-out could not be started.";
    finish.addEventListener("submit",event=>{event.preventDefault();guarded(complete,async()=>{
        const pending=await api("/api/v1/auth/sso/pending");
        if(!pending.linked){notice.textContent="Contact your administrator to enable sign-in.";notice.append(helpDetails("Diagnostics",`Provider: ${pending.provider}; subject: ${pending.subject}. No account was created.`));return;}
        if(pending.mfaRequired&&!factorInput.value){notice.textContent="Enter your app authenticator or recovery code.";factorInput.focus();return;}
        await api("/api/v1/auth/sso/complete",factor(factorInput.value));finish.reset();finish.hidden=true;history.replaceState(null,"","/");await enter();
    },notice.id);});
    document.addEventListener("security-rendered",async()=>{const epoch=++logoutEpoch;security.hidden=account?.authentication!=="SSO";providerLogout.hidden=true;if(security.hidden)return;try{const option=await api("/api/v1/auth/sso/logout-option");if(epoch===logoutEpoch)providerLogout.hidden=!option.enabled;}catch{if(epoch===logoutEpoch)providerLogout.hidden=true;}});
    document.addEventListener("session-cleared",()=>{logoutEpoch++;factorInput.value="";security.hidden=true;providerLogout.hidden=true;});
})();
