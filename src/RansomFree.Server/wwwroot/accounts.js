"use strict";
(() => {
    const make=(tag,text,cls)=>{const e=document.createElement(tag);if(text)e.textContent=text;if(cls)e.className=cls;return e;};
    const label=(text,input)=>{const e=make("label",text);e.append(input);return e;};
    const field=(type,max=256)=>{const e=make("input");e.type=type;e.maxLength=max;return e;};
    const select=values=>{const e=make("select");for(const value of values){const o=make("option",value);o.value=value;e.append(o);}return e;};
    let chosen=null,epoch=0,secretTimer=null,securityPolicy=null;
    const nav=make("button","Accounts");nav.dataset.view="accounts";nav.hidden=true;document.querySelector("nav").append(nav);
    const page=make("section");page.id="accounts";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    page.append(make("h2","Account access"),helpDetails("Account verification","Changes require your administrator password or a recent SSO sign-in, plus MFA when enabled."));
    const notice=make("p");notice.id="account-notice";notice.setAttribute("role","status");const refresh=make("button","Refresh","secondary");page.append(notice,refresh);
    const proof=make("section",null,"security-card password-card"),adminPassword=field("password"),factorInput=field("text",32);adminPassword.autocomplete="current-password";factorInput.autocomplete="one-time-code";
    proof.append(make("h3","Administrator verification"),label("Your password",adminPassword),label("Authenticator or recovery code (if enabled)",factorInput));page.append(proof);
    const create=make("form",null,"security-card password-card"),username=field("text",100),type=select(["Local","Directory","SSO"]),role=select(["Reader","Operator","Administrator"]),password=field("password"),principal=field("text",254),objectId=field("text",36),createButton=make("button","Create account");
    username.required=true;username.autocomplete="off";password.autocomplete="new-password";password.minLength=14;password.required=true;
    password.disabled=true;
    const passwordPolicyNote=make("p","Loading password requirements…","muted");
    fetch("/password-policy.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw new Error();return r.json();}).then(p=>{
        password.minLength=p.minimumLength;password.maxLength=p.maximumLength;password.disabled=false;
        const rules=[[p.requireUppercase,"uppercase"],[p.requireLowercase,"lowercase"],[p.requireDigit,"number"],[p.requireSymbol,"symbol"]].filter(x=>x[0]).map(x=>x[1]);
        passwordPolicyNote.textContent=`Local passwords: ${p.minimumLength}–${p.maximumLength} characters${rules.length?"; "+rules.join(", "):""}.`;
    }).catch(()=>{passwordPolicyNote.textContent="Password requirements unavailable. Reload to retry.";});
    create.append(passwordPolicyNote);
    const passwordLabel=label("New account password",password),directoryFields=make("div");directoryFields.hidden=true;
    directoryFields.append(label("Directory UPN",principal),label("Active Directory objectGUID",objectId),helpDetails("Find the directory identifier","Use the account’s Active Directory objectGUID, not its email address or SID. Directory passwords are not stored here."));
    create.append(make("h3","Create account"),label("Sign-in username",username),label("Authentication",type),label("Role",role),passwordLabel,directoryFields,make("p","New users must change this password within 24 hours.","muted"),createButton);page.append(create);
    const ssoFields=make("div"),ssoProvider=select([]),subject=field("text",256);ssoFields.hidden=true;ssoFields.append(label("SSO provider",ssoProvider),label("Subject ID (sub)",subject),helpDetails("Find the SSO identifier","Use the subject displayed after the person signs in through seQuester. Email addresses are not linked automatically."));create.insertBefore(ssoFields,createButton);
    const securityForm=make("form",null,"security-card password-card"),mfaMode=select(["Optional","Administrators","Everyone"]),securitySave=make("button","Save MFA policy");securityForm.append(make("h3","Organization MFA"),label("Require app MFA for",mfaMode),make("p","Enable your own MFA first. Affected users must set up MFA to continue.","muted"),securitySave);page.append(securityForm);
    securityForm.addEventListener("submit",event=>{event.preventDefault();if(!securityPolicy)return;guarded(securitySave,async()=>{await write("/api/v1/console/security-policy",{expectedVersion:securityPolicy.version,mfaMode:mfaMode.value});await load();notice.textContent="MFA policy saved.";},notice.id);});
    const tableContainer=make("section",null,"policy-assignments");page.append(tableContainer);
    const editor=make("form",null,"security-card password-card"),editTitle=make("h3"),editRole=select(["Reader","Operator","Administrator"]),access=select(["Enabled","Disabled"]),save=make("button","Save access"),cancel=make("button","Cancel","secondary");cancel.type="button";editor.hidden=true;
    editor.append(editTitle,label("Role",editRole),label("Access",access),make("p","Changes sign this user out. Another administrator must change your access.","muted"),save,cancel);page.append(editor);
    const recover=make("form",null,"security-card password-card"),resetPassword=field("checkbox"),resetMfa=field("checkbox"),reason=field("text",500),confirmation=field("text",100),recoverButton=make("button","Recover account","danger");recover.hidden=true;reason.required=true;confirmation.required=true;
    recover.append(make("h3","Account recovery"),make("p","Invalidates existing sessions. MFA reset requires fresh authenticator setup. Disabled accounts stay disabled. Directory passwords cannot be reset here.","muted"),label("Reset local password",resetPassword),label("Reset MFA and old recovery codes",resetMfa),label("Reason (do not include credentials)",reason),label("Type the account username to confirm",confirmation),recoverButton);page.append(recover);
    const recoveryResult=make("section",null,"security-card password-card"),resultNote=make("p"),temporary=field("password"),reveal=make("button","Reveal temporary password","secondary"),dismiss=make("button","Dismiss","secondary");recoveryResult.hidden=true;temporary.readOnly=true;temporary.autocomplete="off";
    recoveryResult.append(make("h3","Recovery issued"),resultNote,label("Temporary password — share securely",temporary),reveal,dismiss);page.append(recoveryResult);
    function clearRecoveryResult(){clearTimeout(secretTimer);secretTimer=null;temporary.value="";temporary.type="password";reveal.textContent="Reveal temporary password";recoveryResult.hidden=true;resultNote.textContent="";}
    reveal.addEventListener("click",()=>{temporary.type=temporary.type==="password"?"text":"password";reveal.textContent=temporary.type==="password"?"Reveal temporary password":"Hide temporary password";});dismiss.addEventListener("click",clearRecoveryResult);
    function clearProof(){adminPassword.value="";factorInput.value="";}
    async function write(path,body){
        if(!adminPassword.value&&account?.authentication!=="SSO")throw new Error("Enter your password in Administrator verification.");
        try{return await api(path,{...body,administratorPassword:adminPassword.value,...factor(factorInput.value)});}finally{clearProof();password.value="";}
    }
    function mode(){const directory=type.value==="Directory",sso=type.value==="SSO";passwordLabel.hidden=directory||sso;password.required=!directory&&!sso;directoryFields.hidden=!directory;principal.required=directory;objectId.required=directory;ssoFields.hidden=!sso;subject.required=sso;ssoProvider.required=sso;password.value="";principal.value="";objectId.value="";subject.value="";}
    type.addEventListener("change",mode);
    async function load(){const generation=++epoch;const [accounts,providers,policy]=await Promise.all([api("/api/v1/console/accounts"),api("/api/v1/auth/sso/providers"),api("/api/v1/console/security-policy")]);if(generation!==epoch)return;chosen=null;editor.hidden=true;recover.hidden=true;clearRecoveryResult();securityPolicy=policy;mfaMode.value=policy.mfaMode;adminPassword.closest("label").hidden=account?.authentication==="SSO";ssoProvider.replaceChildren();for(const provider of providers){const option=make("option",provider.name);option.value=provider.id;ssoProvider.append(option);}
        tableContainer.replaceChildren(make("h3","Accounts"),make("p","First 500 accounts, ordered by username","muted"));const wrap=make("div",null,"table-wrap"),table=make("table"),head=make("thead"),hr=make("tr"),body=make("tbody");
        for(const title of ["Username","Authentication","Role","MFA","Access","Recovery","Action"]){const th=make("th",title);th.scope="col";hr.append(th);}head.append(hr);
        for(const item of accounts){const row=make("tr");cell(row,item.userName);cell(row,item.authentication);cell(row,item.roles.join(", "));cell(row,item.mfaEnabled?"Enabled":"Not enabled");cell(row,item.disabled?"Disabled":"Enabled");cell(row,[item.mustChangePassword?"Password change required":null,item.mustEnrollMfa?"MFA setup required":null].filter(Boolean).join("; ")||"None");const action=cell(row,"");
            if(item.userName!==account.userName){const button=make("button","Manage account","secondary");button.addEventListener("click",()=>{clearRecoveryResult();chosen=item;editTitle.textContent=item.userName;editRole.value=item.roles[0]??"Reader";access.value=item.disabled?"Disabled":"Enabled";editor.hidden=false;recover.reset();resetPassword.disabled=item.authentication!=="Local";recover.hidden=false;editRole.focus();});action.append(button);}else action.textContent="Your account";body.append(row);
        }table.append(head,body);wrap.append(table);tableContainer.append(wrap);
    }
    create.addEventListener("submit",event=>{event.preventDefault();guarded(createButton,async()=>{
        if(type.value==="SSO")await write("/api/v1/console/accounts/sso",{userName:username.value.trim(),role:role.value,provider:ssoProvider.value,subject:subject.value.trim()});
        else await write("/api/v1/console/accounts",{userName:username.value.trim(),role:role.value,newPassword:type.value==="Local"?password.value:null,directoryPrincipal:type.value==="Directory"?principal.value.trim():null,directoryObjectId:type.value==="Directory"?objectId.value.trim():null});
        create.reset();mode();await load();notice.textContent="Account created.";
    },notice.id);});
    editor.addEventListener("submit",event=>{event.preventDefault();if(!chosen)return;const target=chosen;guarded(save,async()=>{await write("/api/v1/console/accounts/"+encodeURIComponent(target.id),{concurrencyStamp:target.concurrencyStamp,role:editRole.value,disabled:access.value==="Disabled"});await load();notice.textContent="Access updated. User signed out.";},notice.id);});
    recover.addEventListener("submit",event=>{event.preventDefault();if(!chosen)return;if(confirmation.value!==chosen.userName){notice.textContent="Enter the account username exactly as shown.";return;}if(!resetPassword.checked&&!resetMfa.checked){notice.textContent="Select password reset, MFA reset, or both.";return;}const target=chosen;
        const requestEpoch=epoch;guarded(recoverButton,async()=>{const result=await write(`/api/v1/console/accounts/${encodeURIComponent(target.id)}/recover`,{concurrencyStamp:target.concurrencyStamp,resetPassword:resetPassword.checked,resetMfa:resetMfa.checked,reason:reason.value});if(epoch!==requestEpoch)return;await load();if(epoch!==requestEpoch+1||page.hidden)return;recover.reset();notice.textContent="Recovery issued. Existing sessions are invalidated; disabled accounts remain disabled.";
            if(result.temporaryPassword){temporary.value=result.temporaryPassword;recoveryResult.hidden=false;resultNote.textContent="Expires "+time(result.expiresUtc)+". The user must change it before accessing management. This display clears in two minutes; dismissing it does not invalidate the password.";secretTimer=setTimeout(clearRecoveryResult,120000);}
        },notice.id);
    });
    cancel.addEventListener("click",()=>{chosen=null;editor.hidden=true;recover.hidden=true;recover.reset();clearProof();clearRecoveryResult();});refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));
    nav.addEventListener("click",()=>guarded(nav,async()=>{await view("accounts");$("page-title").textContent="Accounts";await load();},notice.id));
    document.addEventListener("overview-rendered",()=>{nav.hidden=!account?.roles?.includes("Administrator");});
    document.addEventListener("session-cleared",()=>{epoch++;nav.hidden=true;chosen=null;clearProof();clearRecoveryResult();create.reset();mode();editor.reset();editor.hidden=true;recover.reset();recover.hidden=true;editTitle.textContent="";tableContainer.replaceChildren();notice.textContent="";});
    for(const button of document.querySelectorAll("nav button"))if(button!==nav)button.addEventListener("click",()=>{epoch++;clearProof();clearRecoveryResult();password.value="";});
    window.addEventListener("pagehide",()=>{clearProof();clearRecoveryResult();password.value="";});
})();
