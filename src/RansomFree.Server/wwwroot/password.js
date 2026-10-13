"use strict";
(() => {
    const card=document.createElement("section");card.className="security-card password-card";
    const heading=document.createElement("h3");heading.textContent="Change password";
    const note=document.createElement("p");note.className="muted";note.textContent="Loading password requirements…";
    const form=document.createElement("form");
    function input(labelText,name,autocomplete){const label=document.createElement("label");label.textContent=labelText;const field=document.createElement("input");field.name=name;field.type="password";field.autocomplete=autocomplete;field.required=true;field.maxLength=256;label.append(field);form.append(label);return field;}
    input("Current password","password","current-password");
    const next=input("New password","newPassword","new-password");next.minLength=14;
    next.disabled=true;
    fetch("/password-policy.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw new Error();return r.json();}).then(p=>{
        next.minLength=p.minimumLength;next.maxLength=p.maximumLength;next.disabled=false;
        const rules=[[p.requireUppercase,"uppercase"],[p.requireLowercase,"lowercase"],[p.requireDigit,"number"],[p.requireSymbol,"symbol"]].filter(x=>x[0]).map(x=>x[1]);
        note.textContent=`Use ${p.minimumLength}–${p.maximumLength} characters${rules.length?" with "+rules.join(", "):""}. Changing your password signs out all sessions.`;
    }).catch(()=>{note.textContent="Password requirements unavailable. Reload to retry.";});
    input("Confirm new password","confirmPassword","new-password");
    const factorLabel=document.createElement("label");factorLabel.textContent="Authenticator or recovery code (if MFA is enabled)";
    const factorInput=document.createElement("input");factorInput.name="factor";factorInput.autocomplete="one-time-code";factorInput.maxLength=32;factorLabel.append(factorInput);form.append(factorLabel);
    const button=document.createElement("button");button.textContent="Change password";form.append(button);
    const error=document.createElement("p");error.id="password-error";error.className="error";error.setAttribute("role","alert");
    card.append(heading,note,form,error);$("security").append(card);
    form.addEventListener("submit",event=>{
        event.preventDefault();const values=new FormData(form);
        if(account?.authentication!=="Local"){error.textContent="Your password is managed by your identity provider. Use your organization’s password-change process.";return;}
        if(values.get("newPassword")!==values.get("confirmPassword")){error.textContent="New passwords do not match.";return;}
        if(values.get("password")===values.get("newPassword")){error.textContent="Choose a different password.";return;}
        guarded(button,async()=>{
            await api("/api/v1/auth/password",{password:values.get("password"),newPassword:values.get("newPassword"),...factor(values.get("factor"))});
            showLogin();$("login-error").textContent="Password changed. Sign in with your new password.";
        },error.id);
    });
    function clear(){form.reset();error.textContent="";}
    document.addEventListener("session-cleared",clear);
    document.addEventListener("security-rendered",()=>{card.hidden=account?.authentication!=="Local";});
    window.addEventListener("pagehide",clear);
    for(const nav of document.querySelectorAll("nav button"))nav.addEventListener("click",()=>{if(nav.dataset.view!=="security")clear();});
})();
