"use strict";
(()=>{
    const make=(tag,text)=>{const node=document.createElement(tag);if(text)node.textContent=text;return node;};
    const nav=make("button","Notifications");nav.dataset.view="notifications";nav.hidden=true;document.querySelector("nav").append(nav);
    const page=make("section");page.id="notifications";page.className="view";page.hidden=true;document.querySelector("main").append(page);
    const notice=make("p"),refresh=make("button","Refresh status");notice.id="notification-notice";notice.setAttribute("role","status");refresh.className="secondary";
    page.append(make("h2","Notifications"),helpDetails("Alert delivery","All endpoint alerts go to management. Offline alerts are queued until acknowledged. Syslog sender settings control forwarding, not management collection."),notice,refresh);
    let generation=0,emailRevision=0,syslogRevision=0,loading=false;
    const admin=()=>account?.roles.includes("Administrator");
    function field(form,title,kind="text",max=256){
        const label=make("label",title),input=make(kind==="textarea"?"textarea":kind==="select"?"select":"input");if(kind!=="textarea"&&kind!=="select")input.type=kind;
        input.setAttribute("aria-label",title);if(max)input.maxLength=max;if(kind==="textarea")input.rows=3;if(kind==="checkbox")label.className="notification-check";label.append(input);form.append(label);return input;
    }
    function proof(form){
        const password=field(form,"Administrator password","password"),code=field(form,"Authenticator or recovery code (if enabled)");
        password.autocomplete="current-password";code.autocomplete="one-time-code";code.maxLength=32;
        return {password,code,clear(){password.value="";code.value="";},body(){return {administratorPassword:password.value,...factor(code.value)};},render(){password.closest("label").hidden=account?.authentication==="SSO";password.required=account?.authentication!=="SSO";}};
    }
    const email=make("form");email.className="notification-form";email.append(make("h3","Canary email"),make("p","Email selected canary alerts."),helpDetails("Email requirements","Enable email on each token or select service hits. A STARTTLS-capable relay and a restricted sending account or approved relay access are required."));
    const e={
        enabled:field(email,"Enable server email","checkbox"),serviceHits:field(email,"Email service hits","checkbox"),
        host:field(email,"SMTP host"),port:field(email,"SMTP port","number"),
        from:field(email,"Sender address","email",254),recipients:field(email,"Recipients (one address per line, up to 20)","textarea",5200),
        username:field(email,"SMTP username (optional)"),
        password:field(email,"SMTP password (blank to keep)","password",4096),
        clearPassword:field(email,"Clear stored SMTP password","checkbox"),
        subjectPrefix:field(email,"Subject prefix","text",80),
        minimumIntervalSeconds:field(email,"Minimum seconds between submissions","number")
    };
    e.password.autocomplete="new-password";e.host.autocomplete="off";e.port.min=1;e.port.max=65535;e.minimumIntervalSeconds.min=1;e.minimumIntervalSeconds.max=300;
    const emailStatus=make("p");emailStatus.setAttribute("role","status");email.append(emailStatus,helpDetails("Delivery behavior","First enable starts with future callbacks. Pausing retains pending alerts. Destination changes apply to unsent alerts; an in-flight send may finish. Relay acceptance does not confirm mailbox delivery."));
    const ep=proof(email),saveEmail=make("button","Save email settings"),test=make("button","Send test email");test.type="button";test.className="secondary";email.append(saveEmail,test);page.append(email);
    const syslog=make("form");syslog.className="notification-form";syslog.append(make("h3","Server syslog / Wazuh"),make("p","Forward selected alerts from the server."));
    const s={enabled:field(syslog,"Enable server syslog","checkbox"),endpointEvents:field(syslog,"Forward endpoint events","checkbox"),includeLogOnlyEvents:field(syslog,"Include whitelisted events as logs (no alert)","checkbox"),callbackHits:field(syslog,"Forward callback hits","checkbox"),serviceHits:field(syslog,"Forward service hits","checkbox"),
        host:field(syslog,"Collector host"),port:field(syslog,"Collector port","number"),transport:field(syslog,"Transport","select"),format:field(syslog,"Format","select"),octetCounting:field(syslog,"Octet-counted framing","checkbox"),facility:field(syslog,"Facility","number"),severity:field(syslog,"Severity","number")};
    for(const value of ["TLS","TCP","UDP"]){const option=make("option",value);option.value=value;s.transport.append(option);}for(const value of ["RFC5424","RFC3164"]){const option=make("option",value);option.value=value;s.format.append(option);}
    s.port.min=1;s.port.max=65535;s.facility.min=0;s.facility.max=23;s.severity.min=0;s.severity.max=7;
    const verification=make("details");verification.append(make("summary","Collector verification"));
    s.serverCertificateSha256=field(verification,"TLS certificate SHA-256","text",64);s.serverCertificateSha256.pattern="[0-9a-fA-F]{64}";
    s.requirePersistenceReceipt=field(verification,"Confirm storage","checkbox");verification.append(make("p","Confirm storage requires a collector that returns receipts."));syslog.append(verification);
    const verifyTransport=()=>{s.serverCertificateSha256.setCustomValidity(s.serverCertificateSha256.value&&s.transport.value!=="TLS"?"Choose TLS to use a certificate fingerprint.":"");s.requirePersistenceReceipt.setCustomValidity(s.requirePersistenceReceipt.checked&&s.transport.value==="UDP"?"Choose TCP or TLS to confirm storage.":"");};
    for(const input of [s.transport,s.serverCertificateSha256,s.requirePersistenceReceipt])input.addEventListener("change",verifyTransport);
    const syslogStatus=make("p");syslogStatus.setAttribute("role","status");syslog.append(syslogStatus);
    const sp=proof(syslog),saveSyslog=make("button","Save server syslog");syslog.append(saveSyslog);page.append(syslog);
    const routing=make("section");routing.className="notification-form";routing.append(make("h3","Choose the syslog sender"),helpDetails("Server sender","Enable endpoint forwarding above and disable client syslog in group Policies. Only the server needs collector access."),helpDetails("Client sender","Disable server endpoint forwarding and set a managed client destination in Policies. Each client needs collector access; alerts still go to management."),helpDetails("Both senders","Enable both paths to send from clients and the server. Duplicate events are possible. Token callbacks are forwarded by the server only."),helpDetails("Connectivity and changes","Firewall changes are not automatic. Group settings apply after synchronization. Disabling client syslog retains its queue."),helpDetails("Offline storage limits","Set queue limits in Policies. Current queue agents default to 10,000 alerts / 128 MiB; older agents retain a 1,000-alert limit. Full queues or disks require action; storage is not unlimited."));page.append(routing);
    function values(fields){return Object.fromEntries(Object.entries(fields).map(([key,input])=>[key,input.type==="checkbox"?input.checked:input.type==="number"?Number(input.value):input.value]));}
    function populate(fields,data){for(const [key,input]of Object.entries(fields)){if(key==="password"||key==="clearPassword")continue;if(input.type==="checkbox")input.checked=!!data[key];else input.value=Array.isArray(data[key])?data[key].join("\n"):data[key]??"";}}
    async function load(){
        const epoch=++generation;loading=true;saveEmail.disabled=true;saveSyslog.disabled=true;test.disabled=true;
        try{
            const [mail,forwarding]=await Promise.all([api("/api/v1/console/email"),api("/api/v1/console/server-syslog")]);if(epoch!==generation)return;
            emailRevision=mail.settings.revision;syslogRevision=forwarding.settings.revision;populate(e,mail.settings);e.password.value="";e.clearPassword.checked=false;e.password.placeholder=mail.settings.hasPassword?"Stored securely; leave blank to retain":"No stored password";
            populate(s,{...forwarding.settings.destination,endpointEvents:forwarding.settings.endpointEvents,includeLogOnlyEvents:forwarding.settings.includeLogOnlyEvents,callbackHits:forwarding.settings.callbackHits,serviceHits:forwarding.settings.serviceHits});
            const emailState=emailDeliveryText;
            emailStatus.replaceChildren(document.createTextNode("Token email: "+emailState(mail.delivery.state)+" · Service email: "+emailState(mail.services?.state)),helpDetails("Email diagnostics",mail.delivery.message+" · Completed sequence "+mail.delivery.lastCompletedSequence+". Service email: "+(mail.services?.message||"Unavailable")));
            syslogStatus.replaceChildren(document.createTextNode("Endpoint alerts: "+deliveryText(forwarding.endpoints.message)+" · Token alerts: "+deliveryText(forwarding.callbacks.message)+" · Service alerts: "+deliveryText(forwarding.services?.message)),helpDetails("Syslog diagnostics","Endpoints: "+forwarding.endpoints.message+" · Sequence "+forwarding.endpoints.lastSentSequence+". Tokens: "+forwarding.callbacks.message+" · Sequence "+forwarding.callbacks.lastSentSequence+". Services: "+(forwarding.services?.message||"Unavailable")+" · Sequence "+(forwarding.services?.lastSentSequence??"Unknown")+". Collector receipt is unconfirmed."));
            ep.render();sp.render();verifyTransport();
        }finally{loading=false;saveEmail.disabled=!admin();saveSyslog.disabled=!admin();test.disabled=!admin();}
    }
    email.addEventListener("submit",event=>{event.preventDefault();if(loading||!admin())return;guarded(saveEmail,async()=>{
        try{const body=values(e);body.recipients=body.recipients.split(/[\n,;]/).map(x=>x.trim()).filter(Boolean);await api("/api/v1/console/email",{expectedRevision:emailRevision,...body,...ep.body()});await load();notice.textContent="Email settings saved.";}
        finally{ep.clear();e.password.value="";}
    },notice.id);});
    test.addEventListener("click",()=>{if(loading||!admin())return;if(!confirm("Send a test email to all saved recipients?"))return;guarded(test,async()=>{try{const result=await api("/api/v1/console/email/test",ep.body());notice.textContent=result.message==="SMTP accepted the test for all configured recipients. Verify their mailboxes."?"Test submitted. Check recipients’ inboxes.":"Test outcome unconfirmed. Check before retrying.";notice.append(helpDetails("Diagnostics",result.message||"No delivery result reported"));}finally{ep.clear();}},notice.id);});
    syslog.addEventListener("submit",event=>{event.preventDefault();if(loading||!admin())return;guarded(saveSyslog,async()=>{
        try{const {endpointEvents,includeLogOnlyEvents,callbackHits,serviceHits,...destination}=values(s);destination.serverCertificateSha256=destination.serverCertificateSha256.trim()||null;await api("/api/v1/console/server-syslog",{expectedRevision:syslogRevision,destination,endpointEvents,includeLogOnlyEvents,callbackHits,serviceHits,...sp.body()});await load();notice.textContent="Server syslog saved.";}finally{sp.clear();}
    },notice.id);});
    nav.addEventListener("click",()=>guarded(nav,async()=>{if(!admin())return;await view("notifications");if(page.hidden)return;$("page-title").textContent="Notifications";await load();},notice.id));
    refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));
    document.addEventListener("view-changed",event=>{nav.hidden=!admin()||!!account?.mustChangePassword||!!account?.mustEnrollMfa;if(event.detail!=="notifications"){generation++;ep.clear();sp.clear();e.password.value="";}});
    document.addEventListener("session-cleared",()=>{generation++;email.reset();syslog.reset();ep.clear();sp.clear();nav.hidden=true;notice.textContent="";emailStatus.textContent="";syslogStatus.textContent="";});
    // The initial session can finish loading before this deferred script.
    nav.hidden=!admin()||!!account?.mustChangePassword||!!account?.mustEnrollMfa;
})();
