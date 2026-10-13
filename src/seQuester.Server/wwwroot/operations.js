"use strict";
(()=>{
    const make=(tag,text)=>{const node=document.createElement(tag);if(text)node.textContent=text;return node;};
    const nav=make("button","Operations");nav.dataset.view="operations";document.querySelector("nav").append(nav);
    const page=make("section"),summary=make("p"),notice=make("p"),refresh=make("button","Refresh"),table=make("table"),head=make("thead"),heading=make("tr"),rows=make("tbody");
    page.id="operations";page.className="view";page.hidden=true;notice.id="operations-notice";notice.setAttribute("role","status");
    for(const label of ["Component","State","Details"]){const th=make("th",label);th.scope="col";heading.append(th);}head.append(heading);table.append(head,rows);
    const wrap=make("div");wrap.className="table-wrap";wrap.append(table);page.append(make("h2","Service health"),summary,refresh,notice,wrap);document.querySelector("main").append(page);
    let epoch=0;
    async function load(){const current=++epoch,data=await api("/api/v1/console/operations");if(current!==epoch||page.hidden)return;rows.replaceChildren();summary.textContent=`${operationsSummaryText(data)} · Last checked: ${Number.isFinite(Date.parse(data.checkedUtc))?time(data.checkedUtc):"Unknown"}`;for(const item of data.checks){const row=make("tr"),display=operationPresentation(item);cell(row,display.component);cell(row,display.state);const detail=cell(row,"");detail.append(helpDetails("Diagnostics",`${item.component} · ${item.state}\n${item.detail||"No details reported"}`));rows.append(row);}}
    nav.addEventListener("click",()=>guarded(nav,async()=>{await view("operations");if(page.hidden)return;$("page-title").textContent="Operations";await load();},notice.id));refresh.addEventListener("click",()=>guarded(refresh,load,notice.id));
    document.addEventListener("view-changed",event=>{if(event.detail!=="operations")epoch++;});document.addEventListener("session-cleared",()=>{epoch++;rows.replaceChildren();summary.textContent="";notice.textContent="";});
})();
