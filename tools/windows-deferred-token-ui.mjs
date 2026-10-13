import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [origin,output]=process.argv.slice(2);
assert.match(origin,/^http:\/\/127\.0\.0\.1:\d+$/);
fs.mkdirSync(output,{recursive:false});
const password='QA-only-long-passphrase-905!';
const response=await fetch(origin+'/api/v1/admin/users',{method:'POST',headers:{Authorization:'Bearer '+process.env.RF_NATIVE_UI_ADMIN,'Content-Type':'application/json'},body:JSON.stringify({userName:'deferred-ui-qa',password,role:'Administrator'})});
assert.equal(response.status,200);delete process.env.RF_NATIVE_UI_ADMIN;
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
page.on('pageerror',error=>errors.push(error.message));
const check=(ok,name)=>{assert.ok(ok,name);checks.push(name);};
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('deferred-ui-qa');await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
 const history=await page.evaluate(()=>fetch('/api/v1/console/event-history?limit=500').then(r=>r.json()));
 const events=history.items.filter(x=>x.event.attribution?.windowsKernel?.deferredTokenContext);
 check(events.length===33,'all 33 replayed native records visible through signed-in API');
 const impersonating=events.find(x=>x.event.attribution.windowsKernel.deferredTokenContext.threadImpersonating===true);
 const ordinary=events.find(x=>x.event.attribution.windowsKernel.deferredTokenContext.threadImpersonating===false);
 check(!!impersonating&&!!ordinary,'impersonating and ordinary native controls available');
 for(const item of [impersonating,ordinary]){
  const e=item.event,k=e.attribution.windowsKernel,d=k.deferredTokenContext,row=page.locator(`[data-event-id="${e.eventId}"]`);await row.waitFor();
  for(const [label,value] of [['User',e.user],['Process',e.process],['PID',String(e.processId)]])check(await row.locator(`[data-label="${label}"]`).innerText()===value,'visible '+label+' matches API: '+e.eventId);
  const panel=row.locator('details').filter({has:page.getByText('Windows accessing-thread token captured at APC',{exact:true})});await panel.locator('summary').click();
  const text=await panel.innerText();
  check(text.includes('Thread ID: '+k.threadId)&&text.includes('Impersonating at reference: '+d.threadImpersonating),'actual thread and impersonation state: '+e.eventId);
  check(text.includes(d.referencedUtc)&&text.includes(d.queryStartedUtc)&&text.includes(d.impersonationMetadataTiming),'reference and later query timing visible: '+e.eventId);
  check(text.includes(d.threadEffective.sid??'SID: Unavailable'),'effective SID or explicit unavailable: '+e.eventId);
  if(d.threadImpersonating)check(text.includes(d.threadEffective.tokenId)&&text.includes(d.threadEffective.authenticationId)&&text.includes('S-1-5-19'),'impersonated token identity remains distinct from SYSTEM');
  else check(text.includes('Captured fields: 0/31')&&!text.includes('SID: S-1-5-18'),'ordinary thread has no invented impersonation token');
  for(const label of ['Windows process owner collected later','Windows thread owner collected later']){
   const owner=row.locator('details').filter({has:page.getByText(label,{exact:true})});await owner.locator('summary').click();const ownerText=await owner.innerText();check(ownerText.includes('S-1-5-18')&&ownerText.includes(d.primaryMetadataTiming),'separate later primary metadata: '+label);
  }
 }
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1100});const row=page.locator(`[data-event-id="${impersonating.event.eventId}"]`);
  const bounds=await row.locator('details[open]').evaluateAll(nodes=>nodes.map(n=>{const r=n.getBoundingClientRect();return{left:r.left,right:r.right,width:innerWidth};}));
  check(bounds.length===3&&bounds.every(x=>x.left>=0&&x.right<=x.width),'three separate context panels fit at '+width+'px');
  await row.screenshot({path:path.join(output,'deferred-tokens-'+width+'.png')});
 }
 check(errors.length===0,'no browser script errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({Passed:true,checks,errors,scope:'Signed-in isolated server UI with replayed native Windows records; not production UI or live sensor acceptance'},null,2));
 console.log(JSON.stringify({Passed:true,Checks:checks.length,Output:output}));
}finally{await browser.close();}
