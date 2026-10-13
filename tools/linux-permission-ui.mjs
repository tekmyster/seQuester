import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [origin,output]=process.argv.slice(2);
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));fs.mkdirSync(output,{recursive:false});
const password='QA-only-long-passphrase-905!';
const provision=await fetch(origin+'/api/v1/admin/users',{method:'POST',headers:{Authorization:'Bearer '+process.env.RF_NATIVE_UI_ADMIN,'Content-Type':'application/json'},body:JSON.stringify({userName:'permission-ui-qa',password,role:'Administrator'})});
assert.equal(provision.status,200);delete process.env.RF_NATIVE_UI_ADMIN;
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS: '+label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('permission-ui-qa');await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
 const history=await page.evaluate(()=>fetch('/api/v1/console/event-history?limit=500').then(r=>r.json()));
 const events=history.items.filter(x=>x.event.source==='Linux kernel'&&x.event.attribution?.linuxKernel?.permissionObservation);
 check(events.length>=4,'signed-in history exposes actual native permission observations');
 check(events.every(x=>x.event.processId>0&&x.event.user),'event-time user and PID retained in signed-in API');
 const denied=events.find(x=>x.event.attribution.linuxKernel.permissionObservation.permissionResult===-13);
 check(!!denied,'actual denied permission return visible through console API');
 await page.locator('#history-filter-panel > summary').click();
 for(const [stage,label] of [[1,'Permission Check Requested'],[2,'Permission Check Returned']]){
  await page.getByLabel('Action',{exact:true}).selectOption(label);await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  const expected=events.filter(x=>x.event.attribution.linuxKernel.permissionObservation.stage===stage);
  await page.locator(`[data-event-id="${expected[0].event.eventId}"]`).waitFor();
  const ids=await page.locator('#alert-rows tr[data-event-id]').evaluateAll(rows=>rows.map(r=>r.dataset.eventId));
  check(ids.length===expected.length&&expected.every(x=>ids.includes(x.event.eventId)),'visible action filter retains exact permission stage '+stage);
  for(const item of expected){
   const e=item.event,row=page.locator(`[data-event-id="${e.eventId}"]`),k=e.attribution.linuxKernel,p=k.permissionObservation;
   check(await row.locator('[data-label="PID"]').innerText()===String(e.processId)&&await row.locator('[data-label="User"]').innerText()===e.user,'visible user and PID match actual native record '+e.eventId);
   check(await row.locator('[data-label="Process"]').innerText()===(e.process||'Not reported'),'missing executable path remains explicit '+e.eventId);
   check(await row.locator('[data-label="Action"]').innerText()===label,'permission action does not imply completed I/O '+e.eventId);
   const panel=row.locator('details.linux-permission-evidence');await panel.locator('summary').click();
   const text=await panel.innerText();
   check(text.includes(p.operationNonce)&&text.includes(String(k.targetIdentity.inode))&&text.includes('does not establish the final syscall result'),'permission detail retains nonce, target and result semantics '+e.eventId);
  }
 }
 await page.screenshot({path:path.join(output,'permission-history.png'),fullPage:true});
 check(errors.length===0,'packaged UI has no browser errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({Passed:true,Checks:checks.length,Details:checks,Scope:'Actual accepted native records in isolated authenticated packaged UI; unavailable actor paths remain explicit; no production deployment'},null,2));
}finally{await browser.close();}
