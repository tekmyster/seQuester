import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [origin,output]=process.argv.slice(2);
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));fs.mkdirSync(output,{recursive:false});
const password='QA-only-long-passphrase-905!';
const provision=await fetch(origin+'/api/v1/admin/users',{method:'POST',headers:{Authorization:'Bearer '+process.env.RF_NATIVE_UI_ADMIN,'Content-Type':'application/json'},body:JSON.stringify({userName:'io-ui-qa',password,role:'Administrator'})});
assert.equal(provision.status,200);delete process.env.RF_NATIVE_UI_ADMIN;
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('io-ui-qa');await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
 const history=await page.evaluate(()=>fetch('/api/v1/console/event-history?limit=500').then(r=>r.json()));
 const events=history.items.filter(x=>x.event.source==='Linux kernel'&&x.event.attribution?.linuxKernel?.ioObservation?.stage===2);
 check(events.length===14,'all fourteen actual completed I/O records visible through signed-in API');
 await page.locator('#history-filter-panel > summary').click();
 for(const label of ['File Changed','File Appended']){
  const expected=events.filter(x=>x.displayOperation===label);check(expected.length>0,'actual '+label+' observations exist');
  await page.getByLabel('Action',{exact:true}).selectOption(label);await page.getByRole('button',{name:'Apply filters',exact:true}).click();await page.locator('[data-event-id="'+expected[0].event.eventId+'"]').waitFor();
  const ids=await page.locator('#alert-rows tr[data-event-id]').evaluateAll(rows=>rows.map(r=>r.dataset.eventId));
  check(ids.length===expected.length&&expected.every(x=>ids.includes(x.event.eventId)),'action filter '+label+' retains exact event IDs');
  for(const item of expected){
   const e=item.event,row=page.locator('[data-event-id="'+e.eventId+'"]');
   check(await row.locator('[data-label="PID"]').innerText()===String(e.processId)&&await row.locator('[data-label="User"]').innerText()===e.user,'operation-time user and PID: '+e.eventId);
   const io=row.locator('details.linux-io-evidence');await io.locator('summary').click();const text=await io.innerText();
   check(text.includes('Returned bytes: 7')&&text.includes('Outcome: success'),'actual returned bytes visible: '+e.eventId);
   const pair=row.locator('details.linux-io-actor-evidence');await pair.locator('summary').click();
   check((await pair.innerText()).includes(e.forensics.linuxIoPair.actorSha256),'verified entry executable SHA visible: '+e.eventId);
  }
 }
 check(errors.length===0,'no browser errors');await page.screenshot({path:path.join(output,'io-history.png'),fullPage:true});
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({Passed:true,Checks:checks.length,Details:checks,Scope:'Actual accepted Linux I/O evidence in isolated authenticated release UI; production deployment remains separate.'},null,2));
}finally{await browser.close();}
