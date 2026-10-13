import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const output=process.argv[2];assert.ok(output);fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1050}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS '+label);};
page.on('pageerror',e=>errors.push(e.message));
try{
 await page.goto('http://127.0.0.1:19325');await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#history-filter-panel > summary').click();await page.getByLabel('Host contains',{exact:true}).fill('QA-Kernel');await page.getByRole('button',{name:'Apply filters',exact:true}).click();
 const data=await page.evaluate(()=>fetch('/api/v1/console/event-history?host=QA-Kernel&limit=100').then(r=>r.json()));
 const denied=data.items.find(x=>x.event.attribution?.osStatus==='0xC0000022'),imp=data.items.find(x=>x.event.attribution?.windowsKernel?.threadImpersonating===true&&x.event.attribution.windowsKernel.major===3);
 check(!!denied&&!!imp,'authenticated history retains native denied and impersonated access');
 const deniedRow=page.locator(`[data-event-id="${denied.event.eventId}"]`);await deniedRow.waitFor();
 check(await deniedRow.locator('[data-label="Action"]').innerText()==='Access Denied','denied native open is visible as Access Denied');
 for(const item of [denied,imp]){
  const e=item.event,k=e.attribution.windowsKernel,row=page.locator(`[data-event-id="${e.eventId}"]`);await row.waitFor();
  check(await row.locator('[data-label="PID"]').innerText()===String(e.processId)&&await row.locator('[data-label="User"]').innerText()===e.user&&await row.locator('[data-label="Process"]').innerText()===e.process,'visible user/process/PID match native API record '+e.eventId);
  for(const [label,token] of [['Windows accessing thread',k.threadEffective],['Windows open authorization',k.createAuthorization],['Windows process primary token',k.requestorPrimary]]){
   const panel=row.locator('details').filter({has:page.getByText(label,{exact:true})});await panel.locator('summary').click();const text=await panel.innerText();
   check(text.includes(token.sid??'Unavailable')&&text.includes(token.tokenId??'Unavailable')&&text.includes(token.authenticationId??'Unavailable'),label+' retains independent native identity '+e.eventId);
  }
  check((await row.innerText()).includes('Thread ID: '+k.threadId)&&(await row.innerText()).includes('Thread owner PID: '+k.threadProcessId),'thread and creating-process IDs are visible '+e.eventId);
 }
 check(imp.event.attribution.windowsKernel.threadEffective.sid!==imp.event.attribution.windowsKernel.requestorPrimary.sid,'impersonated user remains distinct from process primary user');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1050});const row=page.locator(`[data-event-id="${imp.event.eventId}"]`);
  const bounds=await row.locator('details[open]').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return{left:r.left,right:r.right,width:innerWidth};}));
  check(bounds.length===3&&bounds.every(x=>x.left>=0&&x.right<=x.width),'expanded token panels fit at '+width+'px');
  check(await row.locator('.kernel-evidence[open] p').evaluateAll(items=>items.length===3&&items.every(el=>getComputedStyle(el).whiteSpace==='pre-wrap')),'token fields retain readable line breaks at '+width+'px');
  await row.screenshot({path:path.join(output,'tokens-'+width+'.png')});
 }
 await page.locator('#history-filters select[name="action"]').selectOption('Access Denied');await Promise.all([page.waitForResponse(r=>r.url().includes('/event-history?')&&r.status()===200),page.getByRole('button',{name:'Apply filters',exact:true}).click()]);await page.locator('#alert-rows').filter({has:page.locator('[data-label="Action"]')}).waitFor();
 const actions=await page.locator('#alert-rows [data-label="Action"]').allTextContents();check(actions.length>0&&actions.every(x=>x==='Access Denied'),'UI denial filter excludes successful reads');
 check(errors.length===0,'native token details render without JavaScript errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({checks,errors,scope:'Isolated packaged server with real VM token observations; not production kernel deployment'},null,2));
}finally{await browser.close();}
