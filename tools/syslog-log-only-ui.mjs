// Render the real notification module against isolated synthetic API state.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const browser=await chromium.launch({headless:true,executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
try {
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.setContent('<nav></nav><main></main><h1 id="page-title"></h1>');
 await page.evaluate(()=>{
  window.account={roles:['Administrator'],authentication:'SSO'};window.$=id=>document.getElementById(id);
  window.helpDetails=(title,text)=>{const el=document.createElement('p');el.textContent=title+': '+text;return el;};
  window.factor=()=>({});window.emailDeliveryText=window.deliveryText=v=>String(v||'Idle');
  window.guarded=async(button,fn)=>{button.disabled=true;try{await fn();}finally{button.disabled=false;}};
  window.view=async id=>{document.getElementById(id).hidden=false;};
  window.calls=[];window.include=true;
  window.api=async(path,body)=>{
   if(body){window.calls.push({path,body});window.include=body.includeLogOnlyEvents;return {};}
   if(path.endsWith('/email'))return {settings:{revision:0},delivery:{message:'Idle',lastCompletedSequence:0},services:{message:'Idle'}};
   return {settings:{revision:7,destination:{enabled:true,host:'192.0.2.10',port:514,transport:'TCP',format:'RFC5424',facility:16,severity:4},endpointEvents:true,includeLogOnlyEvents:window.include},endpoints:{message:'Idle',lastSentSequence:0},callbacks:{message:'Idle',lastSentSequence:0},services:{message:'Idle',lastSentSequence:0}};
  };
 });
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/notifications.js',import.meta.url),'utf8')});
 await page.getByRole('button',{name:'Notifications',exact:true}).click();
 const checkbox=page.getByLabel('Include whitelisted events as logs (no alert)',{exact:true});
 await checkbox.waitFor({state:'visible'});assert.equal(await checkbox.isChecked(),true);
 await checkbox.uncheck();await page.getByRole('button',{name:'Save server syslog',exact:true}).click();
 await page.waitForFunction(()=>window.calls.length===1&&document.getElementById('notification-notice').textContent==='Server syslog saved.');
 let call=await page.evaluate(()=>window.calls[0]);assert.equal(call.body.includeLogOnlyEvents,false);assert.equal('includeLogOnlyEvents' in call.body.destination,false);assert.equal(call.body.expectedRevision,7);
 assert.equal(await checkbox.isChecked(),false);
 await checkbox.check();await page.getByRole('button',{name:'Save server syslog',exact:true}).click();
 await page.waitForFunction(()=>window.calls.length===2);call=await page.evaluate(()=>window.calls[1]);assert.equal(call.body.includeLogOnlyEvents,true);assert.equal(call.body.destination.transport,'TCP');
 await page.evaluate(()=>{document.dispatchEvent(new Event('session-cleared'));});assert.equal(await checkbox.isChecked(),false);
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({Passed:true,Checks:10,Scope:'Real notifications module rendered in Chromium with isolated synthetic API; both toggle directions, payload separation, persisted reload, session reset, no script errors. Not production UI acceptance.'}));
}finally{await browser.close();}
