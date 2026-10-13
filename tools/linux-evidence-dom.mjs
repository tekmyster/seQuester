import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
assert.equal(process.argv.length,4,'Pass native-replay UI seed and fresh output directory');
const seed=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),output=process.argv[3];
fs.mkdirSync(output,{recursive:false});
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1050}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS '+label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.setContent(fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/index.html',import.meta.url),'utf8'));
 await page.addStyleTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/console.css',import.meta.url),'utf8')});
 await page.evaluate(events=>{
  window.rows=events;window.account={roles:['Administrator']};window.requests=[];
  window.cell=(row,value)=>{const td=document.createElement('td');td.textContent=value??'Unknown';row.append(td);return td;};window.time=value=>value;
  window.helpDetails=(title,text)=>{const details=document.createElement('details'),summary=document.createElement('summary'),body=document.createElement('p');summary.textContent=title;body.textContent=text;details.append(summary,body);return details;};
  window.attributionDetails=()=>helpDetails('Other provider details','Offline component fixture');window.guarded=async(_button,work)=>work();
  window.api=async target=>{requests.push(target);if(target.startsWith('/api/v1/console/actor-evidence/'))return {state:'received',size:123,receivedUtc:'2026-10-03T03:00:00Z',receiptId:'fixture-receipt'};
   return {items:rows.map((event,i)=>({sequence:i+1,sequenceText:String(i+1),endpointId:event.forensics.sensorId,machineName:'Linux native replay',recordKind:'endpoint',displayOperation:'Forensic Evidence',responseCandidate:false,event})),total:rows.length,nextCursor:null};};
 },seed.events);
 for(const file of ['presentation.js','event-history.js'])await page.addScriptTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/'+file,import.meta.url),'utf8')});
 await page.evaluate(()=>{document.getElementById('login').hidden=true;document.getElementById('workspace').hidden=false;document.getElementById('alerts').hidden=false;return EventHistory.load(true);});
 check(await page.locator('.linux-task-evidence').count()===4&&await page.locator('.linux-acquisition-evidence').count()===4,'all four native replay rows expose task and acquisition panels');
 for(let i=0;i<seed.events.length;i++){
  const event=seed.events[i],k=event.attribution.linuxKernel,a=event.forensics.actorExecutable.linuxAcquisition,row=page.locator('#alert-rows tr').nth(i);
  check(await row.locator('[data-label="PID"]').textContent()===String(k.processId),'primary PID remains exact for native row '+i);
  check(await row.locator('[data-label="User"]').textContent()===event.user,'primary user remains event-time filesystem principal for row '+i);
  const task=await row.locator('.linux-task-evidence p').textContent(),copy=await row.locator('.linux-acquisition-evidence p').textContent();
  check(task.includes('Filesystem UID: '+k.fileSystemUid)&&task.includes('Effective UID: '+k.effectiveUid)&&task.includes(k.credentialNamespace),'separate credentials and namespace shown for row '+i);
  check(task.includes(k.processStartNs)&&task.includes(k.selfExecId)&&task.includes(k.providerEpoch),'64-bit lifetime, exec and provider IDs render without numeric conversion for row '+i);
  check(copy.includes(a.snapshotSha256)&&copy.includes(a.nativeStatus.inode)&&copy.includes(String(a.nativeStatus.associationError)),'source inode, private hash and association error visible for row '+i);
 }
 check(await page.locator('#alert-rows tr').nth(2).locator('[data-label="Process"]').textContent()==='Not reported','invalid UTF-8 actor remains unavailable in primary process cell');
 check((await page.locator('#alert-rows tr').nth(2).locator('.linux-observation-evidence p').textContent()).includes(seed.events[2].attribution.linuxKernel.actorPath.bytesBase64),'invalid UTF-8 raw path bytes remain available in structured observation');
 await page.locator('#alert-rows tr').first().getByRole('button',{name:'Check server copy',exact:true}).click();
 check(await page.getByRole('link',{name:'Download actor executable evidence',exact:true}).count()===1,'existing server-copy download control remains available');
 const distinct=structuredClone(seed.events[0]);distinct.user='uid:1002 (initial user namespace)';distinct.attribution.linuxKernel={...distinct.attribution.linuxKernel,uid:1000,effectiveUid:1001,fileSystemUid:1002};
 distinct.forensics.process.eventSubject={...distinct.forensics.process.eventSubject,uid:1000,effectiveUid:1001,fileSystemUid:1002};
 distinct.forensics.actorExecutable.linuxAcquisition.nativeStatus.inode='18446744073709551615';
 distinct.process='</p><img src=x onerror="window.injected=true">';
 await page.evaluate(event=>{rows=[event];return EventHistory.load(true);},distinct);
 const detail=await page.locator('#alert-rows tr').textContent();
 check(detail.includes('Event principal: FSUID 1002 (INITIAL_USER_NAMESPACE)')&&!detail.includes('Event principal: 1001'),'filesystem UID, rather than effective UID, is shown as Linux event principal');
 check(detail.includes('18446744073709551615'),'full uint64 source inode remains exact in acquisition text');
 check(await page.locator('#alert-rows img').count()===0&&!await page.evaluate(()=>window.injected),'executable text cannot inject markup or handlers');
 for(const width of [1440,430]){
  await page.setViewportSize({width,height:1050});await page.evaluate(()=>{for(const item of document.querySelectorAll('.linux-task-evidence,.linux-acquisition-evidence'))item.open=true;});
  check(await page.locator('.linux-task-evidence p,.linux-acquisition-evidence p').evaluateAll(nodes=>nodes.every(n=>getComputedStyle(n).whiteSpace==='pre-wrap')),'task and acquisition details retain readable line breaks at '+width+'px');
  check(await page.locator('#alert-rows tr').evaluate(row=>[...row.querySelectorAll('.kernel-evidence p')].every(p=>p.scrollWidth<=p.clientWidth+2)),'native IDs and evidence wrap within their cells at '+width+'px');
  await page.screenshot({path:path.join(output,'linux-evidence-'+width+'.png'),fullPage:true});
 }
 const missing=structuredClone(distinct);missing.forensics.actorExecutable.linuxAcquisition={...missing.forensics.actorExecutable.linuxAcquisition,nativeStatus:null,snapshotSha256:null,snapshotId:null,status:{state:'unavailable',reason:'native-lease-missing'}};
 await page.evaluate(event=>{rows=[event];return EventHistory.load(true);},missing);
 const unavailable=await page.locator('.linux-acquisition-evidence p').textContent();check(unavailable.includes('unavailable · native-lease-missing')&&unavailable.includes('Private snapshot SHA-256: Unavailable')&&!unavailable.includes('undefined'),'missing acquisition metadata is explicit without fabricated values');
 check(errors.length===0,'no browser runtime errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({passed:true,checks:checks.length,scope:seed.scope,constructedEdges:['distinct filesystem UID','full uint64 inode','markup-looking executable','unavailable acquisition'],errors},null,2));
 console.log('PASS '+checks.length+' Linux evidence DOM checks; '+output);
}finally{await browser.close();}
