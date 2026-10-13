import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [file,output]=process.argv.slice(2);assert.ok(file&&output);fs.mkdirSync(output,{recursive:false});
const event=JSON.parse(fs.readFileSync(file,'utf8')),browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1000}}),checks=[],errors=[];
const check=(ok,name)=>{assert.ok(ok,name);checks.push(name);};page.on('pageerror',e=>errors.push(e.message));
try{
 await page.setContent(fs.readFileSync(new URL('../src/seQuester.Server/wwwroot/index.html',import.meta.url),'utf8'));
 await page.addStyleTag({content:fs.readFileSync(new URL('../src/seQuester.Server/wwwroot/console.css',import.meta.url),'utf8')});
 await page.evaluate(event=>{
  window.fixtureEvent=event;window.cell=(row,value)=>{const td=document.createElement('td');td.textContent=value??'Unknown';row.append(td);return td;};window.time=x=>x;
  window.attributionDetails=()=>document.createElement('details');window.guarded=async(_button,work)=>work();window.account={roles:[]};
  window.api=async()=>({items:[{sequence:1,sequenceText:'1',endpointId:'fixture',machineName:'isolated-windows-test',displayOperation:'Access Denied',notificationType:'alert',event:fixtureEvent}],nextCursor:null,total:1,snapshot:1});
 },event);
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/seQuester.Server/wwwroot/presentation.js',import.meta.url),'utf8')});
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/seQuester.Server/wwwroot/event-history.js',import.meta.url),'utf8')});
 await page.evaluate(()=>{document.getElementById('login').hidden=true;document.getElementById('workspace').hidden=false;document.getElementById('alerts').hidden=false;return EventHistory.load(true);});
 const row=page.locator('#alert-rows tr').first(),cells=await row.locator('td').allTextContents();
 check(cells[4]===event.user,'user column retains actual effective SID');check(cells[5]===event.process,'process column matches acquisition fixture');check(cells[6]===String(event.processId),'PID column matches native record');
 const panel=row.locator('.windows-syscall-evidence');await panel.locator(':scope > summary').click();const text=await panel.innerText();
 check(text.includes('S-1-5-18')&&text.includes('S-1-5-19'),'separate owner and effective thread identities visible');
 check(text.includes('Impersonating: true')&&text.includes('0xC0000022'),'impersonation and native denied status visible');
 check(text.includes(event.attribution.windowsSyscall.native.rawRecordSha256),'native raw digest visible');
 check(text.includes('owned-thread-registered-handles')&&text.includes('does not establish general sensor coverage'),'experimental coverage explicitly visible');
 check(text.includes('pending submission is not a completed operation')&&text.includes('target name was queried later'),'timing and completion limitations visible');
 const actorPanel=row.locator('details').filter({has:page.getByText('Actor executable evidence',{exact:true})});await actorPanel.locator('summary').click();
 check((await actorPanel.innerText()).includes(event.forensics.actorExecutable.sha256),'actor SHA256 visible');
 for(const width of [1440,768,390]){await page.setViewportSize({width,height:1000});await page.screenshot({path:path.join(output,`syscall-${width}.png`),fullPage:true});}
 check(errors.length===0,'no browser runtime errors');fs.writeFileSync(path.join(output,'acceptance.json'),JSON.stringify({Passed:true,Checks:checks,NativeTokens:'actual capture',Acquisition:'synthetic fixture',ProductionUiVerified:false},null,2));
 console.log(JSON.stringify({Passed:true,UiChecks:checks.length,Artifacts:output}));
}finally{await browser.close();}
