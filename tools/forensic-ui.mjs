import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const output=process.argv[2];assert.ok(output);fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:['--disable-gpu','--disable-features=CalculateNativeWinOcclusion'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1050}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS '+label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto('http://127.0.0.1:19325');await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Policies',exact:true}).click();await page.getByLabel('New group',{exact:true}).fill('Forensic QA');await page.getByRole('button',{name:'Create group',exact:true}).click();await page.getByRole('button',{name:/Forensic QA ·/}).click();
 const policy=page.locator('#policies');
 check(await policy.getByLabel('Preserve actor executable on alerts',{exact:true}).isChecked(),'default policy preserves actor executables at the alert threshold');
 check(await policy.getByLabel('Preservation threshold',{exact:true}).inputValue()==='alert','policy threshold is explicit');
 check(await policy.getByText(/readable actors above that limit are still hashed/).isVisible(),'policy distinguishes actor preservation size limit from SHA-256 collection');
 await policy.getByLabel('Evidence store limit (MiB)',{exact:true}).fill('2048');await policy.getByLabel('Executable cache entries',{exact:true}).fill('128');await policy.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#policy-notice').filter({hasText:'Policy published.'}).waitFor();
 const groups=await page.evaluate(()=>fetch('/api/v1/console/groups').then(r=>r.json()));const group=groups.find(x=>x.name==='Forensic QA');
 check(group?.settings?.forensics?.evidenceStoreMiB===2048&&group.settings.forensics.cacheEntries===128,'real authenticated publication persists evidence limits in server DB');
 await page.getByRole('button',{name:/Forensic QA ·/}).click();check(await policy.getByLabel('Evidence store limit (MiB)',{exact:true}).inputValue()==='2048','published evidence policy reads back correctly');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1000});const bounds=await policy.locator('input:visible,select:visible').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:innerWidth};}));check(bounds.every(r=>r.left>=0&&r.right<=r.width),'policy controls fit at '+width+'px');await page.screenshot({path:path.join(output,'policy-'+width+'.png'),fullPage:true});
 }
 await page.getByRole('button',{name:'Alerts',exact:true}).click();const detail=page.getByText('Actor executable evidence',{exact:true});await detail.first().waitFor();await detail.first().click();
 check(await page.getByText(/Actor SHA-256:/).count()>0,'actor hash, signer and preservation details are visible');
 const events=await page.evaluate(()=>fetch('/api/v1/console/event-history?host=QA-Windows&limit=100').then(r=>r.json()));const event=events.items.find(x=>x.event.forensics)?.event;
 check(event?.forensics?.actorExecutable?.sha256?.length===64&&event.forensics.preservation.hashMatched===true,'console API retains native fixture hash and independently verified copy evidence');
 check(event.forensics.process.owner.sid!==event.forensics.process.eventSubject.sid&&event.forensics.process.impersonating===null,'console API keeps owner and subject separate and leaves unavailable impersonation unknown');
 check(event.forensics.process.processSessionId!==null&&event.forensics.process.sessionStatus.state==='captured'&&event.forensics.process.parentStatus?.reason&&event.forensics.actorExecutable.file.accessedUtc&&event.forensics.actorExecutable.file.changedUtc,'console API preserves additive parent/session status and actor file timestamps');
 await page.screenshot({path:path.join(output,'actor-evidence-390.png'),fullPage:true});
 check(errors.length===0,'changed console runs without JavaScript errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({checks,errors,group,event,scope:'Isolated packaged console; fixture evidence, not production'},null,2));
}finally{await browser.close();}
