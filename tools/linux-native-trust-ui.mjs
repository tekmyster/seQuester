import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [origin,output]=process.argv.slice(2);
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));fs.mkdirSync(output,{recursive:false});
const password='QA-only-long-passphrase-905!';
const provision=await fetch(origin+'/api/v1/admin/users',{method:'POST',headers:{Authorization:'Bearer '+process.env.RF_NATIVE_UI_ADMIN,'Content-Type':'application/json'},body:JSON.stringify({userName:'native-ui-qa',password,role:'Administrator'})});
assert.equal(provision.status,200,'isolated administrator created');
delete process.env.RF_NATIVE_UI_ADMIN;
async function capability(active){
 const response=await fetch(origin+'/api/v1/agent/trust-policy',{method:'POST',headers:{Authorization:'Bearer '+process.env.RF_NATIVE_UI_CREDENTIAL,'Content-Type':'application/json'},body:JSON.stringify({version:1,policyVersion:3,linuxKernelTrustVersion:active?1:0,operatingSystem:'linux'})});assert.equal(response.status,200);
}
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS: '+label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('native-ui-qa');await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 1'}).waitFor();
 check(await page.locator('.trust-rule').count()===3,'actual native qualification policy loads in packaged UI');
 await page.getByRole('button',{name:'Create whitelist',exact:true}).click();const draft=page.locator('.trust-rule').last();
 await draft.getByLabel('Rule name',{exact:true}).fill('Manual Linux native reader');await draft.getByLabel('Match identity',{exact:true}).selectOption('process');await draft.getByLabel('Process matching',{exact:true}).selectOption('linux-task-root-path-sha256-v1');
 await draft.getByLabel('Executable path',{exact:true}).fill('/usr/lib/sequester-qa-reader');await draft.getByLabel('SHA-256',{exact:true}).fill('a'.repeat(64));await draft.getByLabel('Enabled',{exact:true}).check();
 check(await draft.getByLabel('Open',{exact:true}).isChecked()&&await draft.getByLabel('Write',{exact:true}).isDisabled(),'native rule explicitly permits observed open requests only');
 check(await draft.getByLabel('Operating system',{exact:true}).inputValue()==='linux','native rule uses Linux platform');
 await capability(false);
 await page.locator('#trust').getByLabel('Administrator password',{exact:true}).fill(password);await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'active qualified kernel source'}).waitFor();
 check(await draft.getByLabel('Executable path',{exact:true}).inputValue()==='/usr/lib/sequester-qa-reader','server capability refusal preserves editable manual draft');
 let policy=await page.evaluate(()=>fetch('/api/v1/console/trust-policy').then(r=>r.json()));check(policy.revision===1,'refused native publication leaves exact current revision unchanged');
 await capability(true);await page.locator('#trust').getByLabel('Administrator password',{exact:true}).fill(password);await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Published.'}).waitFor();
 policy=await page.evaluate(()=>fetch('/api/v1/console/trust-policy').then(r=>r.json()));const saved=policy.rules.find(r=>r.name==='Manual Linux native reader');
 check(policy.version===3&&policy.revision===2&&saved?.sha256==='a'.repeat(64)&&saved.processMatch==='linux-task-root-path-sha256-v1'&&saved.actions.join(',')==='open','authenticated manual creation persists exact native path/hash/action policy');
 await page.reload();await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
 const history=await page.evaluate(()=>fetch('/api/v1/console/event-history?limit=100').then(r=>r.json()));
 check(history.items.length===13&&history.items.filter(x=>x.trustClassification==='LogOnly').length===4&&history.items.filter(x=>x.trustClassification==='NonWhitelisted').length===3,'packaged history preserves actual native classifications after policy revision changes');
 const originals=history.items.filter(x=>x.event.source==='Linux kernel');
 check(originals.length===5&&originals.every(x=>x.event.user&&x.event.process&&Number.isInteger(x.event.processId)&&x.event.processId>0),'all actual original user/process/PID fields visible through signed-in console API');
 check(originals.every(x=>x.event.trust.actor.sha256&&x.event.trust.linuxKernelBinding?.actor?.processId===x.event.processId),'console API retains hash and exact process-instance linkage');
 const first=page.getByRole('button',{name:'Create whitelist',exact:true}).first();await first.click();await page.locator('#trust-status').filter({hasText:'Draft created'}).waitFor();const derived=page.locator('.trust-rule').last();
 check(await derived.getByLabel('Process matching',{exact:true}).inputValue()==='linux-task-root-path-sha256-v1'&&(await derived.getByLabel('SHA-256',{exact:true}).inputValue()).length===64,'actual native event creates a hash-bound draft');
 check(await derived.getByLabel('Scope',{exact:true}).inputValue()==='host'&&!(await derived.getByLabel('Enabled',{exact:true}).isChecked()),'event-derived draft stays disabled and scoped to its sensor');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1100});const bounds=await page.locator('#trust input:visible,#trust select:visible').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return{left:r.left,right:r.right,width:innerWidth};}));
  check(bounds.every(r=>r.left>=0&&r.right<=r.width),'native whitelist fields fit '+width+'px');await page.screenshot({path:path.join(output,'native-trust-'+width+'.png'),fullPage:true});
 }
 check(errors.length===0,'packaged UI has no JavaScript errors');fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({Passed:true,Checks:checks.length,Details:checks,Policy:policy,History:history,Scope:'Real isolated authenticated packaged UI/API using accepted immutable native events; readiness reports belong only to the fixture'},null,2));
}finally{delete process.env.RF_NATIVE_UI_CREDENTIAL;await browser.close();}
