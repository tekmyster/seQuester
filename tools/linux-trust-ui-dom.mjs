import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const [seedFile,output]=process.argv.slice(2);assert.ok(seedFile&&output);fs.mkdirSync(output,{recursive:false});
const lower=value=>Array.isArray(value)?value.map(lower):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k[0].toLowerCase()+k.slice(1),lower(v)])):value;
const seed=lower(JSON.parse(fs.readFileSync(seedFile,'utf8'))),event=seed.event;
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);};page.on('pageerror',error=>errors.push(error.message));
try{
 const html=fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/index.html',import.meta.url),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
 await page.route('https://fixture.invalid/**',route=>route.fulfill({status:200,contentType:route.request().url()==='https://fixture.invalid/'?'text/html':'text/css',body:route.request().url()==='https://fixture.invalid/'?html:''}));
 await page.goto('https://fixture.invalid/');
 await page.addStyleTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/console.css',import.meta.url),'utf8')});
 await page.evaluate(event=>{
  document.getElementById('login').hidden=true;document.getElementById('workspace').hidden=false;
  window.account={roles:['Administrator'],authentication:'SSO'};window.$=id=>document.getElementById(id);window.requests=[];window.submissions=[];window.blocked=false;
  window.fixtureEvent=event;window.time=value=>value;window.factor=()=>({});
  window.cell=(row,value)=>{const td=document.createElement('td');td.textContent=value;row.append(td);};
  window.helpDetails=(title,text)=>{const detail=document.createElement('details'),summary=document.createElement('summary'),body=document.createElement('p');summary.textContent=title;body.textContent=text;detail.append(summary,body);return detail;};
  window.guarded=async(button,work,status)=>{try{await work();}catch(error){$(status).textContent=error.message;}};
  window.view=async name=>{for(const section of document.querySelectorAll('.view'))section.hidden=section.id!==name;};
  window.policy={revision:0,mode:'legacy',rules:[],version:1};
  window.api=async(url,body)=>{
   requests.push(url);
   if(url==='/api/v1/console/trust-policy'){
    if(body){submissions.push(structuredClone(body));if(blocked)throw new Error('An applicable Linux sensor has not reported an active qualified kernel source.');policy={revision:policy.revision+1,mode:body.mode,rules:body.rules,version:3};}
    return structuredClone(policy);
   }
   if(url.endsWith('/history')||url==='/api/v1/console/groups')return [];
   if(url==='/api/v1/console/endpoints')return [{endpointId:event.forensics.sensorId,machineName:'Linux qualification sensor',revoked:false}];
   if(url.endsWith('/capabilities'))return [{endpointId:event.forensics.sensorId,machine:'Linux qualification sensor',operatingSystem:'linux',policyVersion:3,linuxKernelTrustVersion:1,reportedUtc:new Date().toISOString()}];
   if(url.endsWith('/endpoints'))return [{endpointId:event.forensics.sensorId,machine:'Linux qualification sensor',status:'Received',reportedUtc:new Date().toISOString()}];
   throw new Error('Unexpected fixture API: '+url);
  };
 },event);
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/trust-policy.js',import.meta.url),'utf8')});
 await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 0'}).waitFor();
 check(await page.getByText('Linux hash-rule readiness',{exact:true}).isVisible(),'source/parser readiness appears alongside receipts');
 await page.getByLabel('Policy mode',{exact:true}).selectOption('enforce');await page.getByRole('button',{name:'Create whitelist',exact:true}).click();
 let rule=page.locator('.trust-rule').last();await rule.getByLabel('Match identity',{exact:true}).selectOption('process');
 await rule.getByLabel('Process matching',{exact:true}).selectOption('linux-task-root-path-sha256-v1');
 await rule.getByLabel('Executable path',{exact:true}).fill('/usr/bin/exact-actor');await rule.getByLabel('SHA-256',{exact:true}).fill('a'.repeat(64));await rule.getByLabel('Enabled',{exact:true}).check();
 check(await rule.getByLabel('Operating system',{exact:true}).inputValue()==='linux'&&await rule.getByLabel('Operating system',{exact:true}).isDisabled(),'native matching explicitly selects and locks Linux');
 check(await rule.getByLabel('Open',{exact:true}).isChecked()&&!await rule.getByLabel('Read',{exact:true}).isChecked()&&await rule.getByLabel('Read',{exact:true}).isDisabled(),'native mode selects Open request without granting read');
 check(await rule.getByLabel('Target file path (optional)',{exact:true}).isDisabled()&&!await rule.getByLabel('Signer',{exact:true}).isVisible()&&await rule.getByLabel('SHA-256',{exact:true}).isVisible(),'unsupported target and signature predicates are constrained while SHA remains editable');
 await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Published.'}).waitFor();
 const body=await page.evaluate(()=>submissions.at(-1));
 check(body.rules.length===1&&body.rules[0].processMatch==='linux-task-root-path-sha256-v1'&&body.rules[0].sha256==='a'.repeat(64)&&body.rules[0].path===null&&body.rules[0].actions.join(',')==='open','manual draft sends explicit path/hash scope and selected action without an event');
 await page.evaluate(()=>document.dispatchEvent(new CustomEvent('whitelist-draft',{detail:{endpointId:fixtureEvent.forensics.sensorId,event:fixtureEvent,activity:{actions:['open-request']}}})));
 await page.locator('#trust-status').filter({hasText:'Draft created'}).waitFor();rule=page.locator('.trust-rule').last();
 check(await rule.getByLabel('Process matching',{exact:true}).inputValue()==='linux-task-root-path-sha256-v1'&&await rule.getByLabel('SHA-256',{exact:true}).inputValue()===event.trust.actor.sha256,'native event draft retains verified hash and explicit matching scope');
 check(await rule.getByLabel('Executable path',{exact:true}).inputValue()===event.trust.actor.executable&&await rule.getByLabel('Target file path (optional)',{exact:true}).inputValue()==='','event draft uses exact actor path and omits unsupported target path');
 check(await rule.getByLabel('User SID or UID',{exact:true}).inputValue()===event.trust.actor.accountId&&await rule.getByLabel('Scope',{exact:true}).inputValue()==='host'&&!await rule.getByLabel('Enabled',{exact:true}).isChecked(),'filesystem UID is retained in a disabled sensor-scoped draft');
 await page.evaluate(()=>blocked=true);await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'not reported an active qualified'}).waitFor();
 check(await page.locator('.trust-rule').count()===2,'publication readiness failure preserves unsaved draft');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1100});
  check(await page.locator('#trust input:visible,#trust select:visible').evaluateAll(nodes=>nodes.every(n=>{const r=n.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth;})),'native rule controls fit viewport '+width);
  await page.screenshot({path:path.join(output,'native-whitelist-'+width+'.png'),fullPage:true});
 }
 check(errors.length===0,'actual changed JavaScript has no runtime errors: '+errors.join('; '));
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({passed:true,checks,errors,submitted:body,scope:'Actual console JavaScript in headless browser with explicit mocked API; backend separately covered by SQLite/client transport checks'},null,2));
 console.log(JSON.stringify({Passed:true,Checks:checks.length,Output:output}));
}catch(error){fs.writeFileSync(path.join(output,'FAILURE.json'),JSON.stringify({error:String(error),checks,errors},null,2));await page.screenshot({path:path.join(output,'failure.png'),fullPage:true});throw error;}finally{await browser.close();}
