import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const origin=process.env.RF_WHITELIST_ORIGIN||'http://127.0.0.1:19325',output=process.argv[2],state=process.argv[3];
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin),'QA is restricted to an isolated loopback server');
assert.ok(output&&state,'Output and isolated state are required');fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:["--disable-gpu","--disable-features=CalculateNativeWinOcclusion"],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS: '+label);};
page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 0'}).waitFor();
 check(await page.getByLabel('Policy mode',{exact:true}).inputValue()==='legacy'&&await page.getByRole('button',{name:'Create whitelist',exact:true}).isVisible(),'manual creation is available before any event or scoped policy exists');
 for(const os of ['windows','linux']){
  await page.getByRole('button',{name:'Create whitelist',exact:true}).click();const rule=page.locator('.trust-rule').last();
  check(await page.getByLabel('Policy mode',{exact:true}).inputValue()==='enforce'&&!(await rule.getByLabel('Enabled',{exact:true}).isChecked()),'manual '+os+' creation prepares a disabled scoped draft without an event');
  await rule.getByLabel('Rule name',{exact:true}).fill('QA '+os+' reader');await rule.getByLabel('Enabled',{exact:true}).check();
  await rule.getByLabel('Match identity',{exact:true}).selectOption('process');
  check(await rule.getByLabel('Process matching',{exact:true}).inputValue()==='','new '+os+' process draft defaults to binary verification, never path-only trust');
  check(await rule.getByLabel('SHA-256',{exact:true}).evaluate(el=>el.required&&!el.checkValidity()),os+' verified process mode requires a hash before publication');
  await rule.getByLabel('SHA-256',{exact:true}).fill('invalid-hash');await rule.getByLabel('Process matching',{exact:true}).selectOption('event-path');
  check(await rule.getByLabel('SHA-256',{exact:true}).evaluate(el=>el.disabled&&el.checkValidity()),os+' explicitly switching to path-only disables hidden stale-hash validation');
  await rule.getByLabel('Process matching',{exact:true}).selectOption('');
  check(await rule.getByLabel('SHA-256',{exact:true}).evaluate(el=>!el.disabled&&!el.checkValidity()),os+' switching back to verified matching rejects the invalid hash');
  if(os==='windows')await rule.getByLabel('SHA-256',{exact:true}).fill('a'.repeat(64));
  else {await rule.getByLabel('SHA-256',{exact:true}).fill('');await rule.getByLabel('Process matching',{exact:true}).selectOption('event-path');}
  await rule.getByLabel('Executable path',{exact:true}).fill(os==='windows'?'C:\\QA\\Reader.exe':'/usr/bin/qa-reader');
  await rule.getByLabel('Operating system',{exact:true}).selectOption(os);
  check(await rule.getByLabel('Read',{exact:true}).isChecked()&&!(await rule.getByLabel('Write',{exact:true}).isChecked()),os+' rule selects read without allowing write');
  check(await rule.getByLabel('When matched',{exact:true}).inputValue()==='log-only',os+' rule selects actual log-only behavior');
  await rule.getByRole('button',{name:'Edit',exact:true}).click();
  check(await rule.getByLabel('Write',{exact:true}).isChecked()&&await rule.getByLabel('Append',{exact:true}).isChecked()&&await rule.getByLabel('Truncate',{exact:true}).isChecked()&&!(await rule.getByLabel('Delete',{exact:true}).isChecked())&&!(await rule.getByLabel('Permissions',{exact:true}).isChecked()),os+' Edit selects precisely write/append/truncate, never delete or permissions');
  await rule.getByRole('button',{name:'Read only',exact:true}).click();
 }
 await page.getByRole('button',{name:'Create alert rule',exact:true}).click();const alertRule=page.locator('.trust-rule').last();
 check(!(await alertRule.getByLabel('Enabled',{exact:true}).isChecked())&&await alertRule.getByLabel('When matched',{exact:true}).inputValue()==='normal','always-alert creation starts as a disabled draft with explicit precedence');
 await alertRule.getByLabel('Rule name',{exact:true}).fill('QA explicit alert');await alertRule.getByLabel('Match identity',{exact:true}).selectOption('process');await alertRule.getByLabel('Enabled',{exact:true}).check();
 await alertRule.getByLabel('Executable path',{exact:true}).fill('C:\\QA\\Reader.exe');await alertRule.getByLabel('SHA-256',{exact:true}).fill('a'.repeat(64));await alertRule.getByLabel('Operating system',{exact:true}).selectOption('windows');await alertRule.getByLabel('Target file path (optional)',{exact:true}).fill('C:\\QA\\block-override.txt');
 check(await alertRule.getByLabel('Domain or sensor ID',{exact:true}).evaluate(el=>!el.required),'hidden account fields cannot block process-only publication');
 for(const subject of ['account','account-and-process']){
  await page.getByRole('button',{name:'Create whitelist',exact:true}).click();const rule=page.locator('.trust-rule').last();
  await rule.getByLabel('Rule name',{exact:true}).fill('QA manual '+subject);await rule.getByLabel('Enabled',{exact:true}).check();await rule.getByLabel('Match identity',{exact:true}).selectOption(subject);
  await rule.getByLabel('User identifier type',{exact:true}).selectOption('sid');await rule.getByLabel('Domain or sensor ID',{exact:true}).fill('QA');await rule.getByLabel('User SID or UID',{exact:true}).fill('S-1-5-21-1-2-3-1000');await rule.getByLabel('Operating system',{exact:true}).selectOption('windows');
  await rule.getByLabel('Target file path (optional)',{exact:true}).fill(subject==='account'?'C:\\QA\\only-user.txt':'C:\\QA\\only-both.txt');
  if(subject==='account-and-process'){await rule.getByLabel('Executable path',{exact:true}).fill('C:\\QA\\Both.exe');await rule.getByLabel('SHA-256',{exact:true}).fill('c'.repeat(64));}
  check(await rule.getByLabel('Read',{exact:true}).isChecked()&&await rule.getByLabel('When matched',{exact:true}).inputValue()==='log-only','manual '+subject+' rule selects read and log only without an event');
 }
 await page.locator('#trust').getByLabel('Administrator password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Published.'}).waitFor();
 let policy=await page.evaluate(()=>fetch('/api/v1/console/trust-policy').then(r=>r.json()));
 check(policy.version===2&&policy.rules.length===5&&policy.rules.filter(r=>r.disposition==='log-only').length===4&&policy.rules.every(r=>r.actions.join(',')==='read')&&policy.rules.find(r=>r.operatingSystem==='windows'&&r.subject==='process').sha256==='a'.repeat(64)&&policy.rules.find(r=>r.operatingSystem==='linux').processMatch==='event-path','authenticated publication persists verified Windows hash, user/AND rules, and explicit always-alert rule');
 check(policy.rules.find(r=>r.subject==='account').executable===null&&policy.rules.find(r=>r.subject==='account-and-process').sha256==='c'.repeat(64)&&policy.rules.filter(r=>r.subject==='process').every(r=>r.accountId===null&&r.authority===null),'manual user, process and AND rules persist only their selected identity predicates');
 check((await page.evaluate(()=>fetch('/api/v1/console/event-history?limit=100').then(r=>r.json()))).items.length===0,'rules are published and persisted without an existing event');
 await page.reload();await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('.trust-rule').first().waitFor();
 for(const rule of await page.locator('.trust-rule').all())await rule.locator(':scope > summary').click();
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1000});const bounds=await page.locator('#trust input:visible,#trust select:visible').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:innerWidth};}));
  check(bounds.every(r=>r.left>=0&&r.right<=r.width),'whitelist inputs fit at '+width+'px');await page.screenshot({path:path.join(output,'whitelists-'+width+'.png'),fullPage:true});
 }
 execFileSync('C:/Program Files/dotnet/dotnet.exe',[process.env.RF_WHITELIST_FIXTURE||'D:/Codex/RansomFree/whitelist-20260924/artifacts/bin/WhitelistFixture/release/WhitelistFixture.dll','--ui-seed',state],{encoding:'utf8',stdio:'pipe'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
 check(await page.getByText('Log only · Alerts suppressed',{exact:true}).count()===2,'Windows and Linux allowed reads are visibly labelled log only');
 const rows=await page.evaluate(()=>fetch('/api/v1/console/event-history?host=Whitelist-&limit=100').then(r=>r.json()));
 check(rows.items.length===7&&rows.items.filter(x=>x.trustClassification==='LogOnly').length===2&&rows.items.filter(x=>x.trustClassification==='NonWhitelisted').length===5,'history retains allowed reads and alerts for writes and same-path wrong/missing hashes');
 const overridden=rows.items.find(x=>x.event.path==='C:\\QA\\block-override.txt');check(overridden?.trustClassification==='NonWhitelisted'&&overridden.event.trust.result.decision.matchedRules.length===2,'server and history preserve both matching rules while always-alert wins');
 check(rows.items.every(x=>x.event.user&&x.event.process&&x.event.processId===4242),'logged-only and alerting entries retain User, Process and PID');
 await page.screenshot({path:path.join(output,'whitelist-history-390.png'),fullPage:true});
 await page.getByRole('button',{name:'Create whitelist',exact:true}).first().click();await page.locator('#trust-status').filter({hasText:'Draft created'}).waitFor();
 const draft=page.locator('.trust-rule').last();check(await draft.getByLabel('Scope',{exact:true}).inputValue()==='host'&&!(await draft.getByLabel('Enabled',{exact:true}).isChecked()),'event-derived whitelist is an unactivated draft bound to its sensor');
 check((await draft.getByLabel('Executable path',{exact:true}).inputValue()).length>0,'event-derived draft preserves actual process identity');
 check(errors.length===0,'changed UI executes without JavaScript errors: '+errors.join('; '));
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({checks,errors,policy,events:rows.items,scope:'Real isolated packaged server with synthetic Windows/Linux native event records'},null,2));
 console.log('PASS: '+checks.length+' packaged whitelist UI checks');
}finally{await browser.close();}
