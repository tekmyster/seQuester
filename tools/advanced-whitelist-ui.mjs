import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const origin=process.env.RF_WHITELIST_ORIGIN,output=process.argv[2];
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'}),page=await browser.newPage(),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS: '+label);};page.on('pageerror',error=>errors.push(error.message));
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 0'}).waitFor();
 await page.getByRole('button',{name:'Create whitelist',exact:true}).click();const rule=page.locator('.trust-rule').last();
 await rule.getByLabel('Match identity',{exact:true}).selectOption('account-or-process');
 check(await rule.getByRole('group',{name:'User',exact:true}).isVisible()&&await rule.getByRole('group',{name:'Process',exact:true}).isVisible(),'User or process exposes both identities');
 await rule.getByLabel('User identifier type',{exact:true}).selectOption('sid');await rule.getByLabel('User context',{exact:true}).selectOption('effective-user');await rule.getByLabel('User SID or UID',{exact:true}).fill('S-1-5-21-1-2-3-1000');await rule.getByLabel('User SID or UID',{exact:true}).dispatchEvent('change');
 check(await rule.getByLabel('Domain or sensor ID',{exact:true}).inputValue()==='sid-domain:S-1-5-21-1-2-3'&&await rule.getByLabel('Domain or sensor ID',{exact:true}).evaluate(el=>el.readOnly),'effective Windows user derives stable SID authority');
 await rule.getByLabel('Process matching',{exact:true}).selectOption('linux-native-operation-sha256-v1');
 check(await rule.getByLabel('SHA-256',{exact:true}).isVisible()&&await rule.getByLabel('SHA-256',{exact:true}).evaluate(el=>el.required),'Linux native matching requires executable SHA-256');
 check(await rule.getByLabel('Write',{exact:true}).isEnabled()&&await rule.getByLabel('Append',{exact:true}).isEnabled()&&await rule.getByLabel('Delete',{exact:true}).isDisabled(),'Linux native mode exposes only qualified operations');
 check(!(await rule.getByLabel('Executable path',{exact:true}).isVisible()),'hash-only Linux mode does not request an unsupported actor path');
 await rule.getByLabel('Match identity',{exact:true}).selectOption('process');await rule.getByLabel('Process matching',{exact:true}).selectOption('');
 check(!(await rule.getByText('Read, Write and Append only.',{exact:true}).isVisible())&&!(await page.locator('#trust-status').textContent()).includes('Linux executable'),'Linux matching notice is scoped to its rule and disappears for Windows matching');
 await rule.getByLabel('Operating system',{exact:true}).selectOption('windows');
 await rule.getByLabel('Executable path',{exact:true}).fill('C:\\QA\\Reader.exe');await rule.getByLabel('SHA-256',{exact:true}).fill('A'.repeat(64));
 await rule.getByLabel('Target scope',{exact:true}).selectOption('directory');
 check(await rule.getByLabel('Target directory',{exact:true}).evaluate(el=>el.required),'directory scope labels its required target directory accurately');
 await rule.getByLabel('Target directory',{exact:true}).fill('C:\\QA\\Protected');
 await rule.getByText('Temporary process rule',{exact:true}).click();await rule.getByLabel('Limit to process',{exact:true}).check();
 check(await rule.getByLabel('PID',{exact:true}).isEnabled()&&await rule.getByLabel('Process start key',{exact:true}).evaluate(el=>el.required),'temporary process exception requires process-lifetime evidence');
 check(await rule.getByLabel('Scope',{exact:true}).isDisabled()&&await rule.getByLabel('Scope',{exact:true}).inputValue()==='host','temporary rule locks scope to one sensor');
 await rule.getByLabel('Limit to process',{exact:true}).uncheck();
 check(await rule.getByLabel('Expires (local time)',{exact:true}).getAttribute('max')===null,'removing temporary selector removes its expiration cap');
 await rule.getByLabel('Scope',{exact:true}).selectOption('organization');await rule.getByLabel('Rule name',{exact:true}).fill('Directory reader');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await page.screenshot({path:path.join(output,'advanced-'+width+'.png'),fullPage:true});check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'advanced whitelist has no page overflow at '+width+'px');}
 await page.locator('#trust').getByLabel('Administrator password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Publish policy',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Published.'}).waitFor();
 await page.reload();await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 1'}).waitFor();
 const saved=page.locator('.trust-rule').first();await saved.locator(':scope > summary').click();
 check(await saved.getByLabel('Target scope',{exact:true}).inputValue()==='directory'&&await saved.getByLabel('Target directory',{exact:true}).inputValue()==='C:\\QA\\Protected','directory and path survive actual server publication and reload');
 check(!await saved.getByLabel('Enabled',{exact:true}).isChecked(),'draft remains disabled after publication');
 await page.route('**/api/v1/console/trust-policy/capabilities',route=>route.fulfill({contentType:'application/json',body:JSON.stringify([
  {machine:'Windows QA',operatingSystem:'windows',policyVersion:4,reportedUtc:new Date().toISOString()},
  {machine:'Linux ready QA',operatingSystem:'linux',policyVersion:4,linuxNativeHashTrustVersion:1,linuxNativeHashReportedUtc:new Date().toISOString(),reportedUtc:new Date().toISOString()},
  {machine:'Linux stale QA',operatingSystem:'linux',policyVersion:4,linuxNativeHashTrustVersion:1,linuxNativeHashReportedUtc:new Date(Date.now()-300000).toISOString(),reportedUtc:new Date().toISOString()}
 ])}));
 await page.locator('#trust').getByRole('button',{name:'Refresh',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy 1'}).waitFor();
 await page.getByText('Linux hash-rule readiness',{exact:true}).click();const readiness=page.locator('.trust-support').filter({has:page.getByText('Linux hash-rule readiness',{exact:true})});
 check((await readiness.locator('tr').filter({hasText:'Linux ready QA'}).textContent()).includes('Reported active'),'readiness distinguishes current native hash source');
 check((await readiness.locator('tr').filter({hasText:'Linux stale QA'}).textContent()).includes('Report expired'),'readiness never displays an expired source as active');
 await page.screenshot({path:path.join(output,'readiness-390.png'),fullPage:true});check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'populated readiness table stays within the mobile page');
 await page.unroute('**/api/v1/console/trust-policy/capabilities');
 await page.getByRole('button',{name:'Notifications',exact:true}).click();const syslog=page.locator('#notifications form').filter({has:page.getByRole('heading',{name:'Server syslog / Wazuh',exact:true})});
 await syslog.getByText('Collector verification',{exact:true}).click();await syslog.getByLabel('Collector host',{exact:true}).fill('127.0.0.1');await syslog.getByLabel('Transport',{exact:true}).selectOption('TLS');await syslog.getByLabel('TLS certificate SHA-256',{exact:true}).fill('B'.repeat(64));await syslog.getByLabel('Confirm storage',{exact:true}).check();
 check(!await syslog.getByLabel('Enable server syslog',{exact:true}).isChecked(),'collector verification can be prepared without enabling delivery');
 await syslog.getByLabel('Administrator password',{exact:true}).fill('QA-only-long-passphrase-905!');await syslog.getByRole('button',{name:'Save server syslog',exact:true}).click();await page.locator('#notification-notice').filter({hasText:'Server syslog saved.'}).waitFor();
 await page.reload();await page.getByRole('button',{name:'Notifications',exact:true}).click();await page.waitForFunction(()=>Array.from(document.querySelectorAll('#notifications input')).some(input=>input.value==='127.0.0.1'));
 await syslog.getByText('Collector verification',{exact:true}).click();
 check(await syslog.getByLabel('TLS certificate SHA-256',{exact:true}).inputValue()==='B'.repeat(64)&&await syslog.getByLabel('Confirm storage',{exact:true}).isChecked(),'certificate pin and storage receipts survive server save and reload');
 await syslog.getByLabel('Transport',{exact:true}).selectOption('UDP');
 check(!await syslog.getByLabel('Confirm storage',{exact:true}).evaluate(el=>el.checkValidity()),'unsupported UDP storage confirmation prevents submission');
 await syslog.getByLabel('Transport',{exact:true}).selectOption('TLS');
 await page.screenshot({path:path.join(output,'collector-verification-390.png'),fullPage:true});
 check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'collector verification has no mobile page overflow');
 check(errors.length===0,'no browser execution errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({passed:true,checks,scope:'Isolated authenticated server, persisted directory rule and advanced authoring. Native execution and deployment are separate.'},null,2));
}finally{await browser.close();}
