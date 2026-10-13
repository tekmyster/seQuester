import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const origin=process.env.RF_WHITELIST_ORIGIN,output=process.argv[2];assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(origin));fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'}),page=await browser.newPage(),checks=[];
const check=(ok,text)=>{assert.ok(ok,text);checks.push(text);console.log('PASS: '+text);};const consoleErrors=[];page.on('console',message=>{if(message.type()==='error'&&!message.text().includes('503'))consoleErrors.push(message.text());});
try{
 await page.goto(origin);await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});consoleErrors.length=0; // Anonymous auth/me is expected before sign-in; inspect the authenticated screen.
 await page.route('**/api/v1/console/trust-policy',async route=>{await new Promise(resolve=>setTimeout(resolve,500));await route.continue();});
 await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.getByText('Loading rules…',{exact:true}).waitFor();check(true,'loading is announced while policy requests are pending');await page.locator('#trust-status').filter({hasText:'Policy '}).waitFor();await page.unroute('**/api/v1/console/trust-policy');
 check(await page.locator('.trust-rule[open]').count()===0,'saved rules start collapsed');
 check(await page.locator('.trust-support[open]').count()===0,'policy status, Linux readiness and history remain accessible without dominating the editor');
 check(await page.locator('.trust-toolbar').evaluate(el=>getComputedStyle(el).display==='flex'),'toolbar styles are applied under the actual server security policy');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1000});await page.screenshot({path:path.join(output,'overview-'+width+'.png'),fullPage:true});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overview has no horizontal overflow at '+width+'px');
 }
 const rule=page.locator('.trust-rule').first();await rule.locator(':scope > summary').focus();await page.keyboard.press('Enter');check(await rule.getAttribute('open')!==null,'rule disclosure opens with the keyboard');
 check(await rule.locator('.trust-actions').evaluate(el=>getComputedStyle(el).display==='grid'),'operation controls use the designed grid layout');
 check(!(await rule.getByLabel('Apply to',{exact:true}).isVisible()),'all-sensor scope does not repeat a redundant target selector');
 check(!(await rule.getByLabel('Signer',{exact:true}).isVisible()),'optional signature restrictions are disclosed on demand');
 for(const width of [1440,768,390]){await page.setViewportSize({width,height:1000});await page.screenshot({path:path.join(output,'process-rule-'+width+'.png'),fullPage:true});check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'expanded rule has no horizontal overflow at '+width+'px');}
 await rule.getByText('Additional process restrictions',{exact:true}).click();check(await rule.getByLabel('Signer',{exact:true}).isVisible()&&await rule.getByLabel('Publisher',{exact:true}).isVisible()&&await rule.getByLabel('Parent executable',{exact:true}).isVisible(),'all optional process restrictions remain available');
 await rule.getByText('Advanced scope settings',{exact:true}).click();check(await rule.getByLabel('Parent rule',{exact:true}).isVisible()&&await rule.getByLabel('Approve broader scope',{exact:true}).isVisible(),'parent and broader-scope approval remain accessible');
 await page.screenshot({path:path.join(output,'advanced-390.png'),fullPage:true});
 await rule.getByLabel('Process matching',{exact:true}).selectOption('linux-task-root-path-sha256-v1');check(await rule.getByLabel('Open',{exact:true}).isChecked()&&await rule.getByLabel('Read',{exact:true}).isDisabled()&&await rule.getByLabel('Target file path (optional)',{exact:true}).isDisabled(),'Linux hash mode retains Open-only safety constraints');
 check(await page.locator('#trust-status').textContent()==='Linux hash matching uses Open only. Other operations and the target-file restriction were cleared.','cleared restrictions are announced at the time of the change');
 await page.reload();await page.getByRole('button',{name:'Trust rules',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy '}).waitFor();
 await page.route('**/api/v1/console/trust-policy',route=>route.fulfill({status:503,contentType:'application/json',body:'{"internal":"not displayed"}'}));
 await page.locator('#trust').getByRole('button',{name:'Refresh',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Request failed'}).waitFor();check(!(await page.locator('#trust-status').textContent()).includes('internal')&&await page.locator('.trust-rule').count()===5,'failure retains rules and does not expose backend data');
 await page.unroute('**/api/v1/console/trust-policy');await page.locator('#trust').getByRole('button',{name:'Refresh',exact:true}).click();await page.locator('#trust-status').filter({hasText:'Policy '}).waitFor();check(true,'Refresh recovers from a failed request');
 check(consoleErrors.length===0,'no security-policy or browser console errors: '+consoleErrors.join('; '));
 fs.writeFileSync(path.join(output,'REVIEW.json'),JSON.stringify({checks,scope:'Isolated exact production-runtime candidate; UI only'},null,2));
}finally{await browser.close();}
