// Whole-package UI acceptance against a real isolated server (no mocked assets/APIs).
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const origin=new URL(process.argv[2]||'http://127.0.0.1:19324');
assert.equal(origin.hostname,'127.0.0.1','Only the isolated QA console is allowed');
const output=process.argv[3];assert.ok(output,'Evidence directory is required');fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:["--disable-gpu","--disable-features=CalculateNativeWinOcclusion"],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1100}}),checks=[],errors=[],responded=new WeakSet();let signedIn=false;
const check=(condition,label)=>{assert.ok(condition,label);checks.push(label);console.log('PASS: '+label);};
page.on('pageerror',error=>errors.push(error.message));
page.on('console',message=>{if(message.type()==='error'&&!message.text().startsWith('Failed to load resource:'))errors.push(message.text());});
page.on('response',response=>{responded.add(response.request());if(response.status()>=400&&!(response.status()===401&&!signedIn&&new URL(response.url()).pathname==='/api/v1/auth/me'))errors.push(`${response.status()} ${new URL(response.url()).pathname}`);});
page.on('requestfailed',request=>{if(!responded.has(request))errors.push(request.url()+': '+request.failure()?.errorText);});
try{
 await page.goto(origin.href);
 check(await page.locator('html').getAttribute('data-ui-version')==='0.6.15-dev','served HTML identifies the tested release');
 await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});signedIn=true;
 await page.getByRole('button',{name:'Sensors',exact:true}).click();await page.locator('#fleet').getByText('QA-Windows',{exact:true}).waitFor();
 check((await page.locator('#fleet thead tr:first-child th').allTextContents()).join('|')==='Host|OS|Status|Monitoring|Canary / honeypot files|Version|Last contact|Access','real packaged Sensors renders all eight columns');
 const images=await page.locator('#fleet-rows .os-icon img').evaluateAll(items=>items.map(img=>({src:img.src,loaded:img.complete&&img.naturalWidth>0})));
 check(images.some(x=>x.src.endsWith('/windows.svg')&&x.loaded)&&images.some(x=>x.src.endsWith('/linux.svg')&&x.loaded),'Windows and Linux logo bytes load and decode from the package');
 for(const [host,css,color] of [['QA-Windows','healthy','rgb(20, 123, 67)'],['QA-Attention','warning','rgb(239, 180, 43)'],['QA-Stopped','failed','rgb(189, 41, 57)'],['QA-Unknown','unknown','rgb(100, 116, 135)']]){
  const row=page.locator('#fleet-rows tr').filter({hasText:host});const icon=row.locator('.status-'+css);
  check(await icon.evaluate(el=>getComputedStyle(el).color)===color,host+' has a visible bubble of the correct color');
 }
 check(await page.locator('#fleet .status-legend').count()===1,'status legend appears exactly once');
 for(const width of [1440,768,390]){
  await page.setViewportSize({width,height:1000});
  await page.getByLabel('Filter Host',{exact:true}).fill('QA-Windows');
  const bounds=await page.locator('#fleet-rows tr').first().locator('[data-label="OS"], [data-label="Status"]').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:innerWidth};}));
  check(bounds.length===2&&bounds.every(r=>r.left>=0&&r.right<=r.width),`OS and status fit at ${width}px`);
  await page.screenshot({path:path.join(output,`sensors-${width}.png`),fullPage:true});
  await page.getByRole('button',{name:'Alerts',exact:true}).click();await page.locator('#alert-rows tr').first().waitFor();
  const baseEvents=page.locator('#alert-rows tr').filter({has:page.locator('[data-label="Host"]').filter({hasText:/^QA-(Windows|Linux|Attention|Unknown|Stopped)$/})});
  check(await baseEvents.count()===6,'all six complete and incomplete base fixture events remain visible at '+width+'px');
  check(await baseEvents.locator('.actor-evidence').count()===6,'one evidence summary per base event at '+width+'px');
  check(await page.locator('#alert-rows [data-actor-evidence="Unavailable"]').count()===1,'unattributed notification is retained and labelled at '+width+'px');
  const windows=page.locator('#alert-rows tr').filter({hasText:'QA-Windows'});
  check((await windows.locator('[data-label="User"]').textContent())==='QA\\alex'&&(await windows.locator('[data-label="PID"]').textContent())==='4242'&&(await windows.locator('[data-label="Process"]').textContent()).endsWith('powershell.exe'),'Windows actor fields are visible values at '+width+'px');
  if(width<=1100){const actors=await windows.locator('[data-label="User"],[data-label="Process"],[data-label="PID"]').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,width:innerWidth,display:getComputedStyle(el).display};}));check(actors.every(r=>r.left>=0&&r.right<=r.width&&r.display!=='none'),'all actor fields fit without horizontal scrolling at '+width+'px');}
  await page.screenshot({path:path.join(output,`history-${width}.png`),fullPage:true});
  await page.getByRole('button',{name:'Sensors',exact:true}).click();await page.locator('#fleet').getByText('QA-Windows',{exact:true}).waitFor();
 }
 await page.setViewportSize({width:1440,height:1000});
 const names=await page.locator('nav button:visible').allTextContents();
 for(const name of names){await page.getByRole('button',{name,exact:true}).first().click();await page.waitForLoadState('networkidle');check(await page.locator('main .view:visible').count()===1,'navigation loads exactly one screen: '+name);check((await page.locator('#page-title').innerText()).trim().length>0,'page heading remains present: '+name);}
 check(errors.length===0,'all console modules run together without JavaScript or resource errors: '+errors.join('; '));
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({origin:origin.href,version:'0.6.15-dev',checks,errors,scope:'Real isolated packaged server; synthetic database, not production login'},null,2));
 console.log(`PASS: ${checks.length} whole-package UI checks`);
}finally{await browser.close();}
