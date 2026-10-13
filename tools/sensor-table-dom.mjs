import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const browser=await chromium.launch({headless:true,args:["--disable-gpu","--disable-features=CalculateNativeWinOcclusion"],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage();let count=0;const check=(value,label)=>{assert.ok(value,label);console.log('PASS: '+label);count++;};
try{
 await page.clock.install();
 const now=Date.now(),fresh=new Date(now-30000).toISOString(),stale=new Date(now-600000).toISOString(),items=[
  {endpointId:'a',machineName:'win-one',agentVersion:'1.0',health:'User/process attribution active',lastSeenUtc:fresh,revoked:false,operatingSystem:'windows',protection:{monitoringState:'active',deployedCanaryAndHoneypotFiles:3}},
  {endpointId:'b',machineName:'linux-policy',agentVersion:'1.1',health:'Policy pending: TaskCanceledException | User/process attribution active | Trust policy pending · Automatic response paused',lastSeenUtc:fresh,revoked:false,operatingSystem:'linux',protection:{monitoringState:'active',deployedCanaryAndHoneypotFiles:2}},
  {endpointId:'c',machineName:'mac-offline',agentVersion:'1.2',health:'Monitoring',lastSeenUtc:stale,revoked:false,operatingSystem:'macos',protection:{monitoringState:'active',deployedCanaryAndHoneypotFiles:1}},
  {endpointId:'d',machineName:'legacy',agentVersion:'0.9',health:'Monitoring',lastSeenUtc:fresh,revoked:false,operatingSystem:null,protection:null},
  {endpointId:'e',machineName:'stopped',agentVersion:'1.0',health:'Monitoring stopped',lastSeenUtc:fresh,revoked:false,operatingSystem:'linux',protection:{monitoringState:'stopped',deployedCanaryAndHoneypotFiles:2}}
 ];
 let endpointItems=items,endpointStatus=200,endpointHang=false;
 await page.route('**/*',async route=>{const url=new URL(route.request().url());if(url.pathname==='/api/v1/auth/me')return route.fulfill({json:{userName:'reader',roles:['Reader'],authentication:'Local',mustChangePassword:false,mustEnrollMfa:false,mfaEnabled:false,mfaRequired:false}});if(url.pathname==='/api/v1/console/overview')return route.fulfill({json:{asOfUtc:fresh,protectionReportingClients:0,protectionActiveClients:0,protectionNeedsAttentionClients:0,nonWhitelistedAlerts:0,informationalActivity:0}});if(url.pathname==='/api/v1/console/endpoints'){if(endpointHang)return;return route.fulfill({status:endpointStatus,json:endpointStatus===200?endpointItems:{}});}return route.abort();});
 const html=fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/index.html',import.meta.url),'utf8').replace('<head>','<head><base href="https://fixture.invalid/">');await page.setContent(html);
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/presentation.js',import.meta.url),'utf8')});
 await page.evaluate(()=>{window.EventHistory={load:async()=>{},next:async()=>{},previous:async()=>{}};});
 await page.addScriptTag({content:fs.readFileSync(new URL('../src/RansomFree.Server/wwwroot/console.js',import.meta.url),'utf8')});
 await page.getByRole('button',{name:'Sensors'}).click();await page.getByText('win-one',{exact:true}).waitFor();
 const headers=await page.locator('#fleet thead tr:first-child th').allTextContents();check(headers.join('|')==='Host|OS|Status|Monitoring|Canary / honeypot files|Version|Last contact|Access','Sensors columns cover every requested field');
 const statuses=await page.locator('#fleet-rows .sensor-status-label').allTextContents();check(statuses.includes('Monitoring')&&statuses.includes('Needs attention')&&statuses.includes('Offline')&&statuses.includes('Status unavailable')&&statuses.includes('Monitoring stopped'),'simple green/yellow/red status labels are rendered');
 const policyRow=page.locator('#fleet-rows tr',{hasText:'linux-policy'});check((await policyRow.innerText()).includes('Needs attention')&&!(await policyRow.innerText()).includes('TaskCanceledException'),'raw exception is absent from the main Sensors row');
 const policyIcon=policyRow.locator('.status-warning');check((await policyIcon.getAttribute('aria-label'))==='Needs attention. Monitoring and alerts are working. The latest policy has not arrived, so automatic blocking is paused.','friendly policy detail is available to keyboard and screen-reader users');
 check(await policyRow.getByText('Technical details',{exact:true}).count()===1,'raw health is retained under expandable Technical details');
 const osText=await page.locator('#fleet-rows .os-name').allTextContents();check(['Windows','Linux','macOS','Unknown OS'].every(value=>osText.includes(value)),'local OS logos include accessible Windows, Linux, macOS and Unknown labels');
 await page.getByLabel('Filter OS').selectOption('Linux');await page.getByLabel('Filter Host').fill('policy');check(await page.locator('#fleet-rows tr').count()===1&&(await page.locator('#sensor-filter-status').textContent())==='2 filters active','per-column Sensors filters combine with an active indicator');
 await page.getByRole('button',{name:'Clear all'}).first().click();check(await page.locator('#fleet-rows tr').count()===5&&(await page.locator('#sensor-filter-status').textContent())==='No filters','Sensors Clear all restores every row');
 await page.getByRole('button',{name:'Host'}).click();check((await page.locator('#fleet thead tr:first-child th').first().getAttribute('aria-sort'))==='ascending','Sensor header exposes ascending sort state');await page.getByRole('button',{name:/Host/}).click();check((await page.locator('#fleet thead tr:first-child th').first().getAttribute('aria-sort'))==='descending','Sensor header cycles to descending sort state');
 endpointItems=items.map(item=>item.endpointId==='c'?{...item,lastSeenUtc:new Date().toISOString()}:item);
 await page.evaluate(()=>refreshFleetInBackground());
 check((await page.locator('#fleet-rows tr',{hasText:'mac-offline'}).innerText()).includes('Monitoring'),'background refresh replaces a stale row with a current server report');
 endpointStatus=503;await page.evaluate(()=>refreshFleetInBackground());
 check(await page.locator('#fleet-rows tr').count()===0&&(await page.locator('#fleet-empty').innerText()).includes('Current sensor status is unavailable'),'failed refresh removes stale health labels rather than marking the fleet offline');
 endpointStatus=200;await page.evaluate(()=>refreshFleetInBackground());
 check(await page.locator('#fleet-rows tr').count()===5,'background refresh restores sensor rows when the server responds again');
 endpointItems=items.map(item=>item.endpointId==='a'?{...item,lastSeenUtc:stale}:item);
 await page.clock.fastForward(30001);
 await page.locator('#fleet-rows tr',{hasText:'win-one'}).getByText('Offline',{exact:true}).waitFor();
 check(true,'scheduled refresh replaces the sensor status without a manual click');
 endpointItems=items;
 await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
 await page.locator('#fleet-rows tr',{hasText:'win-one'}).getByText('Monitoring',{exact:true}).waitFor();
 check(true,'returning to the Sensors page refreshes status immediately');
 endpointHang=true;
 await page.evaluate(()=>{window.pendingFleetRefresh=refreshFleetInBackground();});
 await page.clock.fastForward(15001);await page.evaluate(()=>window.pendingFleetRefresh);
 check(await page.locator('#fleet-rows tr').count()===0&&(await page.locator('#fleet-empty').innerText()).includes('Current sensor status is unavailable'),'hung status request times out and removes stale green labels');
 endpointHang=false;endpointItems=items;
 await page.evaluate(()=>refreshFleetInBackground());
 check(await page.locator('#fleet-rows tr').count()===5,'status polling recovers after a hung request');
 endpointHang=true;
 await page.evaluate(()=>{window.pendingFleetRefresh=refreshFleetInBackground();showLogin();});
 await page.clock.fastForward(15001);await page.evaluate(()=>window.pendingFleetRefresh);
 check(await page.locator('#login').isVisible()&&await page.locator('#fleet-rows tr').count()===0,'expired session is not repopulated by a timed-out request');
 endpointHang=false;
 await page.evaluate(()=>enter());await page.getByRole('button',{name:'Sensors'}).click();
 await page.evaluate(()=>loadFleet());
 endpointStatus=401;await page.evaluate(()=>refreshFleetInBackground());
 check(await page.locator('#login').isVisible()&&await page.locator('#fleet-rows tr').count()===0,'expired session clears sensor rows and shows sign-in');
 check(await page.locator('#fleet .status-legend').count()===1,'exactly one status legend remains visible');
 console.log(`PASS: ${count} Sensors DOM cases. Offline fixture; no live server contacted.`);
}finally{await browser.close();}
