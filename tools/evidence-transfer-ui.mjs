import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const output=process.argv[2];assert.ok(output);fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,args:['--disable-gpu'],executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const page=await browser.newPage({viewport:{width:1440,height:1050}}),checks=[],errors=[];
const check=(ok,label)=>{assert.ok(ok,label);checks.push(label);console.log('PASS '+label);};
page.on('pageerror',e=>errors.push(e.message));
try{
 await page.goto('http://127.0.0.1:19325');await page.getByLabel('Username',{exact:true}).fill('ui-qa');await page.getByLabel('Password',{exact:true}).fill('QA-only-long-passphrase-905!');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Alerts',exact:true}).click();
 const row=page.locator('#alert-rows tr[data-event-source="Evidence transfer"]').filter({hasText:'QA-Upload'}).first();await row.waitFor();
 check(await row.getByText('Server receipt recorded; check availability before downloading.',{exact:true}).isVisible(),'received transfer is labelled as a server receipt');
 await row.getByRole('button',{name:'Check server copy',exact:true}).click();await row.getByText(/Server received and verified/).waitFor();
 const link=row.getByRole('link',{name:'Download actor executable evidence',exact:true});await link.waitFor();
 const href=await link.getAttribute('href');const receiptResponse=await page.request.get(new URL(href.slice(0,-'/artifact'.length),page.url()).href);assert.equal(receiptResponse.status(),200);const receipt=await receiptResponse.json();
 check(receipt.state==='received'&&receipt.receiptId.length===32,'UI checks the persisted server receipt before offering a download');
 for(const [kind,label,expected] of [['artifact','Download actor executable evidence',receipt.sha256],['manifest','Download evidence manifest',receipt.manifestSha256]]){
  const waiting=page.waitForEvent('download');await row.getByRole('link',{name:label,exact:true}).click();const download=await waiting;const filename=path.join(output,download.suggestedFilename());await download.saveAs(filename);
  check(createHash('sha256').update(fs.readFileSync(filename)).digest('hex').toUpperCase()===expected,'browser '+kind+' download matches the recorded SHA-256');
 }
 const local=page.locator('#alert-rows tr').filter({hasText:'QA-Windows'}).filter({has:page.getByRole('button',{name:'Check server copy',exact:true})}).first();
 await local.getByRole('button',{name:'Check server copy',exact:true}).click();await local.getByText('Server has not received this evidence. The sensor may still hold a local copy.',{exact:true}).waitFor();
 check(await local.getByRole('link',{name:'Download actor executable evidence',exact:true}).count()===0,'local-only evidence never presents a fabricated central download');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1050});check(await row.getByRole('link',{name:'Download actor executable evidence',exact:true}).isVisible(),'download controls remain visible at '+width+'px');await page.screenshot({path:path.join(output,'transfer-'+width+'.png'),fullPage:true});}
 check(errors.length===0,'evidence transfer UI has no JavaScript errors');
 fs.writeFileSync(path.join(output,'RESULTS.json'),JSON.stringify({checks,errors,receipt,scope:'Real isolated candidate console with synthetic transferred artifact'},null,2));
}finally{await browser.close();}
