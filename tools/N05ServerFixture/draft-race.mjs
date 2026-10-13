import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.N05_PLAYWRIGHT || 'C:/Users/dmessana/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const source=process.env.N05_SOURCE || new URL('../../src/seQuester.Server/wwwroot/decoy-services.js',import.meta.url);
const output=process.env.N05_EVIDENCE || 'D:/Codex/RansomFree/W-SQ05';
fs.mkdirSync(output,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.N05_CHROMIUM || 'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
let count=0;
try {
 for(const operation of ['save','create','retire']) for(const transition of ['selection','new','same','return','view','session','unchanged']) {
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
  await page.route('**/*',r=>r.abort());await page.setContent('<div id="callbacks"></div>');
  await page.evaluate(()=>{
   if(!crypto.randomUUID)crypto.randomUUID=()=> '00000000-0000-4000-8000-000000000001';
   window.account={roles:['Administrator'],authentication:'Local'};window.helpDetails=()=>document.createElement('details');window.time=x=>x;
   window.cell=(r,t)=>{const td=document.createElement('td');td.textContent=t;r.append(td);};window.factor=()=>({});
   window.guarded=async(b,f)=>{b.disabled=true;try{await f();}catch(e){window.failure=String(e);}finally{b.disabled=false;}};
   window.services=[{id:'a',name:'Alpha',revision:1},{id:'b',name:'Beta',revision:1}];window.requests=[];
   window.api=async(path,body)=>{if(body){requests.push({path,body});return new Promise(resolve=>window.resolveResponse=resolve);}return path.endsWith('/hits')?[]:services;};
  });
  await page.addScriptTag({content:fs.readFileSync(source,'utf8')});
  await page.evaluate(()=>document.dispatchEvent(new CustomEvent('view-changed',{detail:'callbacks'})));
  if(operation!=='create')await page.getByRole('button',{name:'Alpha · Disabled'}).click();
  await page.getByLabel('Name',{exact:true}).fill('Alpha saved');await page.getByLabel('Administrator password',{exact:true}).fill('fixture');
  await page.getByRole('button',{name:operation==='retire'?'Retire service':operation==='create'?'Create disabled service':'Save service',exact:true}).click();
  assert.equal(await page.evaluate(()=>requests.length),1);
  if(transition==='selection'||transition==='return')await page.getByRole('button',{name:'Beta · Disabled'}).click();
  if(transition==='return'){
   if(operation==='create')await page.getByRole('button',{name:'New service',exact:true}).click();
   else await page.getByRole('button',{name:'Alpha · Disabled'}).click();
  }
  if(transition==='new')await page.getByRole('button',{name:'New service',exact:true}).click();
  if(transition==='view')await page.evaluate(()=>document.dispatchEvent(new CustomEvent('view-changed',{detail:'alerts'})));
  if(transition==='session')await page.evaluate(()=>document.dispatchEvent(new Event('session-cleared')));
  if(transition!=='unchanged'){
   await page.getByLabel('Name',{exact:true}).fill(transition==='selection'?'Beta unsaved work':'Pending draft');
   await page.getByLabel('Note',{exact:true}).fill('Preserve this note');
   await page.getByLabel('Administrator password',{exact:true}).fill('next credentials');
  }
  await page.evaluate(op=>resolveResponse(op==='create'?{service:{id:'created',name:'Alpha saved',revision:1},activationPath:'/decoy-api/synthetic/secret'}:{id:'a',name:'Alpha saved',revision:2,retired:op==='retire'}),operation);
  await page.waitForFunction(op=>!document.querySelectorAll('form button')[op==='retire'?1:0].disabled,operation);
  assert.equal(await page.getByLabel('Name',{exact:true}).inputValue(),transition==='unchanged'?'Alpha saved':transition==='selection'?'Beta unsaved work':'Pending draft');
  if(transition!=='unchanged'){
   assert.equal(await page.getByLabel('Note',{exact:true}).inputValue(),'Preserve this note');
   assert.equal(await page.getByLabel('Administrator password',{exact:true}).inputValue(),'next credentials');
  }else assert.equal(await page.getByLabel('Administrator password',{exact:true}).inputValue(),'');
  assert.equal(await page.getByLabel('Activation path · shown once').isVisible(),operation==='create'&&['same','unchanged'].includes(transition));
  if(['same','unchanged'].includes(transition)&&operation!=='retire'){
   await page.getByLabel('Administrator password',{exact:true}).fill('fixture');await page.getByRole('button',{name:'Save service',exact:true}).click();
   assert.equal(await page.evaluate(()=>requests[1].body.expectedRevision),operation==='create'?1:2);
   assert.equal(await page.evaluate(()=>requests[1].path),'/api/v1/console/decoy-services/'+(operation==='create'?'created':'a'));
  }
  assert.deepEqual(errors,[]);assert.ok(!await page.evaluate(()=>window.failure));
  if(operation==='save'&&transition==='selection')await page.screenshot({path:output+'/draft-preserved.png',fullPage:true});
  console.log(`PASS N05-DRAFT-${String(++count).padStart(3,'0')}: ${operation} completion after ${transition}`);await page.close();
 }
 console.log(`${count} browser scenarios passed; offline mocked API only.`);
}finally{await browser.close();}

