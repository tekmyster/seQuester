import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';

// Run only an isolated, explicitly supplied development build. Never target a live server.
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.SEQUESTER_PLAYWRIGHT_MODULE || 'playwright');
const serverDll=process.env.SEQUESTER_DOC_SERVER_DLL;
assert.ok(serverDll && path.isAbsolute(serverDll) && fs.existsSync(serverDll),'Supply SEQUESTER_DOC_SERVER_DLL');
const sourceWebRoot=path.resolve(import.meta.dirname,'../src/RansomFree.Server/wwwroot');
const publishedWebRoot=path.join(path.dirname(serverDll),'wwwroot');
const sourceWebRootSha256={};
function verifyWebRoot(directory){
    for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
        const file=path.join(directory,entry.name);
        if(entry.isDirectory()){verifyWebRoot(file);continue;}
        const relative=path.relative(sourceWebRoot,file);
        const published=path.join(publishedWebRoot,relative);
        assert.ok(fs.existsSync(published),`Published UI file missing: ${relative}`);
        const digest=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
        assert.equal(crypto.createHash('sha256').update(fs.readFileSync(published)).digest('hex'),digest,`Published UI differs: ${relative}`);
        sourceWebRootSha256[relative.split(path.sep).join('/')]=digest;
    }
}
verifyWebRoot(sourceWebRoot);
const output=path.resolve(process.argv[2] || 'docs/screenshots');
fs.mkdirSync(output,{recursive:true});
const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'sequester-documentation-'));
fs.mkdirSync(path.join(temporary,'data'));
fs.mkdirSync(path.join(temporary,'callbacks'));
const listener=net.createServer();
await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
const port=listener.address().port;
await new Promise(resolve=>listener.close(resolve));
const origin=`http://127.0.0.1:${port}`;
const administratorKey=crypto.randomBytes(32).toString('hex');
const password='Documentation-'+crypto.randomBytes(24).toString('hex')+'!';
const environment={...process.env,RF_DATA_DIR:path.join(temporary,'data'),RF_ADMIN_KEY:administratorKey,
    ASPNETCORE_ENVIRONMENT:'Development',DOTNET_ENVIRONMENT:'Development',RF_ALLOW_LOOPBACK_HTTP:'true',
    ASPNETCORE_URLS:origin,Logging__LogLevel__Default:'Warning',Callbacks__Enabled:'false'};
// Exclude inherited deployment settings from this isolated process.
for(const key of Object.keys(environment))if(/^(Database__|ConnectionStrings__|Callbacks__|Kestrel__|IdentityKeys__)/i.test(key))delete environment[key];
environment.Callbacks__Enabled='true';environment.Callbacks__Origin='https://callbacks.example.com';
environment.RF_CALLBACK_DATA=path.join(temporary,'callbacks');
const server=spawn(process.env.SEQUESTER_DOTNET || 'dotnet',[serverDll],{env:environment,windowsHide:true,stdio:['ignore','ignore','pipe']});
let browser;
const failures=[],screens=[],checks=[];
let reportedServerVersion;
let startupError='';
server.stderr.on('data',data=>{startupError=(startupError+data.toString()).slice(-8000);});
server.on('error',error=>failures.push(error.message));
async function post(route,body,credential=administratorKey){
    const response=await fetch(origin+route,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${credential}`},body:body===undefined?undefined:JSON.stringify(body)});
    assert.ok(response.ok,`${route}: HTTP ${response.status}`);
    return response.status===204?null:response.json();
}
try{
    let ready=false;
    for(let attempt=0;attempt<200;attempt++){
        assert.equal(server.exitCode,null,'Isolated server exited: '+startupError);
        try{const response=await fetch(origin+'/health/live');if(response.ok){reportedServerVersion=(await response.json()).serverVersion;ready=true;break;}}catch{}
        await new Promise(resolve=>setTimeout(resolve,150));
    }
    assert.ok(ready,'Isolated server startup timed out');
    await post('/api/v1/admin/users',{userName:'documentation-admin',password,role:'Administrator'});
    for(const sensor of [
        {host:'lab-win01',os:'windows',version:'0.6.26',user:'EXAMPLE\\analyst',process:'sample-reader.exe',pid:1234,file:'C:\\Lab\\Honeypots\\finance.xlsx',operation:'Content read (copy possible)'},
        {host:'lab-linux01',os:'linux',version:'0.9.43',user:'analyst',process:'/usr/bin/cat',pid:2345,file:'/srv/lab/honeypots/finance.csv',operation:'Content read (copy possible)'}
    ]){
        const code=await post('/api/v1/admin/enrollment-codes');
        const enrolled=await post('/api/v1/enroll',{code:code.code,machineName:sensor.host,agentVersion:sensor.version});
        await post('/api/v1/agent/heartbeat',{agentVersion:sensor.version,health:'Healthy',operatingSystem:sensor.os,protection:{deployedCanaryAndHoneypotFiles:3,monitoringState:'active'}},enrolled.credential);
        await post('/api/v1/agent/events',{events:[{eventId:crypto.randomUUID().replaceAll('-',''),observedUtc:new Date().toISOString(),operation:sensor.operation,path:sensor.file,user:sensor.user,process:sensor.process,processId:sensor.pid,source:'Documentation sample'}]},enrolled.credential);
    }
    browser=await chromium.launch({headless:true,...(process.env.SEQUESTER_CHROMIUM?{executablePath:process.env.SEQUESTER_CHROMIUM}:{})});
    const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'en-US',timezoneId:'America/New_York'});
    page.on('pageerror',error=>failures.push(error.message));
    page.on('response',response=>{if(response.status()>=400 && response.status()!==401)failures.push(`HTTP ${response.status()}: ${new URL(response.url()).pathname}`);});
    await page.goto(origin,{waitUntil:'networkidle'});
    await page.screenshot({path:path.join(output,'sign-in-desktop.png'),fullPage:true});screens.push('sign-in-desktop.png');
    await page.getByLabel('Username',{exact:true}).fill('documentation-admin');
    await page.getByLabel('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await page.locator('#workspace').waitFor({state:'visible'});
    await page.waitForFunction(()=>!document.querySelector('#login-form button[type="submit"]').disabled);
    async function capture(label,name){
        const navigation=page.getByRole('button',{name:label,exact:true});
        if(!(await navigation.getAttribute('class')||'').split(/\s+/).includes('selected'))await navigation.click();
        await navigation.waitFor({state:'visible'});
        await page.waitForFunction(label=>Array.from(document.querySelectorAll('nav button')).filter(button=>button.textContent.trim()===label).every(button=>!button.disabled),label);
        await page.waitForLoadState('networkidle');
        if(label==='Sensors')await page.locator('#fleet-rows tr').first().waitFor();
        if(label==='Alerts')await page.locator('#alert-rows tr').first().waitFor();
        await page.screenshot({path:path.join(output,name+'.png'),fullPage:true});screens.push(name+'.png');
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${label}: page overflow`);
        checks.push(`${label}: loaded without page overflow`);
    }
    await capture('Overview','overview-desktop');
    await capture('Sensors','sensors-desktop');
    assert.equal(await page.locator('#fleet-rows tr').count(),2);checks.push('Two sample sensors displayed');
    await capture('Alerts','events-desktop');
    assert.ok((await page.locator('#alert-rows').textContent()).includes('sample-reader'));checks.push('Sample actor details displayed');
    await capture('Canary tokens','canaries-desktop');
    await capture('Policies','policies-desktop');
    await capture('Trust rules','trust-rules-desktop');
    await page.getByRole('button',{name:'Create whitelist',exact:true}).click();
    const rule=page.locator('.trust-rule').last();
    await rule.getByLabel('Rule name',{exact:true}).fill('Approved lab reader');
    await rule.getByLabel('Match identity',{exact:true}).selectOption('process');
    await rule.getByLabel('Operating system',{exact:true}).selectOption('windows');
    await rule.getByLabel('Executable path',{exact:true}).fill('C:\\Lab\\sample-reader.exe');
    await rule.getByLabel('SHA-256',{exact:true}).fill('A'.repeat(64));
    await page.screenshot({path:path.join(output,'whitelist-editor-desktop.png'),fullPage:true});screens.push('whitelist-editor-desktop.png');
    checks.push('Disabled sample whitelist draft displayed; no policy published');
    await capture('Notifications','notifications-desktop');
    await capture('Reports','reports-desktop');
    await capture('Operations','operations-desktop');
    await capture('Incidents','incidents-desktop');
    await capture('Responses','responses-desktop');
    await capture('Accounts','accounts-desktop');
    await capture('Account security','account-security-desktop');
    await page.setViewportSize({width:390,height:844});
    await capture('Sensors','sensors-mobile');
    await capture('Alerts','events-mobile');
    await page.setViewportSize({width:1440,height:1000});
    await page.goto(origin+'/decoy-jobs.html',{waitUntil:'networkidle'});
    await page.screenshot({path:path.join(output,'decoy-jobs-desktop.png'),fullPage:true});screens.push('decoy-jobs-desktop.png');
    checks.push('Decoy jobs screen captured from the authenticated local server');
    assert.deepEqual(failures,[],'Browser/server errors');
    checks.push('No browser page errors');
    fs.writeFileSync(path.join(output,'capture.json'),JSON.stringify({capturedUtc:new Date().toISOString(),serverVersion:reportedServerVersion,environment:'Isolated localhost development server',data:'Synthetic documentation samples; not production telemetry',sourceMatchVerified:true,sourceWebRootSha256,screens,checks},null,2)+'\n');
    console.log(JSON.stringify({screens:screens.length,checks:checks.length,output}));
}finally{
    if(browser)await browser.close();
    if(server.exitCode===null){server.kill();await new Promise(resolve=>server.once('exit',resolve));}
    // Retain the isolated data directory for review. It is outside the repository.
}
