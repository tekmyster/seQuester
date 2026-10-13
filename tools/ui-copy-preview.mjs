// Isolated, read-only sample-data preview. No production configuration or database.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../src/seQuester.Server/wwwroot');
const now=new Date().toISOString();
const ready='Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)';
const legacy='Canary monitoring configured | File activity: inotify; actor evidence supplied separately by Linux Audit when enabled | '+ready;
const group={id:'sample-group',name:'Finance workstations',revision:2,endpointCount:2,settings:{integrityIntervalSeconds:60,deployments:[],allowlist:[]}};
const policy={minimumLength:14,maximumLength:128,requireUppercase:true,requireLowercase:true,requireDigit:true,requireSymbol:true};
const destination={enabled:false,host:'collector.example.invalid',port:6514,transport:'TLS',format:'RFC5424',octetCounting:true,facility:16,severity:4};
const endpoints=[{endpointId:'sample-healthy',machineName:'sample-linux-01',agentVersion:'0.9.7-linux-dev',health:legacy,lastSeenUtc:now,revoked:false},{endpointId:'sample-degraded',machineName:'sample-linux-02',agentVersion:'0.9.8-linux-dev',health:'Canary monitoring active | Linux Audit degraded: relay disconnected',lastSeenUtc:now,revoked:false}];
const actors=['Windows audit 4663','Linux fanotify','Linux Audit'];
const events=actors.map((source,i)=>({sequence:i+1,endpointId:'sample-healthy',receivedUtc:now,event:{observedUtc:now,operation:'File opened',path:'C:\\Sample\\Payroll.xlsx',user:'EXAMPLE\\analyst',process:'sample-reader.exe',processId:120+i,source,attribution:{level:'Full attribution',provider:source,basis:'Sample evidence only',userId:'1000'}}}));
const data={
 '/api/v1/auth/me':{userName:'Sample administrator',roles:['Administrator'],authentication:'Local',mfaEnabled:true,mfaRequired:false,mustChangePassword:false,mustEnrollMfa:false},
 '/api/v1/auth/sso/providers':[], '/password-policy.json':policy,
 '/api/v1/console/overview':{registered:2,staleContact:0,events:3,previousEvents:1,asOfUtc:now},
 '/api/v1/console/incidents/summary':{open:1,investigating:0,resolved:0,criticalActive:0},
 '/api/v1/console/endpoints':endpoints, '/api/v1/console/events':events,
 '/api/v1/console/groups':[group], '/api/v1/console/groups/sample-group/history':[],
 '/api/v1/console/policy-status':endpoints.map(x=>({endpointId:x.endpointId,groupId:group.id,desiredRevision:2,appliedRevision:2,reportedUtc:now})),
 '/api/v1/console/callbacks/catalog':{enabled:true,dnsEnabled:true,emailEnabled:true,mechanisms:[{id:'docx',name:'Word document',state:'Implemented',trigger:'Document opened by a compatible reader'},{id:'xlsx',name:'Excel workbook',state:'Implemented',trigger:'Workbook opened by a compatible reader'}]},
 '/api/v1/console/callbacks/tokens':[{id:'sample-token',name:'Payroll',type:'docx',location:'Finance',description:'Quarterly payroll decoy',note:'Sample only',created:now,revoked:false,emailAlerts:true}],
 '/api/v1/console/callbacks/delivery':{message:'Waiting for callback activity',lastSentSequence:0},'/api/v1/console/callbacks/hits':[],
 '/api/v1/console/email':{settings:{revision:1,enabled:false,host:'mail.example.invalid',port:587,from:'canary@example.invalid',recipients:['soc@example.invalid'],username:'',hasPassword:false,subjectPrefix:'seQuester',minimumIntervalSeconds:60},delivery:{state:'Disabled',message:'Email paused; pending callbacks retained',lastCompletedSequence:0}},
 '/api/v1/console/server-syslog':{settings:{revision:1,destination,endpointEvents:true,callbackHits:true},endpoints:{message:'Disabled',lastSentSequence:0},callbacks:{message:'Disabled',lastSentSequence:0}},
 '/api/v1/console/accounts':[], '/api/v1/console/security-policy':{version:1,mfaMode:'Optional'},
 '/api/v1/console/incidents':[], '/api/v1/console/incidents/assignees':[],
 '/api/v1/console/reports':[], '/api/v1/console/report-schedules':[], '/api/v1/console/responses':[],
 '/api/v1/console/operations':{checkedUtc:now,storageReadable:true,productionReady:false,checks:[{component:'Management storage',state:'Readable',detail:'Database query succeeded; sample only'},{component:'Identity key protection',state:'Unconfigured',detail:'Configure an encryption certificate'},{component:'Endpoint syslog relay',state:'Reported',detail:'Delivery pending: IOException; checkpoint 0. Direct client settings are separate.'}]}
};
const server=http.createServer((req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 if(req.method!=='GET'){res.writeHead(405);res.end('Read-only preview. No changes can be saved.');return;}
 const pathname=new URL(req.url,'http://127.0.0.1').pathname;
 if(Object.hasOwn(data,pathname)){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data[pathname]));return;}
 const name=pathname==='/'?'index.html':pathname.slice(1);
 if(!/^[a-z0-9.-]+\.(html|js|css)$/.test(name)){res.writeHead(404);res.end();return;}
 const file=path.join(root,name);if(!fs.existsSync(file)){res.writeHead(404);res.end();return;}
 res.setHeader('Content-Type',name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.js')?'text/javascript; charset=utf-8':'text/css; charset=utf-8');
 let content=fs.readFileSync(file,'utf8');
 if(name==='index.html')content=content.replace('<body>','<body><div style="position:fixed;right:16px;bottom:12px;z-index:9999;background:#fff4d6;color:#5b4100;padding:8px 14px;border:1px solid #d7b759;border-radius:8px">Sample data · Read-only preview</div>');
 res.end(content);
});
server.listen(18749,'127.0.0.1',()=>console.log('Read-only sample preview: http://127.0.0.1:18749'));
