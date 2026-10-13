import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require('playwright');
const root=path.resolve(import.meta.dirname,'..');
const output=path.join(root,'lucidchart-import');
const scratch='D:/Codex/RansomFree/documentation/lucidchart-qa';
const manifest=JSON.parse(fs.readFileSync(path.join(output,'manifest.json'),'utf8'));
const browser=await chromium.launch({headless:true,executablePath:'C:/Users/dmessana/AppData/Local/ms-playwright/chromium-1193/chrome-win/chrome.exe'});
const context=await browser.newContext({viewport:{width:1800,height:1500}});
await context.route('**/*',route=>route.abort()); // Offline rendering: no artifact/network activation.
const tab=await context.newPage();
await tab.setContent('<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;background:white"><div id="graph" style="position:relative;overflow:hidden"></div></body></html>');
await tab.evaluate(()=>{window.mxLoadResources=false;window.mxLoadStylesheets=false;});
await tab.addScriptTag({content:fs.readFileSync(path.join(scratch,'mxClient.js'),'utf8')});
const results=[];
try {
 for(const set of manifest.sets){
  const xml=fs.readFileSync(path.join(output,set.file),'utf8');
  await tab.evaluate(xml=>{window.inputDoc=new DOMParser().parseFromString(xml,'text/xml');},xml);
  for(const [index,p] of set.pages.entries()){
   const result=await tab.evaluate(({index,width,height})=>{
    if(typeof window.graph?.destroy==='function')window.graph.destroy();
    const container=document.getElementById('graph');container.replaceChildren();container.style.width=width+'px';container.style.height=height+'px';
    const rawModel=window.inputDoc.getElementsByTagName('diagram')[index].getElementsByTagName('mxGraphModel')[0];
    const model=new DOMParser().parseFromString(new XMLSerializer().serializeToString(rawModel),'text/xml').documentElement;
    if(!model)throw Error('Graph model missing');
    const graph=window.graph=new mxGraph(container);graph.setEnabled(false);graph.border=0;
    new mxCodec(model.ownerDocument).decode(model,graph.getModel());graph.refresh();
    let vertices=0,edges=0;const textOverflow=[],missingTerminals=[];
    for(const cell of Object.values(graph.getModel().cells)){
      if(cell.vertex){vertices++;const s=graph.view.getState(cell);const b=s?.text?.boundingBox;
       if(b&&(b.x<s.x-2||b.y<s.y-2||b.x+b.width>s.x+s.width+2||b.y+b.height>s.y+s.height+2))textOverflow.push({id:cell.id,label:cell.value,shape:{x:s.x,y:s.y,w:s.width,h:s.height},text:{x:b.x,y:b.y,w:b.width,h:b.height}});
      }
      if(cell.edge){edges++;if(!cell.source||!cell.target)missingTerminals.push(cell.id);}
    }
    return {vertices,edges,textOverflow,missingTerminals};
   },{index,width:p.width,height:p.height});
   if(result.vertices!==p.nodes+3||result.edges!==p.connectors||result.missingTerminals.length)throw Error('Native decoder coverage mismatch '+p.name);
   results.push({set:set.file,page:index+1,name:p.name,...result});
   if((set.file.startsWith('01-')&&index===0)||(set.file.startsWith('02-')&&index===3)||(set.file.startsWith('03-')&&index===1)){
    await tab.evaluate(({width})=>{const scale=Math.min(1,1750/width);window.graph.view.setScale(scale);document.getElementById('graph').style.width=(width*scale)+'px';},{width:p.width});
    const scale=Math.min(1,1750/p.width);
    await tab.setViewportSize({width:Math.min(1800,Math.ceil(p.width*scale)),height:Math.min(10000,Math.ceil(p.height*scale))});
    await tab.screenshot({path:path.join(scratch,set.file.replace('.drawio','')+`-native-p${index+1}.png`),fullPage:false});
   }
  }
 }
 fs.writeFileSync(path.join(scratch,'native-render-results.json'),JSON.stringify(results,null,2));
 fs.copyFileSync(path.join(scratch,'native-render-results.json'),path.join(output,'native-render-results.json'));
 console.log(JSON.stringify({pages:results.length,vertices:results.reduce((a,r)=>a+r.vertices,0),edges:results.reduce((a,r)=>a+r.edges,0),textOverflow:results.filter(r=>r.textOverflow.length).map(r=>({set:r.set,page:r.page,items:r.textOverflow.map(t=>t.id)})),network:'All browser network blocked; native mxGraph source loaded locally'}));
} finally {await browser.close();}
