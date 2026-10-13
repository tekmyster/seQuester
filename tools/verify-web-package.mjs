import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import assert from 'node:assert/strict';
const root=path.resolve(process.argv[2]||'');assert.ok(process.argv[2],'Published app directory required');
const web=path.join(root,'wwwroot');let count=0;
for(const entry of fs.readdirSync(web,{recursive:true})){
 const name=path.join(web,entry);if(!fs.statSync(name).isFile())continue;
 if(name.endsWith('.br')||name.endsWith('.gz')){
  const compressed=fs.readFileSync(name),raw=fs.readFileSync(name.slice(0,-3));
  const decoded=name.endsWith('.br')?zlib.brotliDecompressSync(compressed):zlib.gunzipSync(compressed);
  assert.ok(raw.equals(decoded),'Compressed asset must exactly match its uncompressed file: '+entry);count++;
 }
}
const html=fs.readFileSync(path.join(web,'index.html'),'utf8');
for(const [,url] of html.matchAll(/(?:src|href)="(\/[^"?]+\.(?:js|css))(?:\?[^"]*)?"/g))assert.ok(fs.existsSync(path.join(web,url)),'Referenced asset exists: '+url);
assert.ok(count>30,'Expected compressed assets are present');
console.log(`PASS: ${count} compressed assets match their uncompressed files; HTML scripts and stylesheet exist.`);
