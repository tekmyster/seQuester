import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';

// This catches mechanical regressions; it cannot judge clarity or visual quality.
const checks=[
 ['Raw object rendered into UI', /(?:textContent|innerHTML)\s*=\s*JSON\.stringify\s*\(/g],
 ['Raw object used as a display label', /\b(?:make|cell)\([^;\n]*JSON\.stringify\s*\(/g],
 ['Generic disclaimer or placeholder copy', /["'`](?:Please be advised|Use at your own risk|This feature may cause unexpected behavior|Lorem ipsum|Coming soon)[^"'`]*["'`]/gi],
 ['Internal identifier used as a field label', /\bfield\([^;\n]*,[ ]*["'][a-z]+(?:_[a-z]+){2,}["']/g]
];
export function inspect(source){return checks.flatMap(([reason,pattern])=>Array.from(source.matchAll(pattern),match=>({reason,line:source.slice(0,match.index).split('\n').length})));}
if(process.argv.includes('--self-test')){
 assert.equal(inspect('node.textContent=JSON.stringify(response);').length,1);
 assert.equal(inspect('cell(row, JSON.stringify(response));').length,1);
 assert.equal(inspect('make("p","Please be advised that settings can change behavior.");').length,1);
 assert.equal(inspect('field(form,"max_retry_count");').length,1);
 assert.equal(inspect('api("/policy", {rules: normalized}); node.textContent="Retry attempts";').length,0);
 console.log('PASS: Product UX checker positive and negative controls');
}else{
 let files=process.argv.slice(2);
 if(!files.length){files=[...new Set([
  ...execFileSync('git',['-c','core.autocrlf=false','diff','HEAD','--name-only'],{encoding:'utf8'}).split(/\r?\n/),
  ...execFileSync('git',['ls-files','--others','--exclude-standard'],{encoding:'utf8'}).split(/\r?\n/)
 ])].filter(file=>/^src\/seQuester\.Server\/wwwroot\/.*\.(js|html)$/.test(file)&&fs.existsSync(file));}
 let failures=0;for(const file of files){for(const result of inspect(fs.readFileSync(file,'utf8'))){console.error(`${file}:${result.line}: ${result.reason}`);failures++;}}
 if(failures)process.exitCode=1;else console.log(`PASS: Product UX mechanical checks (${files.length} files); visual/editorial review still required`);
}
