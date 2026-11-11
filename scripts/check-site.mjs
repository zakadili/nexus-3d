import {readdir,readFile,stat} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
const root=process.cwd(),failures=[];
for(const file of await readdir(root)){
 if(/\.(?:js|mjs)$/.test(file)){const r=spawnSync(process.execPath,['--check',file],{encoding:'utf8'});if(r.status)failures.push(r.stderr)}
 if(!file.endsWith('.html'))continue;
 const html=await readFile(file,'utf8');
 const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(x=>x[1]);
 if(new Set(ids).size!==ids.length)failures.push(file+': duplicate element IDs');
 for(const match of html.matchAll(/(?:href|src)="(\.\/[^"?#]+)(?:[^\"]*)"/g)){
  try{await stat(resolve(dirname(resolve(root,file)),match[1]))}catch{failures.push(file+': missing '+match[1])}
 }
 if(file!=='xray.html')for(const tag of ['Content-Security-Policy','name="description"','rel="canonical"','og:image','id="main"','site-header'])if(!html.includes(tag))failures.push(file+': missing '+tag);
 if(/<script(?![^>]*src=)[^>]*>\s*\S/.test(html))failures.push(file+': inline executable script');
}
for(const file of ['radar.css','styles.css'])if((await readFile(file,'utf8')).includes('@import'))failures.push(file+': remote font import');
const manifest=JSON.parse(await readFile('data/index/manifest.json','utf8'));
for(const key of manifest.shard_keys)await stat('data/index/'+key+'.json');
if(!JSON.parse(await readFile('data/kev.json','utf8')).records.length)failures.push('Empty KEV index');
if(failures.length){console.error(failures.join('\n'));process.exitCode=1}else console.log('Syntax, local links, metadata, CSP and published lookup files checked.');
