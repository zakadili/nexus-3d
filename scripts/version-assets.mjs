import {readFile,writeFile,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,dirname} from 'node:path';
const version=async path=>createHash('sha256').update(await readFile(path)).digest('hex').slice(0,12);
// Dependencies before importing entry points; no circular module dependencies.
for(const file of ['radar-plus.js','app.js','workbench.js','sentinel.js','lookup.js','stream-adapter.js','live-loader.js']){
 let source=await readFile(file,'utf8');
 const matches=[...source.matchAll(/(['"])(\.\/[^'"?]+\.(?:js|mjs))(?:\?[^'"]*)?\1/g)];
 for(const [whole,quote,path] of matches)source=source.replace(whole,quote+path+'?v='+await version(resolve(dirname(file),path))+quote);
 await writeFile(file,source);
}
for(const file of (await readdir('.')).filter(x=>x.endsWith('.html'))){
 let html=await readFile(file,'utf8');const matches=[...html.matchAll(/\b(src|href)="(\.\/[^"?]+\.(?:js|mjs|css))(?:\?[^"\s]*)?"/g)];
 for(const [whole,attr,path] of matches)html=html.replace(whole,attr+'="'+path+'?v='+await version(path)+'"');
 await writeFile(file,html);
}
console.log('Versioned local styles and modules by content.');
