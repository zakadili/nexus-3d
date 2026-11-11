import {mkdir,copyFile,readdir} from 'node:fs/promises';
import {join} from 'node:path';
const output='.site-dist';await mkdir(output,{recursive:true});
async function copy(source,target){await mkdir(target,{recursive:true});for(const entry of await readdir(source,{withFileTypes:true})){const from=join(source,entry.name),to=join(target,entry.name);if(entry.isDirectory())await copy(from,to);else if(entry.isFile())await copyFile(from,to)}}
for(const entry of await readdir('.',{withFileTypes:true}))if(entry.isFile()&&(/\.(html|css|js|mjs)$/.test(entry.name)||['robots.txt','sitemap.xml','.nojekyll'].includes(entry.name))&&!entry.name.includes('entry'))await copyFile(entry.name,join(output,entry.name));
await copy('assets',join(output,'assets'));await copy('data',join(output,'data'));await mkdir(join(output,'sentinel'),{recursive:true});await copyFile('sentinel/lab.json',join(output,'sentinel/lab.json'));
console.log('Packaged public site without development tools, backend source or test fixtures.');
