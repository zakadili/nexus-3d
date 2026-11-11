import {build} from 'esbuild';
import {readFile,writeFile} from 'node:fs/promises';
const result=await build({entryPoints:['map-vendor-entry.js'],bundle:true,format:'esm',minify:true,outfile:'assets/map-vendor.js',legalComments:'external',target:['es2022'],metafile:true});
const packages=[...new Set(Object.keys(result.metafile.inputs).filter(x=>x.startsWith('node_modules/')).map(x=>x.split('/')[1]))].sort();
const notices=[];
for(const name of packages){try{notices.push(name+'\n'+await readFile('node_modules/'+name+'/LICENSE','utf8'))}catch{throw Error('Missing license for bundled dependency '+name)}}
await writeFile('assets/THIRD-PARTY-LICENSES.txt',notices.join('\n\n---\n\n'));
