import test from 'node:test';
import assert from 'node:assert/strict';
import {buildExtrasUI} from '../radar-extras.js';

class Node{constructor(text=''){this.text=text;this.children=[]}append(...items){this.children.push(...items)}replaceChildren(...items){this.children=items}addEventListener(){}get textContent(){return this.text+this.children.map(x=>x.textContent||'').join(' ')}set textContent(v){this.text=v}}
test('supplemental views use data that arrives after UI initialization',()=>{
 const nodes=new Map(['#asn-global','#outages-global','#malware-global'].map(id=>[id,new Node()]));
 globalThis.document={querySelector:id=>nodes.get(id)};
 const state={extra:null},create=(tag,cls,text)=>new Node(text);
 const ui=buildExtrasUI(state,{create,note:text=>new Node(text),fmt:String,name:String,link:(text)=>new Node(text)});
 ui.renderGlobal();assert.match(nodes.get('#asn-global').textContent,/UNAVAILABLE/);
 state.extra={feeds:{iptoasn:{top_global:[{asn:123,org:'Example hosting',listed_ips:42}]},ioda:{events:[]}},source_health:[{id:'iptoasn',status:'ok'},{id:'ioda',status:'ok'}]};
 ui.renderGlobal();assert.match(nodes.get('#asn-global').textContent,/Example hosting/);assert.doesNotMatch(nodes.get('#asn-global').textContent,/UNAVAILABLE/);
 assert.match(nodes.get('#outages-global').textContent,/no recent country events/);
 state.extra={feeds:{},source_health:[{id:'iptoasn',status:'unavailable',reason:'provider timeout'}]};
 ui.renderGlobal();assert.match(nodes.get('#asn-global').textContent,/provider timeout/);
 delete globalThis.document;
});
