const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require.resolve('../static/ui.js'),'utf8');
function setup(saved = null) {
  class Element {
    constructor() { this.dataset={}; this.children=[]; this.handlers={}; this.attrs={}; this.hidden=false; }
    addEventListener(name,fn) { this.handlers[name]=fn; }
    append(...nodes) { this.children.push(...nodes); }
    setAttribute(k,v) { this.attrs[k]=v; }
    removeAttribute(k) { delete this.attrs[k]; }
    querySelector(selector) { return this.children.find(child=>child.tag===selector); }
    querySelectorAll() { return this.children; }
    focus() { this.focused=true; }
  }
  const results=new Element(), items=new Element(), count=new Element(), more=new Element(), status=new Element();
  results.dataset={query:'test',next:'10',total:'23'};
  for(let i=0;i<10;i++) { const row=new Element();row.dataset.cve=`CVE-2024-${1000+i}`;items.append(row); }
  const document={documentElement:{classList:{add(){}}},querySelector:s=>({'.results':results,'#result-items':items,'#result-count':count,'#load-more':more,'#pagination-status':status})[s],querySelectorAll:()=>[],createElement:tag=>{const e=new Element();e.tag=tag;return e;}};
  const requests=[], events={}, storage={};
  const window={addEventListener:(name,fn)=>events[name]=fn,scrollTo:(x,y)=>window.scroll=y};
  vm.runInNewContext(source,{document,window,location:{pathname:'/',search:'?q=test'},performance:{getEntriesByType:()=>[{type:saved?'back_forward':'navigate'}]},sessionStorage:{getItem:()=>JSON.stringify(saved),setItem:(key,value)=>storage[key]=JSON.parse(value)},Date,requestAnimationFrame:fn=>fn(),scrollY:450,fetch:url=>new Promise(resolve=>requests.push({url,resolve}))});
  return {items,count,more,status,requests,events,storage,window,click:()=>more.handlers.click({preventDefault(){}})};
}
const records=(start,n)=>Array.from({length:n},(_,i)=>({cveId:`CVE-2024-${1000+start+i}`,title:'<unsafe> title',summary:'Test'}));
test('load more guards overlapping clicks, preserves rows on failure, retries, deduplicates and exhausts',async()=>{
 const h=setup(); const first=h.click(); const ignored=h.click(); assert.equal(h.requests.length,1);
 h.requests[0].resolve({ok:false});await first;await ignored;
 assert.equal(h.items.children.length,10);assert.match(h.status.textContent,/Try again/);
 const second=h.click();h.requests[1].resolve({ok:true,json:async()=>({results:[...records(9,1),...records(10,10)],totalResults:23,nextStartIndex:20})});await second;
 assert.equal(h.items.children.length,20);assert.equal(h.window.scroll,450);
 assert.equal(h.items.children[10].children[0].children[1].textContent,'<unsafe> title');
 const third=h.click();h.requests[2].resolve({ok:true,json:async()=>({results:records(20,3),totalResults:23,nextStartIndex:null})});await third;
 assert.equal(h.items.children.length,23);assert.equal(h.more.hidden,true);assert.match(h.status.textContent,/All results/);
 h.events.pagehide(); const saved=Object.values(h.storage)[0];assert.equal(saved.items.length,13);
 const restored=setup(saved);assert.equal(restored.items.children.length,23);assert.equal(restored.window.scroll,450);
});
test('empty page stops pagination despite a stale total',async()=>{
 const h=setup(), pending=h.click();h.requests[0].resolve({ok:true,json:async()=>({results:[],totalResults:23,nextStartIndex:10})});await pending;
 assert.equal(h.items.children.length,10);assert.equal(h.more.hidden,true);
});
