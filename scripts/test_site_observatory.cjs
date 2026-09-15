const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const model=require('../site/assets/observatory.js');
let state=model.initial();
for(let stage=0;stage<4;stage++){
 state=model.transition(state,{type:'stage',value:stage});
 assert.equal(state.evidence,false,'Navigation cannot attach evidence');
 assert.doesNotMatch(model.describe(state).label,/attached|proven/i);
}
state=model.transition(state,{type:'select',value:2});
state=model.transition(state,{type:'evidence'});
assert.equal(state.selected,2);
assert.match(model.describe(state).label,/fictional/);
state=model.transition(state,{type:'cut',value:'delegation'});
assert.equal(state.evidence,true);
assert.match(model.describe(state).detail,/does not prove the changed route/);
assert.match(model.describe(state).interpretation,/not proof.*secure/);
state=model.transition(state,{type:'cut',value:'none'});
assert.match(model.describe(state).label,/Evidence attached/);
state=model.transition(state,{type:'evidence'});
assert.equal(state.evidence,false);
assert.deepEqual(model.transition(state,{type:'reset'}),model.initial());
for(const action of [{type:'stage',value:9},{type:'select',value:-1},{type:'cut',value:'unknown'}]){
 assert.deepEqual(model.transition(model.initial(),action),model.initial());
}
const html=fs.readFileSync('site/index.html','utf8');
for(const block of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)){
 if(block[0].includes('application/ld+json'))continue;
 new vm.Script(block[1]);
}
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
assert.equal(ids.length,new Set(ids).size,'HTML IDs must be unique');
for(const match of html.matchAll(/(?:src|href)="([^"#?]+)(?:[?#][^"]*)?"/g)){
 const ref=match[1];if(/^(https?:|data:|mailto:|\/)/.test(ref))continue;
 // Shared social assets are staged from docs by the Pages workflow.
 if(ref.startsWith('docs/'))continue;
 assert(fs.existsSync('site/'+ref),'Missing local asset: '+ref);
}
assert(!html.includes('id="schema-canvas"'),'Old graph canvas must not be mounted');
assert(!html.includes('src="assets/frozen-evidence.js"'),'Old experiment must not be mounted');
console.log('PASS: shared state, no implicit proof, cut/restore, reset, invalid input, inline syntax, IDs and asset references');
