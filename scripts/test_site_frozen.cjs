/* Hermetic interaction contract for the fictional website experiment. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
function mount(paused = false, reducedMotion = false) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {dataset:{}, attrs:{}, events:{}, value:'', hidden:true, textContent:'', style:{setProperty(k,v){this[k]=v;}}, setAttribute(k,v){this.attrs[k]=v;}, addEventListener(k,fn){this.events[k]=fn;}, getBoundingClientRect(){return {top:200,bottom:1400};}, querySelector(){return element('actions');}});
    return elements.get(id);
  }
  element('frozen-relationship').value = 'delegation';
  const events = {};
  const document = {getElementById:element, hidden:false, documentElement:{dataset:{motion:paused?'paused':'running'}}};
  const window = {innerHeight:800, matchMedia(){return {matches:reducedMotion};}, addEventListener(k,fn){events[k]=fn;}, requestAnimationFrame(fn){fn();}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../site/assets/frozen-evidence.js'),'utf8'), {document,window});
  return {element,events};
}
const {element:e,events} = mount();
const click = id => e(id).events.click();
assert.equal(e('path-lab').dataset.evidence,'pending');
assert.equal(e('actions').hidden,false);
events.scroll();
assert.equal(e('frozen-reveal').value,'75');
click('frozen-attach');
assert.equal(e('path-lab').dataset.evidence,'attached');
assert.match(e('frozen-result').textContent,/not a captured assessment/);
click('frozen-break');
assert.equal(e('path-lab').dataset.cut,'delegation');
assert.match(e('frozen-result').textContent,/does not prove the changed route/);
e('frozen-relationship').value='identity'; e('frozen-relationship').events.change();
assert.equal(e('path-lab').dataset.cut,'identity');
click('frozen-break');
assert.equal(e('path-lab').dataset.cut,'none');
click('frozen-attach');
assert.equal(e('path-lab').dataset.evidence,'pending');
e('frozen-reveal').value='20'; e('frozen-reveal').events.input(); events.scroll();
assert.equal(e('frozen-reveal').value,'20');
click('frozen-reset');
assert.equal(e('frozen-reveal').value,'40');
assert.equal(e('path-lab').dataset.cut,'none');
assert.equal(e('frozen-relationship').value,'delegation');
for (const options of [[true,false],[false,true]]) {
  const test = mount(...options); test.events.scroll();
  assert.equal(test.element('path-lab').style['--reveal'],undefined);
}
console.log('PASS: fixture, cut/restore, selection, reset, manual reveal, paused and reduced-motion contracts');
