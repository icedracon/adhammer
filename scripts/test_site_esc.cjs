const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '..');
const {items, commands} = require('../site/assets/esc-explorer.js');
assert.deepEqual(items.map(x => x.id), Array.from({length:16}, (_,i) => i+1));
for (const item of items) {
  for (const key of ['family','title','check','focus','meaning','result','boundary','remedy']) assert(item[key], `ESC${item.id}: ${key}`);
  assert(commands[item.check]);
}
for (const check of Object.values(commands)) {
  assert.equal(check.steps.length, 4);
  assert(fs.existsSync(path.join(root, check.source)));
  if (check.command) {
    assert.match(check.command, /^adhammer (check adcs|enum esc|enum adcs) /);
    assert(!/--insecure|--allow-plaintext|attack|--yes|--kdc/.test(check.command));
    assert(check.command.includes('@file:./audit-password.txt'));
  }
}
assert.equal(items[11].check, 'manual');
assert.match(items[7].boundary, /validation is owed/);
assert.match(items[10].boundary, /validation is owed/);
assert.match(items[12].boundary, /does not by itself prove/);
const html = fs.readFileSync(path.join(root,'site/index.html'),'utf8');
assert(!html.includes('var escData ='));
assert(html.includes('assets/esc-explorer.css'));
assert(html.includes('assets/esc-explorer.js'));

// Exercise browser behavior without network access or a browser dependency.
const elements = new Map();
let animationCount = 0, cancelled = 0, copied = '', observer, visibility;
function element(id) {
  if (elements.has(id)) return elements.get(id);
  const el = {id, textContent:'', hidden:false, attrs:{}, children:[], events:{},
    style:{values:{},setProperty(k,v){this.values[k]=v;}},
    setAttribute(k,v){this.attrs[k]=v;}, addEventListener(k,v){this.events[k]=v;},
    appendChild(v){this.children.push(v);}, focus(){},
    animate(){animationCount++; return {cancel(){cancelled++;}};},
    querySelector(){return element(id+'-label');},
    querySelectorAll(){return flow;}
  };
  elements.set(id,el); return el;
}
const flow = [0,1,2,3].map(i=>element('step-'+i));
const reduced = {matches:false,addEventListener(k,fn){this.change=fn;}};
const document = {hidden:false,documentElement:{dataset:{}},
  getElementById:element, createElement(){return element('button-'+elements.size);},
  addEventListener(k,fn){if(k==='visibilitychange')visibility=fn;}
};
const window = {document, matchMedia(){return reduced;}, navigator:{clipboard:{writeText(text){copied=text;return Promise.resolve();}}},
  MutationObserver:class {constructor(fn){observer=fn;} observe(){}}
};
vm.runInNewContext(fs.readFileSync(path.join(root,'site/assets/esc-explorer.js'),'utf8'),{window});
const buttons = element('esc-picker').children;
assert.equal(buttons.length,16);
assert.equal(animationCount,0,'No animation on initial render');
buttons[7].events.click();
assert.equal(element('esc-number').textContent,'ESC8');
assert.match(element('esc-command').textContent,/enum adcs/);
assert.equal(animationCount,4);
document.documentElement.dataset.motion='paused'; observer();
assert.equal(cancelled,4);
buttons[11].events.click();
assert(element('esc-copy').hidden);
assert.equal(animationCount,4,'Paused motion must not restart on selection');
document.documentElement.dataset.motion='running'; reduced.matches=true;
buttons[0].events.click();
assert.equal(animationCount,4,'Reduced motion must not animate');
buttons[0].events.keydown({key:'End',preventDefault(){}});
assert.equal(element('esc-number').textContent,'ESC16');
element('esc-copy').events.click();
assert.equal(copied,commands.registry.command);
reduced.matches=false; document.hidden=true; visibility();
element('esc-replay').events.click();
assert.equal(animationCount,4,'Hidden document must not animate');
document.hidden=false; reduced.matches=true;
buttons[0].events.click();
const dial = element('esc-dial');
let prevented = false;
function wheel(delta,time,extra={}) {
  prevented=false;
  dial.events.wheel({deltaX:0,deltaY:delta,deltaMode:0,timeStamp:time,cancelable:true,preventDefault(){prevented=true;},...extra});
}
wheel(-100,0);
assert(!prevented,'Scroll up at ESC1 must escape to page');
wheel(100,300);
assert(prevented);
assert.equal(element('esc-number').textContent,'ESC2');
assert.equal(dial.style.values['--turn'],'-22.5deg');
wheel(100,350);
assert.equal(element('esc-number').textContent,'ESC2','Trackpad burst must not skip several classes');
wheel(100,700,{ctrlKey:true});
assert(!prevented,'Browser zoom gesture must remain native');
assert.equal(element('esc-number').textContent,'ESC2');
buttons[15].events.click();
wheel(100,1000);
assert(!prevented,'Scroll down at ESC16 must escape to page');
assert(element('esc-next').disabled);
element('esc-previous').events.click();
assert.equal(element('esc-number').textContent,'ESC15');
dial.events.touchstart({touches:[{clientX:150,clientY:150}]});
dial.events.touchend({changedTouches:[{clientX:70,clientY:160}]});
assert.equal(element('esc-number').textContent,'ESC16');
dial.events.touchstart({touches:[{clientX:100,clientY:150}]});
dial.events.touchend({changedTouches:[{clientX:110,clientY:250}]});
assert.equal(element('esc-number').textContent,'ESC16','Vertical swipes must leave selection alone');
console.log('PASS: cards, commands, keyboard/copy, animation, rotary wheel/throttle/end escape, zoom preservation, horizontal touch and vertical-scroll preservation');
