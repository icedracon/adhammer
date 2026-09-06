// Run with node scripts/test_site_entrance.cjs. Hermetic: no browser or network.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const file = path.join(__dirname, '../site/assets/entrance.js');
const source = fs.readFileSync(file, 'utf8');
const api = require(file);
const scene = api.createScene();
assert.deepEqual(scene, api.createScene(), 'Scene must be deterministic');
assert.equal(scene.nodes.length, 68);
assert.equal(scene.edges.filter(edge => edge.route >= 0).length, 3);
for (const edge of scene.edges) {
  assert(edge.a >= 0 && edge.b < scene.nodes.length && edge.a !== edge.b);
}
for (const progress of [-1, 0, .25, .5, .75, 1, 2]) {
  for (const node of scene.nodes) {
    const point = api.project(node, api.cameraFor(progress, false, {x: .5, y: -.5}));
    assert(Object.values(point).every(Number.isFinite));
    assert(point.scale > 0);
  }
}
assert.deepEqual(api.cameraFor(0, true, {x: 0, y: 0}), api.cameraFor(1, true, {x: 1, y: 1}));
let count = 0, paintCount = 0, paused = false, changeMotion, skipFn, observer;
let rectTop = 0, journey, focused = false, scrollOptions, staticFallback = false;
const queue = new Map(), handlers = {}, docHandlers = {};
const context = new Proxy({}, {get: (_, key) => key === 'clearRect' ? () => paintCount++ : () => {}});
const hero = {
  offsetHeight: 1440,
  classList: {add: name => {staticFallback = name === 'entrance-static';}},
  getBoundingClientRect: () => ({top: rectTop, bottom: rectTop + 1440})
};
const stage = {
  offsetHeight: 800,
  style: {setProperty: (_, value) => {journey = +value;}},
  getBoundingClientRect: () => ({left: 0, top: 0, width: 1280, height: 800}),
  addEventListener() {}
};
const header = {classList: {toggle() {}}};
const engine = {getBoundingClientRect: () => ({top: 1440}), setAttribute() {}, focus: () => {focused = true;}};
const canvas = {getContext: () => context};
const doc = {
  hidden: false,
  querySelector: () => stage,
  getElementById: id => ({top: hero, 'living-graph': canvas, header, engine,
    'skip-entrance': {addEventListener: (_, fn) => {skipFn = fn;}}})[id],
  addEventListener: (type, fn) => {docHandlers[type] = fn;}
};
const browserWindow = {
  document: doc, innerHeight: 800, innerWidth: 1280, devicePixelRatio: 2, scrollY: 0,
  addEventListener: (type, fn) => {handlers[type] = fn;},
  requestAnimationFrame: fn => {queue.set(++count, fn); return count;},
  cancelAnimationFrame: id => queue.delete(id),
  scrollTo: args => {scrollOptions = args;},
  IntersectionObserver: class {constructor(fn) {observer = fn;} observe() {}}
};
vm.runInNewContext(source, {window: browserWindow});
browserWindow.ADhammerEntrance.mount({isReduced: () => paused, onMotionChange: fn => {changeMotion = fn;}});
function frame(time) {const tasks = [...queue.values()]; queue.clear(); tasks.forEach(fn => fn(time));}
frame(40); assert(paintCount > 0); assert.equal(canvas.width, 1920); assert.equal(queue.size, 1);
rectTop = -400; handlers.scroll(); frame(80); assert(journey > 0);
paused = true; changeMotion(); frame(120); assert.equal(queue.size, 0); assert.equal(journey, 0);
paused = false; changeMotion(); frame(160); assert.equal(queue.size, 1);
doc.hidden = true; docHandlers.visibilitychange(); assert.equal(queue.size, 0);
doc.hidden = false; docHandlers.visibilitychange(); frame(200); assert.equal(queue.size, 1);
observer([{isIntersecting: false}]); assert.equal(queue.size, 0);
observer([{isIntersecting: true}]); frame(240); assert.equal(queue.size, 1);
skipFn({preventDefault() {}}); assert(focused); assert.equal(scrollOptions.behavior, 'instant');
assert.equal(handlers.wheel, undefined); assert.equal(handlers.touchmove, undefined);
canvas.getContext = () => null;
browserWindow.ADhammerEntrance.mount({isReduced: () => true, onMotionChange() {}});
assert(staticFallback, 'A missing canvas must retain an ordinary document');
console.log('PASS: scene geometry, projection, scroll camera, reduced motion, frame lifecycle, visibility, skip focus, native scrolling, canvas fallback.');
