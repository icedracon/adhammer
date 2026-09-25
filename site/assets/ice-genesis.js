/* Ice Genesis: the hero dragon rendered as GPU particles that break apart into the illustrative route graph as the
   visitor scrolls. Decorative only; no assessment data. Skipped without WebGL, under reduced motion, and when
   motion is paused. */
(function () {
  'use strict';
  var root = document.documentElement;
  var hero = document.getElementById('top');
  var stage = document.getElementById('living-stage');
  var viewport = hero && hero.querySelector('.entrance-viewport');
  var dragon = stage && stage.querySelector('.dragon-body');
  if (!hero || !stage || !viewport || !dragon) return;
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  function quiet() { return reduced.matches || root.dataset.motion === 'paused'; }
  if (reduced.matches) return;

  var canvas = document.createElement('canvas');
  canvas.className = 'ice-genesis';
  canvas.setAttribute('aria-hidden', 'true');
  var gl = canvas.getContext('webgl', {alpha: true, antialias: false, depth: false, premultipliedAlpha: true, powerPreference: 'high-performance'});
  if (!gl) return;

  var VERT = [
    'attribute vec2 aA; attribute vec4 aE; attribute vec4 aS; attribute vec3 aC;',
    'uniform vec2 uRes; uniform float uP, uT, uIntro, uDpr; uniform vec3 uMouse;',
    'varying vec3 vC; varying float vA;',
    'float h(float n){return fract(sin(n)*43758.5453);}',
    'void main(){',
    '  float s1=aS.x, s2=aS.y, kind=aS.z, size=aS.w; vec2 B;',
    '  if(kind<0.5){ float ang=s2*6.2831+uT*0.04*(0.5+s1); float r=0.72+0.28*s1; B=aE.xy+vec2(cos(ang)*aE.z,sin(ang)*aE.w)*r; }',
    '  else if(kind<1.5){ float ang=s2*6.2831+uT*(0.22+s1*0.35); B=aE.xy+vec2(cos(ang),sin(ang))*aE.z*sqrt(s1); }',
    '  else { float t=fract(s2+uT*(0.05+s1*0.05)); B=mix(aE.xy,aE.zw,t)+vec2(sin(s1*40.0+uT),cos(s1*31.0+uT))*2.2; }',
    '  vec2 scatter=aA+vec2(h(s1*91.7)-0.5,h(s2*57.3)-0.5)*uRes*vec2(0.7,0.9)+vec2(sin(uT*0.9+s2*30.0),cos(uT*0.8+s1*30.0))*30.0;',
    '  float ii=smoothstep(s1*0.5,s1*0.5+0.5,uIntro);',
    '  vec2 A=mix(scatter,aA,ii*ii*(3.0-2.0*ii))+vec2(sin(uT*1.3+s1*50.0),cos(uT*1.1+s2*50.0))*0.7;',
    '  float pp=smoothstep(s1*0.45,s1*0.45+0.55,uP); float e=pp*pp*(3.0-2.0*pp);',
    '  vec2 P=mix(A,B,e);',
    '  float arc=e*(1.0-e)*4.0;',
    '  P+=vec2(sin(s2*20.0+uT*0.7),cos(s1*20.0+uT*0.6))*arc*140.0*(0.4+s1);',
    '  vec2 d=P-uMouse.xy; float f=clamp(1.0-length(d)/170.0,0.0,1.0);',
    '  P+=normalize(d+0.0001)*f*f*78.0*uMouse.z;',
    '  gl_Position=vec4(P.x/uRes.x*2.0-1.0,1.0-P.y/uRes.y*2.0,0.0,1.0);',
    '  vec3 ice=mix(vec3(0.60,0.83,0.95),vec3(0.93,0.98,1.0),h(s1*13.1));',
    '  vC=mix(ice,aC,e); vC=mix(vC,vec3(1.0),f*uMouse.z*0.5);',
    '  vA=min(1.0,uIntro*2.5)*(0.35+0.65*ii)*(0.7+0.3*sin(uT*2.0+s1*60.0))*(0.75+0.75*size)*(1.0+f*uMouse.z*1.2);',
    '  gl_PointSize=(1.5+size*3.1)*uDpr*(1.0+f*uMouse.z*1.1);',
    '}'].join('\n');
  var FRAG = [
    'precision mediump float; varying vec3 vC; varying float vA;',
    'void main(){ float d=length(gl_PointCoord-0.5); float a=smoothstep(0.5,0.0,d); a*=a*vA; gl_FragColor=vec4(vC*a,a); }'].join('\n');

  function shader(type, source) {
    var s = gl.createShader(type); gl.shaderSource(s, source); gl.compileShader(s);
    return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
  }
  var vs = shader(gl.VERTEX_SHADER, VERT), fs = shader(gl.FRAGMENT_SHADER, FRAG);
  if (!vs || !fs) return;
  var program = gl.createProgram();
  gl.attachShader(program, vs); gl.attachShader(program, fs); gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
  gl.useProgram(program);
  var loc = {};
  ['aA', 'aE', 'aS', 'aC'].forEach(function (n) { loc[n] = gl.getAttribLocation(program, n); });
  ['uRes', 'uP', 'uT', 'uIntro', 'uDpr', 'uMouse'].forEach(function (n) { loc[n] = gl.getUniformLocation(program, n); });
  var buffers = {aA: [2], aE: [4], aS: [4], aC: [3]};
  Object.keys(buffers).forEach(function (n) { buffers[n].push(gl.createBuffer()); });
  gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE);

  var seed = 20260925;
  function rand() { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; }
  function hex(c) { return [parseInt(c.slice(1, 3), 16) / 255, parseInt(c.slice(3, 5), 16) / 255, parseInt(c.slice(5, 7), 16) / 255]; }
  var AMBER = hex('#f2b760'), CORAL = hex('#f8795b'), GOLD = hex('#ffd89a'), ICE = hex('#7fb2c2'), DUST = hex('#4f7d8c');

  var samples = null, count = 0, width = 0, height = 0, dpr = 1;

  // Sample opaque dragon pixels, brighter pixels more often.
  function sampleDragon() {
    var w = 480, h = 270, c = document.createElement('canvas'); c.width = w; c.height = h;
    var x = c.getContext('2d'); x.drawImage(dragon, 0, 0, w, h);
    var data = x.getImageData(0, 0, w, h).data, pts = [];
    for (var i = 0; i < w * h; i += 1) {
      var a = data[i * 4 + 3]; if (a < 60) continue;
      var l = (data[i * 4] * .3 + data[i * 4 + 1] * .59 + data[i * 4 + 2] * .11) / 255;
      pts.push({u: (i % w + .5) / w, v: (Math.floor(i / w) + .5) / h, weight: .25 + l * l * 1.8});
    }
    return pts;
  }

  function build() {
    var rect = stage.getBoundingClientRect();
    width = rect.width; height = rect.height;
    dpr = Math.min(window.devicePixelRatio || 1, width < 700 ? 1.25 : 1.6);
    canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
    gl.viewport(0, 0, canvas.width, canvas.height);

    // Undo the rig's scroll-linked scale so the dragon is sampled at rest size.
    var box = dragon.getBoundingClientRect(), scale = 1 - .24 * progress;
    var cx = box.left - rect.left + box.width / 2, cy = box.top - rect.top + box.height / 2;
    var dw = box.width / scale, dh = box.height / scale, u = dw;

    count = width < 700 ? 3600 : 7200;
    var A = new Float32Array(count * 2), E = new Float32Array(count * 4), S = new Float32Array(count * 4), C = new Float32Array(count * 3);
    var cumulative = new Float32Array(samples.length), total = 0;
    samples.forEach(function (p, j) { total += p.weight; cumulative[j] = total; });

    var route = [[-.36, -.02], [-.12, .17], [.12, -.06], [.36, .13]].map(function (p) { return [cx + p[0] * u, cy + p[1] * u]; });
    var minor = [[-.28, -.2], [0, -.23], [.26, -.25], [-.02, .31], [.25, .31], [-.45, .22]].map(function (p) { return [cx + p[0] * u, cy + p[1] * u]; });

    for (var i = 0; i < count; i += 1) {
      // Weighted pick of a dragon pixel, with sub-pixel jitter.
      var r = rand() * total, lo = 0, hi = samples.length - 1;
      while (lo < hi) { var mid = (lo + hi) >> 1; if (cumulative[mid] < r) lo = mid + 1; else hi = mid; }
      var sp = samples[lo];
      A[i * 2] = cx - dw / 2 + (sp.u + (rand() - .5) / 480) * dw;
      A[i * 2 + 1] = cy - dh / 2 + (sp.v + (rand() - .5) / 270) * dh;

      var roll = rand(), kind, e = [0, 0, 0, 0], col, size = rand();
      if (roll < .30) {            // route node clusters
        var n = Math.floor(rand() * 4); kind = 1; e = [route[n][0], route[n][1], u * (n === 3 ? .05 : .04), 0];
        col = n === 3 ? CORAL : AMBER; size = .45 + size * .55;
      } else if (roll < .58) {     // particles flowing along the route
        var m = Math.floor(rand() * 3); kind = 2; e = [route[m][0], route[m][1], route[m + 1][0], route[m + 1][1]];
        col = GOLD; size *= .7;
      } else if (roll < .68) {     // secondary directory objects
        var q = minor[Math.floor(rand() * minor.length)]; kind = 1; e = [q[0], q[1], u * .018, 0]; col = ICE; size *= .6;
      } else {                     // ambient directory dust
        kind = 0; e = [cx, cy + u * .04, u * .62, u * .27]; col = DUST; size *= .5;
      }
      E.set(e, i * 4); S.set([rand(), rand(), kind, size], i * 4); C.set(col, i * 3);
    }
    [['aA', A], ['aE', E], ['aS', S], ['aC', C]].forEach(function (pair) {
      var info = buffers[pair[0]];
      gl.bindBuffer(gl.ARRAY_BUFFER, info[1]); gl.bufferData(gl.ARRAY_BUFFER, pair[1], gl.STATIC_DRAW);
      gl.enableVertexAttribArray(loc[pair[0]]); gl.vertexAttribPointer(loc[pair[0]], info[0], gl.FLOAT, false, 0, 0);
    });
  }

  var progress = 0, targetProgress = 0, start = 0, raf = 0, visible = true, lastFrame = 0;
  var mouse = {x: -9999, y: -9999, z: 0, tz: 0};

  function readScroll() {
    var rect = hero.getBoundingClientRect();
    targetProgress = Math.max(0, Math.min(1, -rect.top / Math.max(1, hero.offsetHeight - viewport.offsetHeight)));
    visible = rect.bottom > 0 && rect.top < window.innerHeight;
  }

  function frame() {
    raf = 0;
    var now = performance.now();
    if (!start) start = now;
    // Time-based easing so the motion feels the same at 30, 60 or 120 fps.
    var dt = Math.min(.1, lastFrame ? (now - lastFrame) / 1000 : 1 / 60);
    progress += (targetProgress - progress) * (1 - Math.exp(-dt * 5));
    mouse.z += (mouse.tz - mouse.z) * (1 - Math.exp(-dt * 7));
    var t = (now - start) / 1000, eased = Math.min(1, progress * 1.25);
    stage.style.setProperty('--genesis', eased.toFixed(3));
    gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform2f(loc.uRes, width, height);
    gl.uniform1f(loc.uP, eased); gl.uniform1f(loc.uT, t);
    gl.uniform1f(loc.uIntro, Math.min(1, t / 3.2)); gl.uniform1f(loc.uDpr, dpr);
    gl.uniform3f(loc.uMouse, mouse.x, mouse.y, mouse.z);
    gl.drawArrays(gl.POINTS, 0, count);
    lastFrame = now;
    schedule();
  }
  function schedule() {
    if (raf || !visible || document.hidden || quiet()) { if (!raf) lastFrame = 0; return; }
    raf = requestAnimationFrame(frame);
  }

  function begin() {
    samples = sampleDragon();
    if (!samples.length) return;
    stage.insertBefore(canvas, stage.querySelector('#living-graph'));
    stage.classList.add('genesis-on');
    readScroll(); progress = targetProgress; build(); schedule();

    window.addEventListener('scroll', function () { readScroll(); schedule(); }, {passive: true});
    if (window.ResizeObserver) new ResizeObserver(function () { build(); schedule(); }).observe(stage);
    viewport.addEventListener('pointermove', function (event) {
      if (event.pointerType === 'touch') return;
      var r = stage.getBoundingClientRect();
      mouse.x = event.clientX - r.left; mouse.y = event.clientY - r.top; mouse.tz = 1; schedule();
    }, {passive: true});
    viewport.addEventListener('pointerleave', function () { mouse.tz = 0; }, {passive: true});
    document.addEventListener('visibilitychange', schedule);
    function onMotionChange() {
      if (reduced.matches) { stage.classList.remove('genesis-on'); canvas.remove(); if (raf) cancelAnimationFrame(raf); raf = 0; return; }
      schedule();
    }
    reduced.addEventListener('change', onMotionChange);
    new MutationObserver(onMotionChange).observe(root, {attributes: true, attributeFilter: ['data-motion']});
    canvas.addEventListener('webglcontextlost', function (event) { event.preventDefault(); stage.classList.remove('genesis-on'); canvas.remove(); });
  }

  if (dragon.complete && dragon.naturalWidth) begin();
  else dragon.addEventListener('load', begin, {once: true});
})();
