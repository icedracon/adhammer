/* Perspective-projected directory graph. No network, dependencies, or scroll interception. */
(function (root) {
  'use strict';
  function clamp(value, min, max) { return Math.max(min, Math.min(max, value)); }
  function createScene() {
    var seed = 1847;
    function random() { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; }
    var nodes = [
      {x: -.72, y: .12, z: .12, label: 'SVC-BUILD'},
      {x: -.24, y: -.14, z: .28, label: 'WORKSTATION-07'},
      {x: .25, y: .08, z: -.08, label: 'DELEGATION'},
      {x: .70, y: -.18, z: .10, label: 'TIER-0'}
    ];
    for (var i = 0; i < 64; i += 1) {
      var angle = random() * Math.PI * 2;
      var radius = .52 + random() * .64;
      nodes.push({x: Math.cos(angle) * radius, y: Math.sin(angle) * radius * .55, z: (random() - .5) * 1.65});
    }
    var edges = [{a: 0, b: 1, route: 0}, {a: 1, b: 2, route: 1}, {a: 2, b: 3, route: 2}];
    var seen = new Set(['0:1','1:2','2:3']);
    nodes.forEach(function (node, index) {
      var nearest = nodes.map(function (other, j) {
        return {index: j, distance: Math.pow(node.x-other.x,2)+Math.pow(node.y-other.y,2)+Math.pow(node.z-other.z,2)};
      }).filter(function (item) { return item.index !== index; }).sort(function (a,b) { return a.distance-b.distance; });
      nearest.slice(0,2).forEach(function (item) {
        var a = Math.min(index,item.index), b = Math.max(index,item.index), key = a+':'+b;
        if (!seen.has(key)) { edges.push({a:a,b:b,route:-1}); seen.add(key); }
      });
    });
    return {nodes:nodes,edges:edges};
  }
  function cameraFor(progress, reduced, pointer) {
    var p = reduced ? 0 : clamp(progress,0,1);
    return {yaw: .12+p*.68+(reduced?0:pointer.x*.16), pitch: -.10+(reduced?0:pointer.y*.10), distance: 3.35-p*1.25};
  }
  function project(node, camera) {
    var cy=Math.cos(camera.yaw),sy=Math.sin(camera.yaw),cx=Math.cos(camera.pitch),sx=Math.sin(camera.pitch);
    var x=node.x*cy-node.z*sy, z=node.x*sy+node.z*cy;
    var y=node.y*cx-z*sx, depth=node.y*sx+z*cx;
    var scale=2/Math.max(.45,camera.distance-depth);
    return {x:x*scale,y:y*scale,z:depth,scale:scale};
  }
  function mount(options) {
    var doc=root.document, hero=doc.getElementById('top'), stage=doc.querySelector('.entrance-viewport');
    var canvas=doc.getElementById('living-graph'), header=doc.getElementById('header');
    if (!hero || !stage || !canvas) return;
    var ctx=null;
    try { ctx=canvas.getContext('2d'); } catch (_) { /* Keep the ordinary document available. */ }
    if (!ctx) { hero.classList.add('entrance-static'); return; }
    var scene=createScene(), width=0,height=0,dpr=1,raf=0,lastTime=0;
    var targetProgress=0,progress=0,visible=true;
    var pointer={x:0,y:0}, targetPointer={x:0,y:0};
    var skip=doc.getElementById('skip-entrance');
    function reduced() { return options.isReduced(); }
    function updateScroll() {
      var rect=hero.getBoundingClientRect();
      targetProgress=clamp(-rect.top/Math.max(1,hero.offsetHeight-stage.offsetHeight),0,1);
      visible=rect.bottom>0 && rect.top<root.innerHeight;
      if (header) header.classList.toggle('at-entrance',rect.bottom>root.innerHeight*.4 && rect.top<=1);
      requestDraw();
    }
    function resize() {
      var rect=stage.getBoundingClientRect();
      width=rect.width; height=rect.height;
      dpr=Math.min(root.devicePixelRatio||1,root.innerWidth<700?1.25:1.5);
      canvas.width=Math.round(width*dpr); canvas.height=Math.round(height*dpr);
      ctx.setTransform(dpr,0,0,dpr,0,0);
      updateScroll();
    }
    function draw(time) {
      if (!width || !height) return;
      var quiet=reduced();
      progress=quiet?0:progress+(targetProgress-progress)*.1;
      pointer.x=quiet?0:pointer.x+(targetPointer.x-pointer.x)*.07;
      pointer.y=quiet?0:pointer.y+(targetPointer.y-pointer.y)*.07;
      stage.style.setProperty('--journey',progress.toFixed(4));
      var camera=cameraFor(progress,quiet,pointer);
      var compact=width<641;
      var xUnit=Math.min(width*.42,height*.68), yUnit=height*.42;
      var points=scene.nodes.map(function (node) {
        var p=project(node,camera);
        return {x:width*.5+p.x*xUnit,y:height*(compact?.34:.36)+p.y*yUnit,z:p.z,scale:p.scale};
      });
      ctx.clearRect(0,0,width,height);
      scene.edges.forEach(function (edge) {
        if (edge.route>=0) return;
        var a=points[edge.a],b=points[edge.b];
        var alpha=clamp(.11+(a.z+b.z)*.04,.035,.23);
        ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y);
        ctx.strokeStyle='rgba(122,192,204,'+alpha+')'; ctx.lineWidth=.7; ctx.stroke();
      });
      var trace=quiet?3:clamp(.28+progress*3.7,0,3);
      for (var i=0;i<3;i+=1) {
        var a=points[i],b=points[i+1],amount=clamp(trace-i,0,1);
        ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
        ctx.lineWidth=1;ctx.strokeStyle='rgba(246,121,91,.19)';ctx.stroke();
        if (!amount) continue;
        ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(a.x+(b.x-a.x)*amount,a.y+(b.y-a.y)*amount);
        ctx.strokeStyle='#f8795b';ctx.lineWidth=1.6;ctx.shadowColor='#f8795b';ctx.shadowBlur=8;ctx.stroke();ctx.shadowBlur=0;
      }
      points.map(function (p,index) {return {p:p,index:index};}).sort(function(a,b){return a.p.z-b.p.z;}).forEach(function(item){
        var p=item.p, route=item.index<4;
        ctx.beginPath();ctx.arc(p.x,p.y,(route?3.2:1.6)*p.scale,0,Math.PI*2);
        ctx.fillStyle=route?'#ffb49d':'rgba(183,224,225,'+clamp(.45+p.z*.18,.2,.75)+')';ctx.fill();
        if (route) {ctx.beginPath();ctx.arc(p.x,p.y,8*p.scale,0,Math.PI*2);ctx.strokeStyle='rgba(248,121,91,.35)';ctx.lineWidth=1;ctx.stroke();}
        if (route && (progress>.30 || quiet) && p.y<height*.55) {
          ctx.font='12px ui-monospace, monospace';ctx.textAlign='center';ctx.fillStyle='#c8d8d6';
          var labelX=clamp(p.x,64,width-64);
          ctx.fillText(scene.nodes[item.index].label,labelX,p.y+24);
        }
      });
      if (!quiet) {
        var segment=(time*.00018)%3,index=Math.floor(segment),part=segment-index;
        if(segment<trace){
          var start=points[index],end=points[index+1],x=start.x+(end.x-start.x)*part,y=start.y+(end.y-start.y)*part;
          ctx.beginPath();ctx.arc(x,y,2.4,0,Math.PI*2);ctx.fillStyle='#fff2df';ctx.shadowColor='#f8795b';ctx.shadowBlur=14;ctx.fill();ctx.shadowBlur=0;
        }
      }
    }
    function tick(time) {
      raf=0;
      if (doc.hidden || !visible) return;
      if (reduced() || time-lastTime>=32) {lastTime=time;draw(time);}
      if (!reduced()) requestDraw();
    }
    function requestDraw() { if (!raf && visible && !doc.hidden) raf=root.requestAnimationFrame(tick); }
    stage.addEventListener('pointermove',function(event){
      if(reduced() || event.pointerType==='touch')return;
      var rect=stage.getBoundingClientRect();
      targetPointer.x=(event.clientX-rect.left)/Math.max(1,rect.width)-.5;
      targetPointer.y=(event.clientY-rect.top)/Math.max(1,rect.height)-.5;
      requestDraw();
    },{passive:true});
    stage.addEventListener('pointerleave',function(){targetPointer.x=0;targetPointer.y=0;},{passive:true});
    root.addEventListener('scroll',updateScroll,{passive:true});
    root.addEventListener('resize',resize,{passive:true});
    doc.addEventListener('visibilitychange',function(){
      if(doc.hidden && raf){root.cancelAnimationFrame(raf);raf=0;}else requestDraw();
    });
    if(root.ResizeObserver)new root.ResizeObserver(resize).observe(stage);
    if(root.IntersectionObserver)new root.IntersectionObserver(function(entries){
      visible=entries[0].isIntersecting;
      if(!visible && raf){root.cancelAnimationFrame(raf);raf=0;}else requestDraw();
    }).observe(hero);
    if(skip)skip.addEventListener('click',function(event){
      var engine=doc.getElementById('engine');if(!engine)return;
      event.preventDefault();engine.setAttribute('tabindex','-1');engine.focus({preventScroll:true});
      root.scrollTo({top:root.scrollY+engine.getBoundingClientRect().top-88,behavior:'instant'});
    });
    options.onMotionChange(function(){
      if(raf){root.cancelAnimationFrame(raf);raf=0;}
      lastTime=0;resize();
    });
    resize();
  }
  var api={createScene:createScene,cameraFor:cameraFor,project:project,mount:mount};
  if(typeof module==='object' && module.exports)module.exports=api;
  else root.ADhammerEntrance=api;
})(typeof window!=='undefined'?window:globalThis);
