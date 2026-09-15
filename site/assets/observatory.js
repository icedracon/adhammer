/* Fictional browser-only model. Selection, evidence and record share one state. */
(function(root){
 'use strict';
 var nodes=[
  {name:'svc-build',kind:'01 / Identity',description:'A fictional service identity. A directory object does not establish usable credentials or a live session.',needed:"The object's source, collection time, and relevant permissions."},
  {name:'workstation-07',kind:'02 / Host',description:'A fictional computer object supplies host context. Its presence does not establish an observed session.',needed:'The source and time of a session observation, if one exists. Keep it separate from directory inventory.'},
  {name:'delegation',kind:'03 / Relationship',description:'A conceptual relationship connects the objects. The edge is a hypothesis, not a demonstrated outcome.',needed:'The relevant configuration, constraints, and recorded evidence. Untested prerequisites remain unknown.'},
  {name:'tier-0',kind:'04 / Boundary',description:'A privileged destination in this fictional model. A connected graph does not establish domain compromise.',needed:'Evidence for every necessary connection. A gap in the route cannot be hidden by its destination.'}
 ];
 var descriptions=['Objects provide context. Their presence is not proof of access.','A connected route is a hypothesis. Select an object to inspect its context.','Evidence is an explicit input, never a reward for scrolling.','The record below uses the same selection, fixture and relationship state.'];
 function initial(){return {stage:0,selected:0,evidence:false,cut:'none'};}
 function transition(state,action){
  var next=Object.assign({},state);
  if(action.type==='stage' && Number.isInteger(action.value) && action.value>=0 && action.value<4)next.stage=action.value;
  if(action.type==='select' && Number.isInteger(action.value) && action.value>=0 && action.value<4)next.selected=action.value;
  if(action.type==='evidence'){next.evidence=!state.evidence;next.stage=2;}
  if(action.type==='cut' && ['none','identity','delegation'].indexOf(action.value)>=0){next.cut=action.value;next.stage=2;}
  return action.type==='reset'?initial():next;
 }
 function describe(state){
  var interrupted=state.cut!=='none';
  return {
   label:interrupted?'Route interrupted / simulation':state.evidence?'Evidence attached / fictional':state.stage===0?'Observed / untested':'Possible / untested',
   evidence:state.evidence?'Synthetic fixture DEMO-001. Not captured assessment output.':'None attached',
   connection:interrupted?'Removed '+state.cut+' relationship in this model':'Intact in the fictional model',
   interpretation:interrupted?'This illustrated route is disconnected. Other routes remain untested; this is not proof that an environment is secure.':state.evidence?'A synthetic fixture illustrates evidence handling. It does not validate a real environment.':'An observed object or connected route is not proof of access.',
   detail:interrupted?(state.evidence?'The earlier fixture is retained; it does not prove the changed route.':'No evidence fixture is attached.'):(state.evidence?'Synthetic fixture only. No real assessment was performed.':'No evidence fixture is attached.')
  };
 }
 function mount(){
  var doc=root.document,host=doc.getElementById('engine');
  if(!host || !doc.getElementById('observatory-workbench'))return;
  var state=initial(),manual=false,queued=false;
  var stages=Array.from(host.querySelectorAll('[data-ob-stage]')),buttons=Array.from(host.querySelectorAll('[data-ob-node]'));
  var reduced=root.matchMedia('(prefers-reduced-motion: reduce)');
  function text(id,value){doc.getElementById(id).textContent=value;}
  function render(){
   var node=nodes[state.selected],view=describe(state);
   host.dataset.stage=String(state.stage);host.dataset.evidence=state.evidence?'attached':'pending';host.dataset.cut=state.cut;
   stages.forEach(function(button,index){button.setAttribute('aria-pressed',String(index===state.stage));});
   buttons.forEach(function(button,index){button.setAttribute('aria-pressed',String(index===state.selected));});
   text('ob-kind',node.kind);text('ob-name',node.name);text('ob-description',node.description);text('ob-needed',node.needed);
   text('ob-state-label',view.label);text('ob-state-detail',view.detail);text('ob-stage-description',descriptions[state.stage]);
   text('ob-next',['Map relationships →','Inspect the evidence →','View the record ↓','Back to discovery ↶'][state.stage]);
   text('ob-attach',state.evidence?'Remove fictional evidence −':'Attach fictional evidence ＋');
   doc.getElementById('ob-attach').setAttribute('aria-pressed',String(state.evidence));
   text('ob-cut',state.cut==='none'?'Remove relationship':'Restore relationship');
   doc.getElementById('ob-cut').setAttribute('aria-pressed',String(state.cut!=='none'));
   host.querySelector('.ob-scene-caption i').textContent='0'+(state.stage+1)+' / 04';
   text('ob-report-kind',node.kind);text('ob-report-name',node.name);text('ob-report-state',view.label);
   text('ob-report-evidence',view.evidence);text('ob-report-connection',view.connection);text('ob-report-interpretation',view.interpretation);
   doc.dispatchEvent(new CustomEvent('adhammer:route-selection',{detail:{index:state.selected}}));
  }
  function act(action){manual=true;state=transition(state,action);render();}
  function showRecord(){
   var report=doc.getElementById('proof');report.setAttribute('tabindex','-1');report.focus({preventScroll:true});
   report.scrollIntoView({behavior:reduced.matches||doc.documentElement.dataset.motion==='paused'?'instant':'smooth',block:'start'});
  }
  stages.forEach(function(button,index){button.addEventListener('click',function(){act({type:'stage',value:index});if(index===3)showRecord();});});
  buttons.forEach(function(button,index){button.addEventListener('click',function(){act({type:'select',value:index});});});
  function keyboard(group,attribute){
   group.forEach(function(button,index){button.addEventListener('keydown',function(event){
    var next=index;if(event.key==='ArrowRight')next=(index+1)%group.length;else if(event.key==='ArrowLeft')next=(index+group.length-1)%group.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=group.length-1;else return;
    event.preventDefault();group[next].focus();act({type:attribute,value:next});
   });});
  }
  keyboard(stages,'stage');keyboard(buttons,'select');
  doc.getElementById('ob-attach').addEventListener('click',function(){act({type:'evidence'});});
  doc.getElementById('ob-cut').addEventListener('click',function(){act({type:'cut',value:state.cut==='none'?doc.getElementById('ob-relationship').value:'none'});});
  doc.getElementById('ob-relationship').addEventListener('change',function(event){manual=true;if(state.cut!=='none')act({type:'cut',value:event.target.value});});
  doc.getElementById('ob-reset').addEventListener('click',function(){doc.getElementById('ob-relationship').value='delegation';act({type:'reset'});});
  doc.getElementById('ob-next').addEventListener('click',function(){var next=(state.stage+1)%4;act({type:'stage',value:next});if(next===3)showRecord();});
  function syncScroll(){
   queued=false;
   if(manual||reduced.matches||doc.hidden||doc.documentElement.dataset.motion==='paused'||root.innerWidth<=760)return;
   var rect=host.getBoundingClientRect();if(rect.bottom<0||rect.top>root.innerHeight)return;
   var next=Math.max(0,Math.min(3,Math.floor((-rect.top+root.innerHeight*.12)/Math.max(1,rect.height-root.innerHeight*.4)*4)));
   if(next!==state.stage){state=transition(state,{type:'stage',value:next});render();}
  }
  root.addEventListener('scroll',function(){if(!queued&&!manual){queued=true;root.requestAnimationFrame(syncScroll);}},{passive:true});
  function openAnchor(){
   var id;try{id=decodeURIComponent(root.location.hash.slice(1));}catch(_){return;}
   if(!id)return;var element=doc.getElementById(id);if(!element)return;
   if(element.matches('details'))element.open=true;
  }
  root.addEventListener('hashchange',openAnchor);openAnchor();
  host.querySelector('.observatory-stages').hidden=false;
  ['ob-next','ob-attach','ob-cut','ob-reset'].forEach(function(id){doc.getElementById(id).hidden=false;});
  render();
 }
 var api={initial:initial,transition:transition,describe:describe,nodes:nodes};
 if(typeof module==='object'&&module.exports)module.exports=api;
 else{root.ADhammerObservatory=api;mount();}
})(typeof window!=='undefined'?window:globalThis);
