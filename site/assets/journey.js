/* A shared selection for the illustrative route and its evidence view. */
(function () {
  'use strict';
  var nodes = [
    {name:'svc-build',kind:'Starting identity',description:'A fictional service identity starts this route. Its permissions and relationships supply context; its presence alone does not establish compromise.',evidence:'Confirm the identity and relevant permissions from collected directory objects. Do not infer usable credentials or a live session.'},
    {name:'workstation-07',kind:'Host context',description:'A fictional host supplies context for the next relationship. A directory computer object and an observed user session are different kinds of evidence.',evidence:'Record the source and time of any session observation. A computer object alone does not prove that an identity is present or usable on the host.'},
    {name:'delegation',kind:'Control relationship',description:'This label represents a relationship to examine, not an automatic permission to act. The precise delegation configuration and prerequisites determine what may be possible.',evidence:'Inspect the actual attributes, principals, constraints, and applicable permissions. A graph edge is a hypothesis until a supported validation produces evidence.'},
    {name:'tier-0',kind:'Privileged boundary',description:'Tier-0 denotes a privileged destination in this conceptual route. Reaching it in a graph does not establish domain compromise.',evidence:'Retain the full route and the evidence for each required step. Unsupported or untested links must remain explicitly unproven.'}
  ];
  var buttons=Array.prototype.slice.call(document.querySelectorAll('[data-route-node]'));
  var title=document.getElementById('journey-node-title');
  if(!title || !buttons.length)return;
  function select(index, announce) {
    var node=nodes[index];if(!node)return;
    document.getElementById('journey-kind').textContent=node.kind;
    title.textContent=node.name;
    document.getElementById('journey-description').textContent=node.description;
    document.getElementById('journey-evidence').textContent=node.evidence;
    buttons.forEach(function(button){button.setAttribute('aria-pressed',String(Number(button.dataset.routeNode)===index));});
    document.querySelectorAll('[data-record-node]').forEach(function(element){element.classList.toggle('selected',Number(element.dataset.recordNode)===index);});
    document.getElementById('journey-record-selection').textContent='Inspecting '+node.name+' · same selection as Route 01.';
    document.documentElement.setAttribute('data-selected-node',String(index));
    document.dispatchEvent(new CustomEvent('adhammer:route-selection',{detail:{index:index}}));
  }
  buttons.forEach(function(button,index){
    button.addEventListener('click',function(){select(index,true);});
    button.addEventListener('keydown',function(event){
      var next=index;
      if(event.key==='ArrowRight')next=(index+1)%nodes.length;
      else if(event.key==='ArrowLeft')next=(index+nodes.length-1)%nodes.length;
      else if(event.key==='Home')next=0;
      else if(event.key==='End')next=nodes.length-1;
      else return;
      event.preventDefault();buttons[next].focus();select(next,true);
    });
  });
  window.ADhammerJourney={
    setStage:function(stage,proven){
      var label=document.getElementById('journey-state');
      var labels=['Observed objects','Possible relationship','Evidence pending · demo','Record assembled · demo'];
      label.textContent=stage===2 && proven?'Evidence attached · demo':labels[stage];
      label.dataset.tone=(stage===2 && proven)||stage===3?'proven':stage===2?'pending':stage===1?'possible':'observed';
    }
  };
  select(0,false);
})();
