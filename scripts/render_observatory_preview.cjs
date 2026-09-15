// Render a finite README preview from the site's SVG and pure state model.
// Requires Python, Pillow and CairoSVG; not part of the website runtime.
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const model=require('../site/assets/observatory.js');
const html=fs.readFileSync(path.join(__dirname,'../site/index.html'),'utf8');
const svg=html.match(/<svg class="observatory-graph"[\s\S]*?<\/svg>/)[0];
let state=model.initial();
const states=[state];
state=model.transition(state,{type:'stage',value:1});states.push(state);
state=model.transition(state,{type:'select',value:2});
state=model.transition(state,{type:'evidence'});states.push(state);
state=model.transition(state,{type:'stage',value:3});states.push(state);
const data={svg,nodes:model.nodes,states,views:states.map(model.describe),output:path.join(__dirname,'../docs/observatory-preview.gif')};
const result=spawnSync('python',[path.join(__dirname,'render_observatory_preview.py')],{input:JSON.stringify(data),encoding:'utf8'});
process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');
if(result.status!==0)process.exit(result.status||1);
if(process.argv[2]){
 const profile=path.resolve(process.argv[2]);
 const p={profile:true,svg:fs.readFileSync(path.join(profile,'assets/profile-banner.svg'),'utf8'),output:path.join(profile,'assets/profile-intro.gif')};
 const r=spawnSync('python',[path.join(__dirname,'render_observatory_preview.py')],{input:JSON.stringify(p),encoding:'utf8'});
 process.stdout.write(r.stdout||'');process.stderr.write(r.stderr||'');process.exit(r.status||0);
}
