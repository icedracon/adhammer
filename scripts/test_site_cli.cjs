'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const {methods} = require('../site/assets/cli-methods.js');
const html = fs.readFileSync(path.join(root,'site/index.html'),'utf8');
assert.equal(methods.length,6);
for (const method of methods) {
  for (const key of ['title','format','purpose','command','prerequisite','behavior','result','limit','source']) assert.ok(method[key],`${method.title}: ${key}`);
  assert.ok(fs.existsSync(path.join(root,method.source)));
  assert.match(method.command,/^adhammer (doctor|check adcs|enum (esc|adcs|dns|posture)) /);
  assert.doesNotMatch(method.command,/--insecure|--allow-plaintext|attack |dump /);
  if(method.command.includes('--password')) assert.ok(method.command.includes('"@file:./audit-password.txt"'));
}
assert.match(html,/<video id="methods-film" data-ambient-video muted loop playsinline/);
assert.equal((html.match(/data-ambient-video/g)||[]).length,3);
assert.equal((html.match(/data-video-toggle=/g)||[]).length,3);
assert.match(html,/id="native-speed"/);
assert.match(html,/data-copy="--fast"/);
assert.match(html,/ADHAMMER_FAST=1/);
assert.match(html,/basic network sweep retains its fixed timeouts/);
assert.match(html,/<track kind="captions"/);
for (const file of ['cli-workflow.mp4','cli-workflow-poster.jpg','cli-workflow.vtt','cli-methods.js','cli-methods.css']) assert.ok(fs.statSync(path.join(root,'site/assets',file)).size>0);
const probe = spawnSync('ffprobe',['-v','error','-show_entries','format=duration:stream=codec_name,width,height,r_frame_rate','-of','json',path.join(root,'site/assets/cli-workflow.mp4')],{encoding:'utf8'});
assert.equal(probe.status,0,probe.stderr);
const media = JSON.parse(probe.stdout);
assert.equal(media.streams[0].codec_name,'h264');
assert.equal(media.streams[0].width,1280);
assert.equal(media.streams[0].height,720);
assert.equal(Number(media.format.duration),18);
// Decode adjacent instants: this must be animated media, not a still in an MP4.
function decode(time) {
  const result = spawnSync('ffmpeg',['-v','error','-ss',String(time),'-i',path.join(root,'site/assets/cli-workflow.mp4'),'-frames:v','1','-f','rawvideo','-pix_fmt','rgb24','-'],{maxBuffer:4*1024*1024});
  assert.equal(result.status,0,result.stderr.toString());
  assert.equal(result.stdout.length,1280*720*3);
  return result.stdout;
}
assert.notDeepEqual(decode(1),decode(1.25));
console.log('PASS: six scoped methods, source paths, example flags, three muted looping videos with pause controls, 720p H.264 duration and actual frame motion');
