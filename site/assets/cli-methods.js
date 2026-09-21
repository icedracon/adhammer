/* Examples only. No command execution or connections to assessment targets. */
(function (root) {
  'use strict';
  var esc = root.ADhammerEscExplorer || (typeof require === 'function' ? require('./esc-explorer.js') : null);
  var sourceRoot = 'https://github.com/icedracon/adhammer/blob/7b5e60b4200d2557760867a80d0f1f225e6915dc/';
  var ldap = '--url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt"';
  var methods = [
    {title:'Preflight the connection',format:'JSON checklist',purpose:'Separate connectivity problems from assessment results before collecting directory data.',command:'adhammer doctor --domain example.test --dc dc.example.test --timeout 3 --json',prerequisite:'Authorization for DNS and TCP probes to the specified DC. No credentials are supplied in this example.',behavior:'Uses the DC for DNS SRV discovery and probes AD TCP ports. It does not attempt a credentialed LDAP bind.',result:'Inspect checks, ran, failed, and verdict. Skipped checks are not successful checks; inconclusive is not ready.',limit:'Reachable ports do not establish LDAP authentication, secure configuration, or assessment coverage.',source:'cli/src/doctor.rs'},
    Object.assign({}, esc.commands.template, {title:'Review certificate templates',format:'JSON findings array',purpose:'Find template configuration signals to investigate in an authorized AD CS assessment.',result:'Review each finding’s id, affected objects, detail, and remediation. Match it to the original configuration; an empty array is not an all-clear.'}),
    Object.assign({}, esc.commands.registry, {title:'Read CA configuration',format:'Human-readable text',purpose:'Inspect registry-based CA settings separately from the LDAP template review.',result:'Correlate settings with the correct CA and host role. Record failed or missing reads instead of interpreting them as secure defaults.'}),
    Object.assign({}, esc.commands.web, {title:'Inspect web-enrollment exposure',format:'Human-readable text',purpose:'Discover enterprise CAs and identify HTTP enrollment exposure within the approved host scope.',result:'Use reported CA hosts and HTTP responses to guide a separate configuration review. Exposure alone is not proof of a relay vulnerability.'}),
    {title:'Inventory directory DNS',format:'Human-readable text',purpose:'Understand the AD-integrated DNS records visible to the assessment account.',command:'adhammer enum dns '+ldap+' --text',prerequisite:'Approved LDAP collection scope, a trusted LDAPS certificate, and an account permitted to read the relevant DNS objects.',behavior:'Reads AD-integrated DNS zones and records through LDAP; this example does not update DNS records.',result:'Review visible zones and records. Keep the output private: infrastructure names can be sensitive.',limit:'Visibility depends on directory permissions. This is not a complete external DNS inventory or proof that a listed host is reachable.',source:'cli/src/enums/dns.rs'},
    {title:'Review DC posture',format:'Human-readable text',purpose:'Read configuration relevant to LDAP signing, channel binding, and exposed named pipes.',command:'adhammer enum posture --host dc.example.test --domain EXAMPLE --user auditor --password "@file:./audit-password.txt" --text',prerequisite:'An approved DC and an account permitted to read the relevant configuration through SMB/MS-RRP. Do not enable Remote Registry just to run this example.',behavior:'Reads available registry settings and probes named pipes. It does not execute a coercion or relay attack.',result:'Review each reported value and read failure against the DC’s role and administrative configuration.',limit:'A pipe or registry value does not prove an exploit path. Missing reads and host or patch differences require manual review.',source:'cli/src/enums/posture.rs'}
  ];
  if (typeof module === 'object' && module.exports) module.exports = {methods:methods};
  if (!root.document) return;
  var doc = root.document, selected = 0, film = doc.getElementById('methods-film');
  var picker = Array.from(doc.querySelectorAll('[data-cli-method]'));
  if (!film || !picker.length) return;
  function select(index) {
    selected = index;
    var method = methods[index];
    ['title','format','purpose','command','prerequisite','behavior','result','limit'].forEach(function(key){doc.getElementById('method-'+key).textContent = method[key];});
    doc.getElementById('method-source').href = sourceRoot+method.source;
    doc.getElementById('method-copy-status').textContent = '';
    picker.forEach(function(button,i){button.setAttribute('aria-pressed', String(i === index));});
  }
  picker.forEach(function(button,index){button.addEventListener('click',function(){select(index);});});
  var copy = doc.getElementById('method-copy');
  copy.hidden = false;
  copy.addEventListener('click',async function(){
    try {await root.navigator.clipboard.writeText(methods[selected].command);doc.getElementById('method-copy-status').textContent = 'Copied. Replace the placeholders before use.';}
    catch (_) {doc.getElementById('method-copy-status').textContent = 'Copy unavailable. Select and copy the command above.';}
  });
  film.addEventListener('playing',function(){doc.getElementById('film-status').textContent = '';});
  film.addEventListener('error',function(){doc.getElementById('film-status').textContent = 'Video unavailable here. Use Open video or read the transcript.';});
  select(0);
})(typeof window !== 'undefined' ? window : globalThis);
