/* Documentation only: this module never connects to an assessment target. */
(function (root) {
  'use strict';
  var sourceRoot = 'https://github.com/icedracon/adhammer/blob/7b5e60b4200d2557760867a80d0f1f225e6915dc/';
  var templateCommand = 'adhammer check adcs --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --json';
  var registryCommand = 'adhammer enum esc --host ca.example.test --domain EXAMPLE --user auditor --password "@file:./audit-password.txt" --ca EXAMPLE-CA --text';
  var commands = {
    template: {
      label: 'Template configuration check', command: templateCommand,
      prerequisite: 'Approved LDAP collection scope, a trusted LDAPS certificate, and an account allowed to read the relevant directory objects.',
      behavior: 'Connects to LDAP, collects directory data, extracts certificate templates, and runs the template rules. JSON findings go to stdout. It does not issue certificates.',
      limit: 'Not a complete ACL walk or CA registry audit. The shared checker can return several ESC classes; there is no per-class filter in this example.',
      source: 'cli/src/checks/adcs.rs', steps: ['Read directory', 'Inspect template', 'Retain context', 'Review finding']
    },
    registry: {
      label: 'Registry configuration check', command: registryCommand,
      prerequisite: 'Approved CA host and CA configuration name, plus an account permitted to read its registry over SMB/MS-RRP. Remote Registry must already be available under your security policy.',
      behavior: 'Reads CA configuration and evaluates registry-based rules. It does not modify settings or request a certificate. --text requests human-readable output.',
      limit: 'Some reads may fail or be omitted. An empty result is not proof of safety. DC-specific checks need a DC; a CA-only host cannot establish domain-controller policy.',
      source: 'cli/src/enums/esc_registry.rs', steps: ['Read approved host', 'Inspect setting', 'Check host role', 'Review finding']
    },
    web: {
      label: 'CA discovery + HTTP exposure probe',
      command: 'adhammer enum adcs --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --text',
      prerequisite: 'Authorization for LDAP discovery AND HTTP probes to discovered CA hosts. An approved LDAP server alone does not authorize every discovered CA.',
      behavior: 'Enumerates enterprise CAs and probes their web-enrollment exposure over HTTP/80. This is active network probing, not passive collection; it performs no relay or certificate issuance.',
      limit: 'Not a complete HTTPS, EPA, authentication, or enrollment audit. No HTTP/80 exposure detected does not mean all enrollment endpoints are secure.',
      source: 'cli/src/enums/adcs.rs', steps: ['Discover CAs', 'Probe HTTP exposure', 'Record response', 'Review configuration']
    },
    manual: {
      label: 'Manual review required', command: null,
      prerequisite: 'Use your approved administrative review process and read-only access to the relevant configuration.',
      behavior: 'No focused defensive ADhammer command is documented here for this class. The template checker is not a substitute for the missing context.',
      limit: 'This is a boundary of this guide, not a claim that no related implementation exists. Consult the ledger before relying on a broader workflow.',
      source: 'docs/VALIDATION.md', steps: ['Gather evidence', 'Inspect configuration', 'Review permissions', 'Document limits']
    }
  };
  var items = [
    {id:1, family:'Templates', title:'Who defines the identity?', check:'template', focus:'Subject configuration',
      meaning:'ESC1 concerns identity control in certificate templates. Risk depends on the template, enrollment permissions, approval controls, and the accepting service.',
      result:'Look for A-Esc1-ms-crtd and its affected template. Treat it as a configuration lead, not proof of impersonation.',
      boundary:'Template checking is separate from active enrollment. No certificate is issued by this example.',
      remedy:'Constrain requester-controlled identity fields, restrict enrollment, and review approval requirements.'},
    {id:2, family:'Templates', title:'A certificate with too much scope.', check:'template', focus:'Certificate purposes',
      meaning:'ESC2 concerns overly broad certificate purposes. A certificate may be trusted for more uses than its owner intended.',
      result:'Look for A-Esc2-ms-crtd. Review the intended certificate uses and who can enroll; broad purpose alone does not establish another user’s identity.',
      boundary:'The template result does not test every service that might accept a certificate.',
      remedy:'Limit certificate purposes to business needs and restrict enrollment permissions.'},
    {id:3, family:'Templates', title:'Enrollment is delegated trust.', check:'template', focus:'Enrollment-agent role',
      meaning:'ESC3 concerns enrollment-agent authority: who may request certificates on behalf of others, and how that authority is constrained.',
      result:'Look for A-Esc3-ms-crtd. Confirm agent restrictions, eligible recipients, and the relevant approval controls separately.',
      boundary:'The ledger marks the related MS-ICPR submission path offline-only, with live submission evidence still owed. This checker does not validate that chain.',
      remedy:'Restrict enrollment agents, their recipient scope, and the templates they can use.'},
    {id:4, family:'Permissions', title:'Who can rewrite the template?', check:'manual', focus:'Template ownership + ACL',
      meaning:'ESC4 concerns control over template configuration. An unsafe owner or permission assignment can undermine otherwise appropriate settings.',
      result:'Review the template owner, effective write permissions, inherited entries, and change history with the PKI owner.',
      boundary:'check adcs does not perform the complete ACL walk needed here. No template-changing command is included.',
      remedy:'Remove unnecessary template-management rights and monitor changes to ownership and permissions.'},
    {id:5, family:'Permissions', title:'Trust extends beyond templates.', check:'manual', focus:'PKI directory objects',
      meaning:'ESC5 concerns permissions over other PKI objects and infrastructure. Template properties alone do not describe that administrative boundary.',
      result:'Review effective permissions and ownership across the relevant PKI directory objects. Preserve the object identity and why each permission is required.',
      boundary:'A template-only check cannot establish the security of the wider PKI hierarchy.',
      remedy:'Minimize PKI administration rights, document ownership, and monitor directory-object changes.'},
    {id:6, family:'CA settings', title:'One CA setting. Wider consequences.', check:'registry', focus:'CA subject policy',
      meaning:'ESC6 concerns a CA-wide subject-name policy that can affect how certificate identities are accepted, beyond individual template settings.',
      result:'Review A-Esc6 with the CA policy and published-template context. Confirm current mapping enforcement and other prerequisites before drawing conclusions.',
      boundary:'A registry condition is not a demonstrated authentication outcome.',
      remedy:'Remove unnecessary CA-wide requester-supplied identity allowances through approved change control.'},
    {id:7, family:'Permissions', title:'Who administers the authority?', check:'registry', focus:'CA management rights',
      meaning:'ESC7 concerns CA management and certificate-approval permissions. These roles need a tightly controlled administrative boundary.',
      result:'The implementation also inspects the CA Security descriptor. Review A-Esc7 and confirm effective role membership and permission scope.',
      boundary:'The CLI’s short help names ESC6/10/11/16, but its handler also checks ESC7. Read failures and identity classification still need review.',
      remedy:'Limit CA management and approval rights to designated, monitored administrators.'},
    {id:8, family:'Transport', title:'Inspect the enrollment boundary.', check:'web', focus:'Web-enrollment exposure',
      meaning:'ESC8 concerns relay risk at web-based enrollment endpoints. Endpoint exposure and authentication protections are separate pieces of evidence.',
      result:'Review discovered CA hosts and the reported HTTP exposure. Inspect HTTPS and Extended Protection for Authentication independently.',
      boundary:'End-to-end AD CS HTTP relay validation is owed in the ledger. This probe is not proof that a relay succeeds.',
      remedy:'Review enrollment endpoints, enforce appropriate transport and authentication protections, and remove unused interfaces.'},
    {id:9, family:'Identity mapping', title:'Keep identity binding intact.', check:'template', focus:'Template security extension',
      meaning:'ESC9 concerns template settings that omit a certificate security extension used in identity binding. The effect depends on the authenticating service and patch state.',
      result:'Look for A-Esc9-ms-crtd, then inspect current certificate mapping enforcement. Do not infer effective DC behavior from template flags alone.',
      boundary:'Modern enforcement changes can invalidate legacy assumptions. Consult current Microsoft mapping guidance.',
      remedy:'Retain identity-binding protections and review compatibility with current strong-mapping requirements.'},
    {id:10, family:'Identity mapping', title:'Configuration is not effective policy.', check:'manual', focus:'DC mapping + patch state',
      meaning:'ESC10 concerns weak certificate-to-account mapping. The relevant service, Windows updates, and effective policy all matter.',
      result:'ADhammer’s registry checker contains a DC-gated legacy mapping check. Review current OS behavior and authentication events with the identity administrator.',
      boundary:'No standalone command is supplied: enum esc also expects CA configuration, and a CA-only probe does not establish DC policy. Legacy registry values are not reliable proof of current enforcement.',
      remedy:'Follow current Microsoft strong-mapping guidance and validate compatibility before policy changes.'},
    {id:11, family:'Transport', title:'Protect the RPC enrollment channel.', check:'registry', focus:'RPC privacy requirement',
      meaning:'ESC11 concerns protection of the RPC certificate-enrollment interface. Transport policy must preserve the enrollment authentication boundary.',
      result:'Review A-Esc11 and the underlying read. The handler can treat a missing or unreadable InterfaceFlags value as zero; confirm the actual configuration before accepting the finding.',
      boundary:'End-to-end ICPR relay validation is owed in the ledger. A registry finding is not proof of a successful relay.',
      remedy:'Require packet privacy for RPC enrollment and review legacy client dependencies before changing service policy.'},
    {id:12, family:'Key protection', title:'The boundary includes the key.', check:'manual', focus:'Hardware-backed key custody',
      meaning:'ESC12 concerns protection around hardware-backed CA keys. Key custody requires a review beyond directory-template data.',
      result:'Review the hardware provider, administrative access, operational procedures, and vendor guidance with the PKI owner.',
      boundary:'Hardware-token / YubiHSM validation remains out of scope for this site’s documented ADhammer coverage. No test command is supplied.',
      remedy:'Follow the hardware vendor’s key-protection guidance and tightly control administrative access.'},
    {id:13, family:'Identity mapping', title:'A policy can carry authorization.', check:'template', focus:'Issuance policy + group link',
      meaning:'ESC13 concerns issuance policies linked to group authorization. A certificate policy needs to be understood together with its directory relationships.',
      result:'Look for A-Esc13-ms-crtd. The template checker reports policy identifiers; verify the actual group link and effective rights separately.',
      boundary:'A policy OID on a template does not by itself prove that a privileged group is linked or reachable.',
      remedy:'Audit issuance-policy group links and restrict enrollment where they convey sensitive authorization.'},
    {id:14, family:'Identity mapping', title:'Review the explicit identity link.', check:'manual', focus:'Explicit certificate mappings',
      meaning:'ESC14 concerns explicit certificate-to-account mappings and the permissions governing those links.',
      result:'Review mapping entries, their strength, the intended account binding, and who can modify them.',
      boundary:'The focused template checker does not validate explicit account mappings. No dedicated defensive example is verified here.',
      remedy:'Use supported strong mappings, limit who can edit them, and monitor mapping changes.'},
    {id:15, family:'Templates', title:'Version and patch context matter.', check:'template', focus:'Template schema + CA updates',
      meaning:'ESC15 concerns application-policy handling associated with CVE-2024-49019. Template shape and CA patch state must be interpreted together.',
      result:'Look for A-Esc15-ms-crtd. The schema-based signal does not check whether the CA has the relevant security update.',
      boundary:'Do not label every schema-v1 template exploitable. This example neither submits a request nor verifies a vulnerable CA.',
      remedy:'Apply the relevant CA security updates and review legacy templates and enrollment permissions.'},
    {id:16, family:'Identity mapping', title:'A CA-wide identity-binding gap.', check:'registry', focus:'CA security-extension policy',
      meaning:'ESC16 concerns CA-wide suppression of the certificate security extension. Review it alongside the policies of services that accept issued certificates.',
      result:'Review A-Esc16 and the CA extension configuration. Confirm current strong-mapping behavior and patch state independently.',
      boundary:'A CA setting alone does not establish successful authentication as another identity.',
      remedy:'Preserve certificate identity-binding protections and align CA configuration with current mapping requirements.'}
  ];
  function mount() {
    var doc = root.document, host = doc.getElementById('esc-explorer');
    if (!host) return;
    var picker = doc.getElementById('esc-picker'), dial = doc.getElementById('esc-dial'), buttons = [], animations = [], selected = 0;
    var wheelTotal = 0, wheelTime = -Infinity, lastWheel = -Infinity, touchStart = null;
    var reduced = root.matchMedia('(prefers-reduced-motion: reduce)');
    function set(id, text) { doc.getElementById(id).textContent = text; }
    function stopped() { return reduced.matches || doc.hidden || doc.documentElement.dataset.motion === 'paused'; }
    function cancel() { animations.forEach(function(a) { a.cancel(); }); animations = []; }
    function play() {
      cancel();
      if (stopped() || !host.animate) return;
      host.querySelectorAll('.esc-flow li').forEach(function(step, index) {
        animations.push(step.animate([{backgroundColor:'#392c26',borderColor:'#ff997c'},{backgroundColor:'#172124',borderColor:'#3d4848'}],{duration:1100,delay:index*700,iterations:1}));
      });
    }
    function select(index, animate) {
      selected = index;
      var item = items[index], check = commands[item.check];
      dial.style.setProperty('--turn', (-index * 22.5) + 'deg');
      set('esc-dial-number', 'ESC' + item.id); set('esc-dial-family', item.family);
      set('esc-dial-title', item.title); set('esc-dial-description', item.meaning);
      set('esc-dial-count', String(item.id).padStart(2, '0') + ' / 16');
      doc.getElementById('esc-previous').disabled = index === 0;
      doc.getElementById('esc-next').disabled = index === items.length - 1;
      buttons.forEach(function(b, n) { b.setAttribute('aria-pressed', String(n === index)); });
      set('esc-number', 'ESC' + item.id); set('esc-family', item.family); set('esc-heading', item.title);
      set('esc-meaning', item.meaning); set('esc-focus', item.focus); set('esc-boundary', item.boundary);
      set('esc-check-label', check.label); set('esc-prerequisite', check.prerequisite);
      set('esc-behavior', check.behavior); set('esc-check-limit', check.limit);
      set('esc-result', item.result); set('esc-remedy', item.remedy);
      set('esc-command', check.command || 'No verified focused command for this card. See the review guidance below.');
      doc.getElementById('esc-copy').hidden = !check.command;
      set('esc-copy', 'Copy example'); set('esc-copy-status', '');
      doc.getElementById('esc-code-source').href = sourceRoot + check.source;
      var flow = host.querySelectorAll('.esc-flow li');
      flow.forEach(function(step, n) { step.querySelector('b').textContent = check.steps[n]; });
      set('esc-flow-caption', 'Illustrative review sequence / ESC' + item.id + ' / not a running test');
      set('esc-selection-status', 'ESC' + item.id + ' selected. ' + check.label + '.');
      if (animate) play(); else cancel();
    }
    items.forEach(function(item, index) {
      var b = doc.createElement('button'); b.type = 'button'; b.textContent = 'ESC' + item.id;
      b.style.setProperty('--slot', String(index));
      b.setAttribute('aria-label', 'ESC' + item.id + ': ' + item.title); b.setAttribute('aria-controls', 'esc-detail');
      b.addEventListener('click', function() { select(index, true); });
      b.addEventListener('keydown', function(e) {
        var next = index;
        if (e.key === 'ArrowRight') next = (index + 1) % items.length;
        else if (e.key === 'ArrowLeft') next = (index + items.length - 1) % items.length;
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = items.length - 1;
        else return;
        e.preventDefault(); buttons[next].focus(); select(next, true);
      });
      buttons.push(b); picker.appendChild(b);
    });
    function step(direction) {
      var next = selected + direction;
      if (next < 0 || next >= items.length) return false;
      select(next, true); return true;
    }
    doc.getElementById('esc-previous').addEventListener('click', function() { step(-1); });
    doc.getElementById('esc-next').addEventListener('click', function() { step(1); });
    // Only the dial consumes wheel gestures. At either end, native scrolling resumes.
    dial.addEventListener('wheel', function(e) {
      if (e.ctrlKey || e.metaKey || doc.hidden) return;
      var delta = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
      if (!delta) return;
      delta *= e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 300 : 1;
      var direction = Math.sign(delta), now = e.timeStamp;
      if ((selected === 0 && direction < 0) || (selected === items.length - 1 && direction > 0)) { wheelTotal = 0; return; }
      if (!e.cancelable) return;
      e.preventDefault();
      if (now - lastWheel > 250 || Math.sign(wheelTotal) !== direction) wheelTotal = 0;
      lastWheel = now;
      if (now - wheelTime < 220) return;
      wheelTotal += delta;
      if (Math.abs(wheelTotal) >= 55) { wheelTotal = 0; wheelTime = now; step(direction); }
    }, {passive:false});
    dial.addEventListener('touchstart', function(e) {
      touchStart = e.touches.length === 1 ? {x:e.touches[0].clientX,y:e.touches[0].clientY} : null;
    }, {passive:true});
    dial.addEventListener('touchend', function(e) {
      if (!touchStart || e.changedTouches.length !== 1) { touchStart = null; return; }
      var dx = e.changedTouches[0].clientX - touchStart.x, dy = e.changedTouches[0].clientY - touchStart.y;
      touchStart = null;
      if (Math.abs(dx) > 45 && Math.abs(dx) > Math.abs(dy) * 1.5) step(dx < 0 ? 1 : -1);
    }, {passive:true});
    dial.addEventListener('touchcancel', function() { touchStart = null; }, {passive:true});
    doc.getElementById('esc-replay').addEventListener('click', play);
    doc.getElementById('esc-copy').addEventListener('click', function() {
      var command = commands[items[selected].check].command;
      if (!command) return;
      if (!root.navigator.clipboard) { set('esc-copy-status', 'Select and copy the example text manually.'); return; }
      root.navigator.clipboard.writeText(command).then(function() { set('esc-copy-status', 'Example copied. Replace the placeholders before use.'); }, function() { set('esc-copy-status', 'Copy unavailable. Select the example text manually.'); });
    });
    reduced.addEventListener('change', cancel);
    doc.addEventListener('visibilitychange', function() { if (doc.hidden) cancel(); });
    new root.MutationObserver(function() { if (stopped()) cancel(); }).observe(doc.documentElement,{attributes:true,attributeFilter:['data-motion']});
    picker.hidden = false; doc.getElementById('esc-dial-layout').hidden = false; doc.getElementById('esc-replay').hidden = false;
    select(0, false);
  }
  var api = {items:items, commands:commands};
  if (typeof module === 'object' && module.exports) module.exports = api;
  else { root.ADhammerEscExplorer = api; mount(); }
})(typeof window !== 'undefined' ? window : globalThis);
