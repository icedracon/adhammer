/* Entirely fictional, local-only counterfactual. No commands or network access. */
(function () {
  'use strict';
  var lab = document.getElementById('path-lab');
  if (!lab) return;
  var attach = document.getElementById('frozen-attach');
  var breakButton = document.getElementById('frozen-break');
  var relationship = document.getElementById('frozen-relationship');
  var reset = document.getElementById('frozen-reset');
  var range = document.getElementById('frozen-reveal');
  var stateLabel = document.getElementById('frozen-state');
  var result = document.getElementById('frozen-result');
  var evidence = false;
  var cut = 'none';
  var manualReveal = false;
  var queued = false;
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  function reveal(value) {
    var amount = Math.max(0, Math.min(100, Number(value) || 0));
    lab.style.setProperty('--reveal', amount + '%');
    range.value = String(amount);
  }
  function render() {
    lab.dataset.evidence = evidence ? 'attached' : 'pending';
    lab.dataset.cut = cut;
    attach.setAttribute('aria-pressed', String(evidence));
    attach.textContent = evidence ? 'Remove demo evidence −' : 'Attach demo evidence ＋';
    breakButton.setAttribute('aria-pressed', String(cut !== 'none'));
    breakButton.textContent = cut === 'none' ? 'Break the path ↗' : 'Restore relationship ↶';
    if (cut !== 'none') {
      var name = cut === 'identity' ? 'identity-to-host' : 'delegation';
      stateLabel.textContent = 'Route interrupted / simulation';
      result.textContent = 'Removing the ' + name + ' edge disconnects this illustrated route. ' + (evidence ? 'The earlier fixture is retained, but it does not prove the changed route.' : 'No evidence has been attached.');
    } else {
      stateLabel.textContent = evidence ? 'Evidence attached / fictional fixture' : 'Possible / untested';
      result.textContent = evidence ? 'A synthetic fixture marks this demo route as evidenced. It is not a captured assessment or a validation receipt.' : 'The fictional route is connected. No evidence has been attached.';
    }
  }
  attach.addEventListener('click', function () { evidence = !evidence; manualReveal = true; reveal(100); render(); });
  breakButton.addEventListener('click', function () { cut = cut === 'none' ? relationship.value : 'none'; manualReveal = true; reveal(100); render(); });
  relationship.addEventListener('change', function () { if (cut !== 'none') { cut = relationship.value; render(); } });
  range.addEventListener('input', function () { manualReveal = true; reveal(range.value); });
  reset.addEventListener('click', function () { evidence = false; cut = 'none'; relationship.value = 'delegation'; manualReveal = true; reveal(40); render(); });
  function scrollReveal() {
    queued = false;
    if (manualReveal || reduced.matches || document.documentElement.dataset.motion === 'paused' || document.hidden) return;
    var rect = lab.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight) return;
    reveal(Math.round(Math.max(10, Math.min(100, (window.innerHeight - rect.top) / Math.max(1, window.innerHeight) * 100))));
  }
  window.addEventListener('scroll', function () {
    if (!queued && !manualReveal && !reduced.matches) { queued = true; window.requestAnimationFrame(scrollReveal); }
  }, { passive: true });
  lab.querySelector('.frozen-actions').hidden = false;
  reset.hidden = false;
  render();
})();
