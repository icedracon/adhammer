/* Live SVG flows: pause off-screen, in hidden tabs, under reduced motion, or when paused by the visitor. */
(function () {
  'use strict';
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var states = Array.from(document.querySelectorAll('[data-live-flow]')).map(function (figure) {
    return {figure:figure, visible:false, manualPause:false,
      button:document.querySelector('[data-flow-toggle="'+figure.id+'"]')};
  });
  function stopped() { return document.hidden || reduced.matches || document.documentElement.dataset.motion === 'paused'; }
  function sync(state) {
    var paused = stopped() || state.manualPause;
    state.figure.classList.toggle('is-paused', paused || !state.visible);
    if (!state.button) return;
    state.button.textContent = reduced.matches ? 'Reduced motion enabled' : document.documentElement.dataset.motion === 'paused' ? 'Motion paused globally' : paused ? 'Resume animation' : 'Pause animation';
    state.button.disabled = reduced.matches || document.documentElement.dataset.motion === 'paused';
    state.button.setAttribute('aria-pressed', String(paused));
  }
  var observer = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      var state = states.find(function (item) { return item.figure === entry.target; });
      state.visible = entry.isIntersecting; sync(state);
    });
  }, {threshold:0.12}) : null;
  states.forEach(function (state) {
    if (state.button) state.button.addEventListener('click', function () {
      if (stopped()) return;
      state.manualPause = !state.manualPause; sync(state);
    });
    if (observer) observer.observe(state.figure); else state.visible = true;
    sync(state);
  });
  function syncAll() { states.forEach(sync); }
  reduced.addEventListener('change', syncAll);
  document.addEventListener('visibilitychange', syncAll);
  new MutationObserver(syncAll).observe(document.documentElement, {attributes:true, attributeFilter:['data-motion']});
})();
