/* Silent, viewport-aware films. No assessment data or network targets. */
(function () {
  'use strict';
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var videos = Array.from(document.querySelectorAll('[data-ambient-video]'));
  var states = videos.map(function (video) {
    return {video:video, visible:false, manualPause:false, blocked:false,
      button:document.querySelector('[data-video-toggle="'+video.id+'"]')};
  });
  function stopped() { return document.hidden || reduced.matches || document.documentElement.dataset.motion === 'paused'; }
  function label(state) {
    if (!state.button) return;
    var paused = stopped() || state.manualPause || state.blocked;
    state.button.textContent = reduced.matches ? 'Reduced motion enabled' : document.documentElement.dataset.motion === 'paused' ? 'Motion paused globally' : paused ? 'Resume animation' : 'Pause animation';
    state.button.disabled = reduced.matches || document.documentElement.dataset.motion === 'paused';
    state.button.setAttribute('aria-pressed', String(paused));
  }
  function sync(state) {
    label(state);
    if (stopped() || !state.visible || state.manualPause || state.blocked) { state.video.pause(); return; }
    state.video.muted = true;
    var pending = state.video.play();
    if (pending) pending.then(function () {
      if (stopped() || !state.visible || state.manualPause) state.video.pause();
    }).catch(function (error) {
      // A viewport exit can interrupt a pending play; it is not an autoplay refusal.
      if (error.name === 'AbortError' || stopped() || !state.visible || state.manualPause) return;
      state.blocked = true; label(state);
    });
  }
  var observer = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      var state = states.find(function (item) { return item.video === entry.target; });
      state.visible = entry.isIntersecting; sync(state);
    });
  }, {threshold:0.12}) : null;
  states.forEach(function (state) {
    if (state.button) state.button.addEventListener('click', function () {
      if (stopped()) return;
      if (state.blocked) { state.blocked = false; state.manualPause = false; }
      else state.manualPause = !state.manualPause;
      sync(state);
    });
    if (observer) observer.observe(state.video);
    else {state.visible = true; sync(state);}
    label(state);
  });
  function syncAll() { states.forEach(sync); }
  reduced.addEventListener('change', syncAll);
  document.addEventListener('visibilitychange', syncAll);
  new MutationObserver(syncAll).observe(document.documentElement, {attributes:true,attributeFilter:['data-motion']});
})();
