/* Motion system: heading line reveals, a rolling version digit, and pointer tilt.
   Content is never hidden without JS, and everything shows at once under reduced motion or paused motion. */
(function () {
  'use strict';
  var root = document.documentElement;
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var finePointer = window.matchMedia('(hover: hover) and (pointer: fine)');
  function still() { return reduced.matches || root.dataset.motion === 'paused'; }

  function el(name) { return document.createElement(name); }

  // Split a heading into lines at <br> and at block-level children, then mask each line.
  function splitHeading(heading) {
    var groups = [[]];
    Array.from(heading.childNodes).forEach(function (node) {
      if (node.nodeName === 'BR') { groups.push([]); return; }
      if (node.nodeType === 1 && getComputedStyle(node).display === 'block') { groups.push([node], []); return; }
      groups[groups.length - 1].push(node);
    });
    groups = groups.filter(function (group) {
      return group.some(function (node) { return node.nodeType === 1 || node.textContent.trim(); });
    });
    if (!groups.length) return false;
    heading.textContent = '';
    groups.forEach(function (group, index) {
      var line = el('m-line'), inner = el('m-line-in');
      inner.style.setProperty('--i', index);
      group.forEach(function (node) { inner.appendChild(node); });
      line.appendChild(inner); heading.appendChild(line);
    });
    heading.classList.add('m-heading');
    return true;
  }

  // Roll the final digit of a version string, e.g. v1.5.0 -> v1.5.2.
  function makeRoll(node) {
    var text = node.textContent, last = text.slice(-1), target = Number(last);
    if (!/\d/.test(last) || target === 0) return null;
    var roll = el('m-roll'), strip = el('m-roll-strip');
    for (var d = 0; d <= target; d += 1) { var digit = el('span'); digit.textContent = String(d); strip.appendChild(digit); }
    roll.appendChild(strip);
    var label = el('span'); label.className = 'esc-sr-only'; label.textContent = text;
    var visible = el('span'); visible.setAttribute('aria-hidden', 'true');
    visible.textContent = text.slice(0, -1); visible.appendChild(roll);
    node.textContent = ''; node.style.whiteSpace = 'nowrap';
    node.appendChild(visible); node.appendChild(label);
    return {roll: roll, strip: strip, target: target};
  }
  function settleRoll(item, animate) {
    if (!animate) item.strip.style.transition = 'none';
    item.strip.style.transform = 'translate3d(0,' + (-item.target) + 'em,0)';
    item.roll.classList.add('m-in');
  }

  var headings = Array.from(document.querySelectorAll('main h2, section h2')).filter(function (h) {
    return !h.closest('.hero, [aria-hidden="true"]');
  }).filter(splitHeading);
  var rolls = Array.from(document.querySelectorAll('.release-lineage-current strong')).map(makeRoll).filter(Boolean);

  function showAll() {
    headings.forEach(function (h) { h.classList.add('m-in'); });
    rolls.forEach(function (item) { settleRoll(item, false); });
  }

  if (still() || !('IntersectionObserver' in window)) {
    showAll();
  } else {
    var seen = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var target = entry.target;
        if (target.classList.contains('m-heading')) target.classList.add('m-in');
        rolls.forEach(function (item) { if (item.roll === target) settleRoll(item, true); });
        seen.unobserve(target);
      });
    }, {threshold: 0.3, rootMargin: '0px 0px -8% 0px'});
    headings.forEach(function (h) { seen.observe(h); });
    rolls.forEach(function (item) { seen.observe(item.roll); });
  }
  reduced.addEventListener('change', function () { if (still()) showAll(); });
  new MutationObserver(function () { if (still()) showAll(); }).observe(root, {attributes: true, attributeFilter: ['data-motion']});

  // Pointer tilt: at most 6 degrees, with a sheen that follows the cursor.
  Array.from(document.querySelectorAll('.release-platforms a, .final-link')).forEach(function (card) {
    card.classList.add('m-tilt');
    card.addEventListener('pointermove', function (event) {
      if (!finePointer.matches || still()) return;
      var box = card.getBoundingClientRect();
      var x = (event.clientX - box.left) / box.width, y = (event.clientY - box.top) / box.height;
      card.style.setProperty('--mx', (x * 100).toFixed(1) + '%');
      card.style.setProperty('--my', (y * 100).toFixed(1) + '%');
      card.style.transform = 'perspective(700px) rotateX(' + ((.5 - y) * 6).toFixed(2) + 'deg) rotateY(' + ((x - .5) * 6).toFixed(2) + 'deg) translateZ(0)';
      card.classList.add('m-hover');
    });
    card.addEventListener('pointerleave', function () { card.style.transform = ''; card.classList.remove('m-hover'); });
  });
})();
