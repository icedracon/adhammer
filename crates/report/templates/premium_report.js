(() => {
  'use strict';
  const root = document.documentElement;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  try {
    const stored = localStorage.getItem('adhammer-report-theme');
    if (stored === 'light' || stored === 'dark') root.dataset.theme = stored;
  } catch (_) {}

  document.querySelectorAll('[data-theme-toggle]').forEach(button => {
    button.addEventListener('click', () => {
      const current = root.dataset.theme || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try { localStorage.setItem('adhammer-report-theme', next); } catch (_) {}
    });
  });
  document.querySelectorAll('[data-print]').forEach(button => button.addEventListener('click', () => print()));
  addEventListener('pointermove', event => {
    root.style.setProperty('--pointer-x', `${event.clientX}px`);
    root.style.setProperty('--pointer-y', `${event.clientY}px`);
  }, {passive: true});

  const progress = document.querySelector('.page-progress');
  const navLinks = [...document.querySelectorAll('.nav a[href^="#"]')];
  const navSections = navLinks.map(link => document.querySelector(link.getAttribute('href'))).filter(Boolean);
  let scrollQueued = false;
  const updateScroll = () => {
    const max = Math.max(1, document.documentElement.scrollHeight - innerHeight);
    if (progress) progress.style.transform = `scaleX(${Math.min(1, scrollY / max)})`;
    const line = innerHeight * .24;
    let active = navSections[0];
    navSections.forEach(section => { if (section.getBoundingClientRect().top <= line) active = section; });
    navLinks.forEach(link => link.classList.toggle('active', !!active && link.hash === `#${active.id}`));
    scrollQueued = false;
  };
  addEventListener('scroll', () => {
    if (!scrollQueued) { scrollQueued = true; requestAnimationFrame(updateScroll); }
  }, {passive: true});
  updateScroll();

  const revealItems = [...document.querySelectorAll('.chapter .section-head,.panel,.highlight,.finding,.path,.chain,.roadmap-card,.report-footer')];
  revealItems.forEach((item, index) => {
    item.classList.add('reveal');
    item.style.transitionDelay = `${Math.min(index % 3, 2) * 55}ms`;
  });
  if ('IntersectionObserver' in window && !reduced) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) { entry.target.classList.add('visible'); observer.unobserve(entry.target); }
      });
    }, {threshold: .06, rootMargin: '0px 0px -7%'});
    revealItems.forEach(item => observer.observe(item));
  } else revealItems.forEach(item => item.classList.add('visible'));

  document.querySelectorAll('.metric-value[data-count]').forEach((element, index) => {
    if (reduced) return;
    const target = Number(element.dataset.count);
    if (!Number.isFinite(target)) return;
    const suffix = element.dataset.suffix || '';
    const start = performance.now() + index * 45;
    const tick = now => {
      if (now < start) return requestAnimationFrame(tick);
      const elapsed = Math.min(1, (now - start) / 780);
      const eased = 1 - Math.pow(1 - elapsed, 3);
      element.textContent = `${Math.round(target * eased)}${suffix}`;
      if (elapsed < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });

  document.querySelectorAll('[data-filter]').forEach(button => {
    button.addEventListener('click', () => {
      const value = button.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach(other => other.classList.toggle('active', other === button));
      document.querySelectorAll('.finding[data-severity]').forEach(card => {
        card.classList.toggle('is-filtered', value !== 'all' && card.dataset.severity !== value);
      });
    });
  });

  document.querySelectorAll('code.cmd').forEach(code => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-btn';
    button.textContent = 'Copy';
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code.textContent || '');
        button.textContent = 'Copied';
        setTimeout(() => button.textContent = 'Copy', 1200);
      } catch (_) { button.textContent = 'Select'; }
    });
    code.insertAdjacentElement('beforebegin', button);
  });

  const shell = document.querySelector('.graph-shell');
  if (shell && matchMedia('(pointer:fine)').matches && !reduced) {
    shell.addEventListener('pointermove', event => {
      const box = shell.getBoundingClientRect();
      const x = (event.clientX - box.left) / box.width - .5;
      const y = (event.clientY - box.top) / box.height - .5;
      shell.style.transform = `rotateY(${x * 7 - 4}deg) rotateX(${-y * 6 + 1.5}deg)`;
    });
    shell.addEventListener('pointerleave', () => shell.style.transform = '');
  }

  const canvas = document.querySelector('.attack-graph');
  const dataNode = document.getElementById('report-graph-data');
  if (!canvas || !dataNode) return;
  let graph;
  try { graph = JSON.parse(dataNode.textContent || '{}'); } catch (_) { graph = {nodes: [], edges: []}; }
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const empty = document.querySelector('.graph-empty');
  if (!nodes.length) { if (empty) empty.hidden = false; return; }
  if (empty) empty.hidden = true;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  let width = 1, height = 1, dpr = 1, visible = true;
  const byId = new Map(nodes.map((node, index) => [node.id, {...node, index, layer: 0}]));
  const incoming = new Map(nodes.map(node => [node.id, 0]));
  const adjacency = new Map(nodes.map(node => [node.id, []]));
  edges.forEach(edge => {
    if (!byId.has(edge.from) || !byId.has(edge.to)) return;
    incoming.set(edge.to, (incoming.get(edge.to) || 0) + 1);
    adjacency.get(edge.from).push(edge.to);
  });
  let roots = nodes.filter(node => (incoming.get(node.id) || 0) === 0 && !node.tier0).map(node => node.id);
  if (!roots.length) roots = [nodes[0].id];
  const queue = roots.map(id => [id, 0]);
  const seen = new Map();
  while (queue.length) {
    const [id, layer] = queue.shift();
    if (seen.has(id) && seen.get(id) <= layer) continue;
    seen.set(id, layer);
    (adjacency.get(id) || []).forEach(next => queue.push([next, layer + 1]));
  }
  let maxLayer = Math.max(1, ...seen.values());
  nodes.forEach(node => {
    const item = byId.get(node.id);
    item.layer = node.tier0 ? maxLayer : Math.min(maxLayer, seen.get(node.id) ?? Math.floor(maxLayer / 2));
  });
  const layerGroups = new Map();
  byId.forEach(node => {
    if (!layerGroups.has(node.layer)) layerGroups.set(node.layer, []);
    layerGroups.get(node.layer).push(node);
  });
  layerGroups.forEach(group => group.sort((a, b) => String(a.label).localeCompare(String(b.label))));

  const resize = () => {
    const box = canvas.getBoundingClientRect();
    width = Math.max(1, box.width); height = Math.max(1, box.height);
    dpr = Math.min(devicePixelRatio || 1, 1.7);
    canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };
  const place = () => {
    layerGroups.forEach((group, layer) => {
      group.forEach((node, index) => {
        const spread = Math.min(height * .62, Math.max(70, (group.length - 1) * 62));
        node.x = width * (.13 + .74 * (maxLayer ? layer / maxLayer : .5));
        node.y = height * .44 - spread / 2 + (group.length === 1 ? spread / 2 : index * spread / (group.length - 1));
      });
    });
  };
  if ('ResizeObserver' in window) new ResizeObserver(() => { resize(); place(); if (reduced) draw(0); }).observe(canvas);
  else addEventListener('resize', () => { resize(); place(); });
  resize(); place();

  const draw = time => {
    if (!visible || document.hidden) { if (!reduced) requestAnimationFrame(draw); return; }
    ctx.clearRect(0, 0, width, height);
    ctx.save();
    ctx.globalAlpha = .12;
    for (let r = 90; r < Math.min(width, height); r += 88) {
      ctx.beginPath(); ctx.ellipse(width * .58, height * .44, r * 1.35, r * .48, -.08, 0, Math.PI * 2);
      ctx.strokeStyle = r % 176 ? '#69c9ff' : '#a18cff'; ctx.lineWidth = .7; ctx.stroke();
    }
    ctx.restore();

    edges.forEach((edge, index) => {
      const from = byId.get(edge.from), to = byId.get(edge.to);
      if (!from || !to) return;
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y);
      ctx.strokeStyle = edge.executable ? 'rgba(85,230,162,.48)' : 'rgba(105,201,255,.24)';
      ctx.lineWidth = edge.executable ? 1.5 : 1; ctx.stroke();
      if (!reduced) {
        const phase = (time / 1550 + index * .17) % 1;
        const x = from.x + (to.x - from.x) * phase, y = from.y + (to.y - from.y) * phase;
        const glow = ctx.createRadialGradient(x, y, 0, x, y, 8);
        glow.addColorStop(0, edge.executable ? 'rgba(85,230,162,.9)' : 'rgba(105,201,255,.75)');
        glow.addColorStop(1, 'rgba(105,201,255,0)');
        ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(x, y, 8, 0, Math.PI * 2); ctx.fill();
      }
    });

    [...byId.values()].forEach(node => {
      const color = node.tier0 ? '#ff5876' : node.layer === 0 ? '#69c9ff' : '#a18cff';
      const radius = node.tier0 ? 7 : 4.5;
      const glow = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius * 4.5);
      glow.addColorStop(0, color); glow.addColorStop(.25, `${color}aa`); glow.addColorStop(1, `${color}00`);
      ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(node.x, node.y, radius * 4.5, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = color; ctx.beginPath(); ctx.arc(node.x, node.y, radius, 0, Math.PI * 2); ctx.fill();
      ctx.font = '9px ui-monospace, monospace'; ctx.fillStyle = getComputedStyle(root).getPropertyValue('--muted');
      const label = String(node.label || '').slice(0, 24);
      ctx.fillText(label, node.x + radius + 7, node.y + 3);
    });
    if (!reduced) requestAnimationFrame(draw);
  };
  if ('IntersectionObserver' in window) new IntersectionObserver(entries => { visible = entries[0].isIntersecting; }, {rootMargin: '100px'}).observe(canvas);
  requestAnimationFrame(draw);
})();
