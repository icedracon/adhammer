(() => {
  if (new URLSearchParams(location.search).get("flight") === "classic") return;

  const root = document.documentElement;
  const main = document.getElementById("content");
  const hero = document.getElementById("top");
  const stage = hero.querySelector(".entrance-viewport");
  const aerie = main.querySelector(".dragon-aerie");
  const perch = aerie?.querySelector(".dragon-perch");
  const observatory = main.querySelector("#engine");
  const release = main.querySelector("#release");
  const lightSections = Array.from(main.querySelectorAll("#proof, #coverage, #install"));
  const panels = Array.from(main.querySelectorAll(
    ".observatory-workbench, .ob-inspector, .ob-report, .esc-detail, .esc-flow li, " +
    ".methods-workbench, .methods-cinema, .methods-film-notes, .methods-picker",
  ));
  const poster = document.createElement("img");
  const video = document.createElement("video");
  const assets = new URL("./", document.currentScript.src);

  poster.className = "dragon-chase-poster";
  poster.alt = "";
  poster.width = 1920;
  poster.height = 1080;
  poster.addEventListener("load", () => main.classList.add("chase-poster-ready"), { once: true });
  stage.querySelector(".living-stage").prepend(poster);
  poster.src = new URL("dragon-opening-1080.webp", assets).href;
  if (!video.canPlayType('video/webm; codecs="vp9"')) return;

  const initialTarget = document.getElementById(location.hash.slice(1));
  const anchorInput = new AbortController();
  if (initialTarget && initialTarget !== hero && root.dataset.motion === "playing") {
    for (const event of ["wheel", "pointerdown", "keydown", "hashchange"]) {
      window.addEventListener(event, () => anchorInput.abort(), {
        capture: true, passive: true, signal: anchorInput.signal,
      });
    }
  } else {
    anchorInput.abort();
  }

  const source = new URL("dragon-journey-1080.webm?v=hd-detail", assets);
  const fallback = new URL("dragon-flight-1080.webm", assets);
  const fps = 24;
  const turn = 60;
  const last = 80;
  const resting = 129;
  const perchX = .74;
  const perchY = .828;
  const approachStart = 1.18;
  const touchdown = .72;
  const limit = (value) => Math.min(1, Math.max(0, value));
  const mix = (from, to, progress) => from + (to - from) * progress;
  const fade = (value) => {
    const t = limit(value);
    return t * t * (3 - 2 * t);
  };
  let frame = 0;
  let requested = false;
  let ready = false;
  let hasLanding = false;
  let objectURL;
  let displayedScroll;
  let lastTick;
  let pendingPose;

  video.className = "dragon-chase";
  video.muted = true;
  video.playsInline = true;
  video.preload = "auto";
  video.setAttribute("aria-hidden", "true");
  main.prepend(video);

  async function load(urls = perch ? [source, fallback] : [fallback]) {
    requested = true;
    for (const url of urls) {
      try {
        const response = await fetch(url);
        if (!response.ok) continue;
        // A local blob supports seeking on static servers without byte-range responses.
        objectURL = URL.createObjectURL(await response.blob());
        hasLanding = url === source;
        video.src = objectURL;
        return;
      } catch {
        ready = false;
      }
    }
    anchorInput.abort();
  }

  function paint(pose) {
    video.style.setProperty("--chase-x", `${pose.x}px`);
    video.style.setProperty("--chase-y", `${pose.y}px`);
    video.style.setProperty("--chase-scale", pose.scale);
    video.style.setProperty("--chase-opacity", pose.opacity);
    stage.style.setProperty("--chase-focus", pose.focus);
    stage.style.setProperty("--chase-opening", pose.opening);
    main.style.setProperty("--route-arrival", pose.arrival);
    main.style.setProperty("--chase-veil", pose.veil);
    aerie?.style.setProperty("--perch-contact", pose.contact);
    if (pose.veil <= 0) return;

    const { centerX, centerY, radiusX, radiusY } = pose;
    const bounds = panels.map((panel) => panel.getBoundingClientRect());
    for (const [index, panel] of panels.entries()) {
      const { left, right, top, bottom } = bounds[index];
      if (centerX + radiusX < left || centerX - radiusX > right ||
          centerY + radiusY < top || centerY - radiusY > bottom) {
        panel.style.setProperty("--chase-panel-size", "0px 0px");
        continue;
      }
      panel.style.setProperty("--chase-panel-size", `${radiusX}px ${radiusY}px`);
      panel.style.setProperty("--chase-panel-position", `${centerX - left}px ${centerY - top}px`);
    }
  }

  function update(time) {
    frame = 0;
    if (root.dataset.motion !== "playing" || document.hidden) {
      displayedScroll = lastTick = undefined;
      return;
    }
    if (!requested) load();
    if (!ready) return;

    const { innerHeight: height, innerWidth: width } = window;
    const targetScroll = Math.max(0, -hero.getBoundingClientRect().top);
    const elapsed = Math.max(1, Math.min(32, time - (lastTick ?? time - 16)));
    lastTick = time;
    displayedScroll ??= targetScroll;
    const difference = targetScroll - displayedScroll;
    if (Math.abs(difference) > .75) {
      displayedScroll += difference * (1 - Math.exp(-elapsed / 72));
      schedule();
    } else {
      displayedScroll = targetScroll;
    }
    if (video.seeking) return;

    const scroll = displayedScroll;
    const distance = Math.max(1, hero.offsetHeight - stage.offsetHeight);
    const approach = limit(scroll / distance);
    const descent = Math.max(0, (scroll - distance) / height);
    const glideDistance = hasLanding ? .94 : 1.26;
    const glide = limit(descent / glideDistance);
    const cruise = Math.max(0, descent - glideDistance);
    const wingStroke = 4.5 * (1 - Math.cos(cruise * 4.1));
    const flight = turn * approach * (1 + .37 * (1 - approach)) + (last - turn) * glide - wingStroke;
    const compact = width < 761;
    const arrival = fade((descent - .52) / .42);
    const drift = fade(cruise / .85);
    const nearX = width * ((compact ? .04 : 0) - .09 * glide + .10 * Math.sin(cruise * .76) * drift);
    const descentY = compact ? .36 * fade((descent - .04) / .88) : -.15 * fade((descent - .2) / .66);
    const swing = (compact ? -.10 : 0) + .12 * Math.sin(cruise * .83);
    const nearY = height * (descentY + drift * swing);
    const screenWidth = compact ? width * 1.13 : Math.max(width, height * 16 / 9);
    const screenHeight = screenWidth * 9 / 16;
    const screenLeft = compact ? -width * .10 : (width - screenWidth) / 2;
    const screenTop = compact ? Math.min(184, Math.max(72, height * .17)) : (height - screenHeight) / 2;
    const originX = screenLeft + screenWidth * perchX;
    const originY = screenTop + screenHeight * perchY;
    const retreat = hasLanding ? fade((descent - .08) / .96) : 0;
    const alongSection = (section) => {
      const { top, bottom } = section.getBoundingClientRect();
      const cursor = .60 * height - targetScroll + scroll;
      return fade((Math.min(cursor - top, bottom - cursor) + .20 * height) / (.47 * height));
    };
    const lane = compact ? .78 : .80 - .20 * alongSection(observatory) - .51 * alongSection(release);
    const distantX = width * (lane + .028 * Math.sin(cruise * .81));
    const distantY = height * ((compact ? .59 : .62) + .047 * Math.sin(cruise * .92));
    const flyX = mix(nearX, distantX - originX, retreat);
    const flyY = mix(nearY, distantY - originY, retreat);
    const flyScale = mix(1, compact ? .72 : .50, retreat);
    const anchor = hasLanding ? perch.getBoundingClientRect() : null;
    const perchProgress = anchor ? (anchor.top + targetScroll - scroll) / height : Infinity;
    const landing = limit((approachStart - perchProgress) / (approachStart - touchdown));
    const join = fade((1.63 - perchProgress) / (1.63 - approachStart));
    const path = fade(landing / .79);
    const position = mix(flight, last, join) + (resting - last) * landing;
    const x = anchor ? mix(flyX, anchor.left + anchor.width * .53 - originX, path) : flyX;
    const dip = (fade(landing / .43) - fade((landing - .43) / .46)) * .075 * height;
    const y = anchor ? mix(flyY, Math.min(anchor.top, .93 * height) - originY, path) + dip : flyY;
    const scale = anchor ? mix(flyScale, anchor.width / (screenWidth * .47), path) : flyScale;
    const centerX = originX + x + screenWidth * (.71 - perchX) * scale;
    const centerY = originY + y + screenHeight * (.62 - perchY) * scale;
    const daylight = Math.max(...lightSections.map((section) => {
      const { top, bottom } = section.getBoundingClientRect();
      return fade((Math.min(centerY - top, bottom - centerY) + 55) / 160);
    }));
    const visibility = anchor ? fade((anchor.top + 92) / 92) : fade((main.getBoundingClientRect().bottom / height - .10) / .70);
    const opening = fade(approach / .058);

    const pose = {
      x, y, scale,
      contact: fade((landing - .35) / .31),
      opacity: visibility * (1 - (hasLanding ? .025 * retreat + .14 * daylight : .35 * daylight) * (1 - path)) *
        (main.classList.contains("chase-poster-ready") ? opening : 1),
      opening: 1 - opening,
      focus: fade((approach - .62) / .38),
      arrival: arrival * (1 - fade((descent - 1.35) / .65)),
      veil: visibility * fade((descent - .53) / .57) * (1 - path),
      centerX, centerY,
      radiusX: Math.min(475, screenWidth * .39 * scale),
      radiusY: Math.min(300, screenHeight * .52 * scale),
    };
    const target = Math.round(position) / fps + .002;
    if (Math.abs(video.currentTime - target) >= .5 / fps && visibility > 0) {
      pendingPose = pose;
      video.currentTime = target;
    } else {
      paint(pose);
    }
  }

  function schedule() {
    if (!frame) frame = requestAnimationFrame(update);
  }

  video.addEventListener("loadeddata", () => {
    const sample = document.createElement("canvas");
    sample.width = sample.height = 1;
    const pixel = sample.getContext("2d", { willReadFrequently: true });
    if (!pixel) return;
    pixel.drawImage(video, 0, 0, 1, 1, 0, 0, 1, 1);
    ready = pixel.getImageData(0, 0, 1, 1).data[3] === 0;
    hasLanding = hasLanding && ready && video.duration > resting / fps;
    if (aerie) aerie.hidden = !hasLanding;
    main.classList.toggle("chase-ready", ready);
    if (ready && !anchorInput.signal.aborted) initialTarget.scrollIntoView({ behavior: "instant" });
    anchorInput.abort();
    schedule();
  });
  video.addEventListener("error", () => {
    ready = false;
    if (objectURL) URL.revokeObjectURL(objectURL);
    const retry = hasLanding;
    objectURL = undefined;
    hasLanding = false;
    if (aerie) aerie.hidden = true;
    main.classList.remove("chase-ready");
    if (retry) load([fallback]);
    schedule();
  });
  video.addEventListener("seeked", () => {
    if (pendingPose && root.dataset.motion === "playing" && !document.hidden) paint(pendingPose);
    pendingPose = undefined;
    schedule();
  });
  window.addEventListener("scroll", schedule, { passive: true });
  window.addEventListener("resize", schedule);
  document.addEventListener("visibilitychange", schedule);
  new ResizeObserver(schedule).observe(main);
  new MutationObserver(schedule).observe(root, {
    attributes: true,
    attributeFilter: ["data-motion"],
  });
  schedule();
})();
