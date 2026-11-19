(() => {
  const root = document.documentElement;
  const layer = document.querySelector(".dragon-follow");
  const video = layer.querySelector("video");
  const fallback = layer.querySelector("img");
  const hero = document.querySelector(".cinema-hero");
  const main = document.getElementById("content");
  const lightSections = Array.from(main.querySelectorAll("#proof, #coverage, #install"));
  let frame = 0;

  const clamp = (value) => Math.min(1, Math.max(0, value));
  const smooth = (value) => {
    const edge = clamp(value);
    return edge * edge * (3 - 2 * edge);
  };

  function showFallback() {
    if (fallback.hasAttribute("src")) return;
    fallback.src = fallback.dataset.src;
    if (video.hasAttribute("src")) {
      video.removeAttribute("src");
      video.load();
    }
  }

  function fly() {
    if (fallback.hasAttribute("src")) return;
    if (!video.canPlayType('video/webm; codecs="vp9"')) {
      showFallback();
      return;
    }
    if (!video.hasAttribute("src")) video.src = video.dataset.src;
    if (video.paused) {
      video.play().catch((error) => {
        if (error.name !== "AbortError") showFallback();
      });
    }
  }

  function update() {
    frame = 0;
    if (root.dataset.motion !== "playing") return;
    if (main.classList.contains("chase-ready")) {
      video.pause();
      return;
    }

    const { innerHeight: height, innerWidth: width } = window;
    const heroBottom = hero.getBoundingClientRect().bottom;
    const mainBottom = main.getBoundingClientRect().bottom;
    const entrance = smooth((.72 - heroBottom / height) / .55);
    const exit = smooth((mainBottom / height - .24) / .56);
    const opacity = entrance * exit;
    layer.style.opacity = opacity;
    layer.style.visibility = opacity ? "visible" : "hidden";
    if (!opacity) {
      video.pause();
      return;
    }

    const depth = clamp(-heroBottom / Math.max(height, mainBottom - heroBottom - height));
    const dive = smooth((.63 - heroBottom / height) / 1.9);
    const current = depth * 2 * Math.PI;
    const center = height * (.23 + .35 * dive + .21 * depth + .015 * Math.sin(current));
    const light = lightSections.some((section) => {
      const { top, bottom } = section.getBoundingClientRect();
      return top < center && bottom > center;
    });
    layer.dataset.tone = light ? "light" : "dark";

    const drift = Math.min(width * .085, 120);
    const bank = -9 + 23 * dive - 5 * depth + 3 * Math.sin(current);
    layer.style.setProperty("--flight-x", `${(-.6 + dive + .3 * Math.sin(current)) * drift}px`);
    layer.style.setProperty("--flight-y", `${center}px`);
    layer.style.setProperty("--flight-yaw", `${Math.sin(current) * 11}deg`);
    layer.style.setProperty("--flight-bank", `${bank}deg`);
    layer.style.setProperty("--flight-scale", 1.04 - .19 * depth);
    fly();
  }

  function requestUpdate() {
    if (!frame && root.dataset.motion === "playing") {
      frame = window.requestAnimationFrame(update);
    }
  }

  window.addEventListener("scroll", requestUpdate, { passive: true });
  window.addEventListener("resize", requestUpdate);
  new ResizeObserver(requestUpdate).observe(main);
  new MutationObserver(() => {
    if (root.dataset.motion === "playing") requestUpdate();
    else video.pause();
  }).observe(root, {
    attributes: true,
    attributeFilter: ["data-motion"],
  });
  video.addEventListener("loadeddata", () => {
    // Some VP9 decoders drop the alpha channel.
    const pixel = document.createElement("canvas");
    pixel.width = pixel.height = 1;
    const context = pixel.getContext("2d", { willReadFrequently: true });
    if (!context) return showFallback();
    context.drawImage(video, 0, 0, 1, 1, 0, 0, 1, 1);
    if (context.getImageData(0, 0, 1, 1).data[3] === 0) video.dataset.ready = "";
    else showFallback();
  }, { once: true });
  video.addEventListener("error", showFallback, { once: true });
  requestUpdate();
})();
