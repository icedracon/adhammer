(() => {
  const intro = document.querySelector(".brand-intro");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  if (reduced.matches || scrollY > 12 || (location.hash && location.hash !== "#top")) return;

  const face = intro.querySelector("img");
  const film = intro.querySelector("video");
  const listeners = new AbortController();
  const signal = listeners.signal;
  let started = false;
  let deadline;

  const finish = () => {
    intro.hidden = true;
    clearTimeout(deadline);
    listeners.abort();
    film.pause();
  };
  const showAssembly = () => {
    if (started || signal.aborted) return;
    started = true;
    clearTimeout(deadline);
    film.pause();
    face.src = face.dataset.src;
    intro.hidden = false;
  };

  intro.addEventListener("animationend", (event) => {
    if (event.target === intro) finish();
  }, { signal });
  window.addEventListener("pointerdown", finish, { capture: true, passive: true, signal });
  window.addEventListener("wheel", finish, { passive: true, signal });
  window.addEventListener("keydown", finish, { capture: true, signal });
  window.addEventListener("scroll", () => {
    if (scrollY > 12) finish();
  }, { passive: true, signal });
  reduced.addEventListener("change", finish, { signal });
  face.addEventListener("error", finish, { once: true, signal });
  if (new URLSearchParams(location.search).get("intro") === "assembly") {
    showAssembly();
    return;
  }

  function updateFilm() {
    if (!intro.classList.contains("brand-film-active") || !Number.isFinite(film.duration)) return;
    if (film.duration - film.currentTime >= .5 || intro.classList.contains("brand-film-fading")) return;
    intro.classList.add("brand-film-fading");
  }

  film.addEventListener("playing", () => {
    if (started || signal.aborted) return;
    started = true;
    clearTimeout(deadline);
    intro.classList.add("brand-film-active");
    intro.hidden = false;
    if ("requestVideoFrameCallback" in film) {
      const check = () => {
        if (signal.aborted) return;
        updateFilm();
        film.requestVideoFrameCallback(check);
      };
      film.requestVideoFrameCallback(check);
    }
  }, { once: true, signal });
  film.addEventListener("timeupdate", updateFilm, { signal });
  film.addEventListener("ended", finish, { once: true, signal });
  film.addEventListener("error", () => {
    if (intro.classList.contains("brand-film-active")) finish();
    else showAssembly();
  }, { once: true, signal });

  if (!film.canPlayType("video/mp4")) {
    showAssembly();
    return;
  }
  deadline = setTimeout(showAssembly, 650);
  film.src = film.dataset.src;
  film.play().catch(showAssembly);
})();
