(() => {
  const intro = document.querySelector(".brand-intro");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  if (reduced.matches || scrollY > 12 || (location.hash && location.hash !== "#top")) return;

  const face = intro.querySelector("img");
  const film = intro.querySelector("video");
  const listeners = new AbortController();
  const signal = listeners.signal;
  let usingAssembly = false;
  let started = false;
  let deadline;

  const finish = () => {
    intro.hidden = true;
    clearTimeout(deadline);
    listeners.abort();
    film.pause();
  };
  const showAssembly = () => {
    if (usingAssembly || signal.aborted) return;
    usingAssembly = true;
    clearTimeout(deadline);
    film.pause();
    film.removeAttribute("src");
    film.load();
    intro.classList.remove("brand-film-fading");
    intro.classList.add("brand-intro-assembly");
    face.src = face.dataset.src;
    intro.hidden = false;
  };

  const recover = () => {
    if (film.currentTime > .65) finish();
    else showAssembly();
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
    if (!started && film.currentTime > 0) {
      started = true;
      clearTimeout(deadline);
    }
    if (usingAssembly || !Number.isFinite(film.duration) || film.duration - film.currentTime >= .5) return;
    intro.classList.add("brand-film-fading");
  }

  film.addEventListener("playing", () => {
    if (started) clearTimeout(deadline);
  }, { signal });
  film.addEventListener("waiting", () => {
    if (usingAssembly || !started) return;
    clearTimeout(deadline);
    deadline = setTimeout(recover, 2500);
  }, { signal });
  film.addEventListener("timeupdate", updateFilm, { signal });
  film.addEventListener("ended", finish, { once: true, signal });
  film.addEventListener("error", recover, { signal });

  if (!film.canPlayType("video/mp4")) {
    showAssembly();
    return;
  }
  film.poster = film.dataset.poster;
  intro.hidden = false;
  deadline = setTimeout(recover, 3600);
  film.src = film.dataset.src;
  film.play()?.catch(showAssembly);
})();
