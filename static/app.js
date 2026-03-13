document.addEventListener("DOMContentLoaded", function () {
  const slider = document.getElementById("info-slider");
  if (!slider) return;

  const slides = Array.from(slider.querySelectorAll(".slide"));
  if (slides.length === 0) return;

  let index = 0;

  function showSlide(i) {
    slides.forEach((s, idx) => {
      s.classList.toggle("active", idx === i);
    });
  }

  function next() {
    index = (index + 1) % slides.length;
    showSlide(index);
  }

  function prev() {
    index = (index - 1 + slides.length) % slides.length;
    showSlide(index);
  }

  const btnPrev = document.querySelector("[data-slider-prev]");
  const btnNext = document.querySelector("[data-slider-next]");

  if (btnPrev) btnPrev.addEventListener("click", prev);
  if (btnNext) btnNext.addEventListener("click", next);

  // auto-rotate slides
  setInterval(next, 7000);
});
