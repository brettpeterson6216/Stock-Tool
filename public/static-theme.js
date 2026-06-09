(function () {
  const root = document.documentElement;
  const button = document.querySelector(".static-theme-toggle");

  function isDark() {
    return root.getAttribute("data-theme") === "dark";
  }

  function update() {
    if (!button) return;
    const next = isDark() ? "light" : "dark";
    button.setAttribute("aria-label", `Switch to ${next} mode`);
    button.title = `Switch to ${next} mode`;
  }

  if (button) {
    button.addEventListener("click", () => {
      const dark = !isDark();
      if (dark) root.setAttribute("data-theme", "dark");
      else root.removeAttribute("data-theme");
      localStorage.setItem("il-theme", dark ? "dark" : "light");
      update();
    });
  }
  update();
}());
