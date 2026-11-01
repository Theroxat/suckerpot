// Runs before first paint: the stored choice, else the OS preference, else dark.
;(function () {
  var t = null
  try {
    t = localStorage.getItem("selfhostr.theme")
  } catch (e) {}
  if (t !== "light" && t !== "dark") t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
  document.documentElement.dataset.theme = t
  var meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.content = t === "light" ? "#f7f7f8" : "#0b0c0e"
})()
