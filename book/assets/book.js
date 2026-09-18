/* Book behaviour: theme, contents drawer, on-page highlighting, copy buttons,
   client-side search, and lazy mermaid rendering. No dependencies. */
(function () {
  "use strict";

  var doc = document.documentElement;

  /* theme ------------------------------------------------------------ */
  var themeButton = document.getElementById("theme-toggle");
  if (themeButton) {
    themeButton.addEventListener("click", function () {
      var next = doc.dataset.theme === "ink" ? "paper" : "ink";
      doc.dataset.theme = next;
      try {
        localStorage.setItem("book-theme", next);
      } catch (e) {}
    });
  }

  /* contents drawer (narrow screens) --------------------------------- */
  var navButton = document.getElementById("nav-toggle");
  if (navButton) {
    navButton.addEventListener("click", function () {
      var open = document.body.classList.toggle("nav-open");
      navButton.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  /* highlight the current section in the margin table of contents ---- */
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  var headings = tocLinks
    .map(function (link) {
      var id = link.getAttribute("href").slice(1);
      return document.getElementById(id);
    })
    .filter(Boolean);

  if (headings.length && "IntersectionObserver" in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          tocLinks.forEach(function (link) {
            var active = link.getAttribute("href") === "#" + entry.target.id;
            link.classList.toggle("is-active", active);
          });
        });
      },
      { rootMargin: "-64px 0px -70% 0px", threshold: 0 }
    );
    headings.forEach(function (heading) {
      observer.observe(heading);
    });
    if (tocLinks.length) tocLinks[0].classList.add("is-active");
  }

  /* copy buttons on every code listing ------------------------------- */
  Array.prototype.slice
    .call(document.querySelectorAll("figure.listing pre"))
    .forEach(function (pre) {
      var button = document.createElement("button");
      button.className = "copy-button";
      button.type = "button";
      button.textContent = "Copy";
      button.addEventListener("click", function () {
        var code = pre.querySelector("code");
        var text = code ? code.textContent : "";
        var done = function () {
          button.textContent = "Copied";
          setTimeout(function () {
            button.textContent = "Copy";
          }, 1200);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, done);
        } else {
          var area = document.createElement("textarea");
          area.value = text;
          document.body.appendChild(area);
          area.select();
          try {
            document.execCommand("copy");
          } catch (e) {}
          document.body.removeChild(area);
          done();
        }
      });
      pre.parentNode.appendChild(button);
    });

  /* search ----------------------------------------------------------- */
  var overlay = document.getElementById("search");
  var searchInput = document.getElementById("search-input");
  var searchResults = document.getElementById("search-results");
  var searchOpen = document.getElementById("search-open");
  var index = null;
  var hits = [];
  var active = -1;

  function loadIndex() {
    if (index) return Promise.resolve(index);
    return fetch("search.json")
      .then(function (response) {
        return response.json();
      })
      .then(function (pages) {
        index = pages.map(function (page) {
          return {
            p: page.p,
            t: page.t,
            n: page.n,
            part: page.part,
            s: page.s.map(function (section) {
              return {
                a: section.a,
                h: section.h,
                x: section.x,
                low: (section.h + " " + section.x).toLowerCase()
              };
            })
          };
        });
        return index;
      });
  }

  function search(query) {
    var needle = query.trim().toLowerCase();
    if (!index || needle.length < 2) return [];
    var terms = needle.split(/\s+/);
    var found = [];
    index.forEach(function (page) {
      page.s.forEach(function (section) {
        var score = 0;
        for (var i = 0; i < terms.length; i += 1) {
          var term = terms[i];
          var inTitle = section.h.toLowerCase().indexOf(term) >= 0;
          var inPage = page.t.toLowerCase().indexOf(term) >= 0;
          var inText = section.low.indexOf(term) >= 0;
          if (!inTitle && !inPage && !inText) return;
          score += inTitle ? 6 : inPage ? 3 : 1;
        }
        found.push({ page: page, section: section, score: score });
      });
    });
    found.sort(function (a, b) {
      return b.score - a.score;
    });
    return found.slice(0, 20);
  }

  function snippet(section, needle) {
    var text = section.x;
    var at = text.toLowerCase().indexOf(needle.split(/\s+/)[0]);
    if (at < 0) at = 0;
    var start = Math.max(0, at - 60);
    var piece = text.slice(start, start + 190);
    return (start > 0 ? "\u2026" : "") + piece + (start + 190 < text.length ? "\u2026" : "");
  }

  function render(list, needle) {
    hits = list;
    active = -1;
    searchResults.innerHTML = "";
    if (!list.length) {
      if (needle.length >= 2) {
        var empty = document.createElement("li");
        empty.innerHTML = '<a tabindex="-1"><span class="result-title">No matches</span></a>';
        searchResults.appendChild(empty);
      }
      return;
    }
    list.forEach(function (hit, position) {
      var item = document.createElement("li");
      var link = document.createElement("a");
      link.href = hit.page.p + ".html" + (hit.section.a ? "#" + hit.section.a : "");
      var where = hit.page.n ? "Chapter " + hit.page.n + " \u00b7 " + hit.page.t : hit.page.t;
      link.innerHTML =
        '<div class="result-page"></div><div class="result-title"></div><div class="result-snippet"></div>';
      link.querySelector(".result-page").textContent = where;
      link.querySelector(".result-title").textContent = hit.section.h;
      link.querySelector(".result-snippet").textContent = snippet(hit.section, needle);
      item.appendChild(link);
      item.dataset.position = String(position);
      searchResults.appendChild(item);
    });
  }

  function move(step) {
    var items = Array.prototype.slice.call(searchResults.children);
    if (!items.length) return;
    active = (active + step + items.length) % items.length;
    items.forEach(function (item, position) {
      item.classList.toggle("is-active", position === active);
    });
    items[active].scrollIntoView({ block: "nearest" });
  }

  function openSearch() {
    loadIndex().then(function () {
      overlay.hidden = false;
      searchInput.value = "";
      render([], "");
      searchInput.focus();
    });
  }

  function closeSearch() {
    overlay.hidden = true;
  }

  if (overlay) {
    if (searchOpen) searchOpen.addEventListener("click", openSearch);
    searchInput.addEventListener("input", function () {
      render(search(searchInput.value), searchInput.value.trim().toLowerCase());
    });
    searchInput.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        move(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        move(-1);
      } else if (event.key === "Enter") {
        var target = searchResults.querySelector("li.is-active a") || searchResults.querySelector("li a");
        if (target) window.location.href = target.href;
      } else if (event.key === "Escape") {
        closeSearch();
      }
    });
    overlay.addEventListener("click", function (event) {
      if (event.target === overlay) closeSearch();
    });
    document.addEventListener("keydown", function (event) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if (event.key === "Escape") closeSearch();
      if (typing) return;
      if (event.key === "/" || ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k")) {
        event.preventDefault();
        openSearch();
      }
    });
  }

  /* diagrams --------------------------------------------------------- */
  if (document.querySelector(".mermaid")) {
    var mermaidScript = document.createElement("script");
    mermaidScript.src = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js";
    mermaidScript.async = true;
    mermaidScript.onload = function () {
      if (!window.mermaid) return;
      window.mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: doc.dataset.theme === "ink" ? "dark" : "neutral",
        themeVariables: { fontSize: "15px" },
        flowchart: { useMaxWidth: false, htmlLabels: true },
        sequence: { useMaxWidth: false }
      });
      window.mermaid.run({ querySelector: ".mermaid" });
    };
    document.head.appendChild(mermaidScript);
  }
})();
