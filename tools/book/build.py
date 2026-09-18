#!/usr/bin/env python3
"""Build the SELinux manual as a static HTML site from book/ sources.

Standard library only, so `make book` works on a laptop, on rhel-qa, and in CI
without installing anything.

    python3 tools/book/build.py                # build into site/
    python3 tools/book/build.py --check        # validate links, anchors, repo refs
    python3 tools/book/build.py --serve 8000   # build, then serve site/ locally

Supported markdown (a deliberate subset; anything else is a build error rather
than silently dropped content):

    # H1 (one per page, becomes the page title)
    ## H2 / ### H3   (anchors; H2 appears in "On this page")
    paragraphs, **bold**, *italic*, `code`, ~~strike~~, [links](target)
    - / 1. lists, nested by indentation, - [ ] task items
    > blockquote (the first one after H1 is styled as the chapter dek)
    | tables | with a |---| rule row, alignment via :---
    ``` fenced code with a language; lang `mermaid` renders as a diagram;
        ```bash title="Compile the module"  names the listing
    ::: why Title ... :::   callouts: why how try note warn good story
    ---   horizontal rule
    a line starting with '<' passes through as a raw HTML block
    four-space indented code blocks (rendered as unlabelled listings)

Link targets:
    other-page.md#anchor    another page (rewritten to .html, validated)
    repo:selinux/myapp.te   a path in the selinux-pac repository (validated)
    asset:cover.svg         a file in book/assets/
    http(s)://...           external, not validated offline
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

CALLOUTS = {"why", "how", "try", "note", "warn", "good", "story"}
CODE_TOKEN = "\x00%d\x00"


class BookError(Exception):
    """A build failure that carries the source location."""


def fail(page: str, line: int, message: str) -> BookError:
    return BookError(f"{page}:{line}: {message}")


@dataclass
class Entry:
    """One page of the book."""

    file: str
    title: str
    part: str = ""
    part_blurb: str = ""
    part_first: bool = False
    part_index: int = 0
    appendix: str = ""
    number: int = 0
    slug: str = ""
    html: str = ""
    h1: str = ""
    ids: set = field(default_factory=set)
    sections: list = field(default_factory=list)


@dataclass
class Book:
    cfg: dict
    entries: list

    @property
    def repo(self) -> str:
        return self.cfg.get("repo", "").rstrip("/")

    @property
    def branch(self) -> str:
        return self.cfg.get("branch", "main")


def load_book(book_dir: Path) -> Book:
    cfg_path = book_dir / "book.toml"
    if not cfg_path.is_file():
        raise BookError(f"missing {cfg_path}")
    try:
        cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise BookError(f"{cfg_path}: invalid TOML: {exc}") from exc

    entries = []
    for item in cfg.get("front", []):
        entries.append(Entry(file=item["file"], title=item["title"]))

    number = 0
    part_index = 0
    appendix = 0
    for part in cfg.get("part", []):
        part_index += 1
        title = part["title"]
        blurb = part.get("blurb", "")
        is_appendix = part.get("kind", "") == "appendix"
        first = True
        for item in part.get("chapters", []):
            letter = ""
            if is_appendix:
                letter = chr(ord("A") + appendix)
                appendix += 1
            else:
                number += 1
            entries.append(
                Entry(
                    file=item["file"],
                    title=item["title"],
                    part=title,
                    part_blurb=blurb,
                    part_first=first,
                    part_index=part_index,
                    appendix=letter,
                    number=number if not is_appendix else 0,
                )
            )
            first = False

    for entry in entries:
        name = Path(entry.file).name
        entry.slug = name[:-3] if name.endswith(".md") else name

    slugs = [entry.slug for entry in entries]
    duplicates = sorted({slug for slug in slugs if slugs.count(slug) > 1})
    if duplicates:
        raise BookError("duplicate page basenames in book.toml: " + ", ".join(duplicates))
    if "index" not in slugs:
        raise BookError("book.toml must include an index.md front page")
    return Book(cfg=cfg, entries=entries)


# ---------------------------------------------------------------------------
# inline rendering
# ---------------------------------------------------------------------------

_SLUG_STRIP = re.compile(r"[`*_\[\]]")
_SLUG_SPLIT = re.compile(r"[^a-z0-9]+")
_LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")
_AUTOLINK = re.compile(r"&lt;(https?://[^&\s]+)&gt;")
_STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.S)
_EM_STAR = re.compile(r"(?<![A-Za-z0-9*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![A-Za-z0-9*])")
_EM_UNDER = re.compile(r"(?<![A-Za-z0-9_])_(?=\S)([^_\n]+?)(?<=\S)_(?![A-Za-z0-9_])")
_STRIKE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~", re.S)
_FENCE = re.compile(r"^\s*(```+|~~~+)\s*(\S*)\s*(.*)$")
_LIST_ITEM = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")


def slugify(text: str) -> str:
    text = _SLUG_STRIP.sub("", text).lower()
    return _SLUG_SPLIT.sub("-", text).strip("-") or "section"


def typography(text: str) -> str:
    text = text.replace("...", "\u2026")
    text = re.sub(r"\s--\s", "\u2009\u2014\u2009", text)
    text = re.sub(r"(?<=\S)--(?=\S)", "\u2014", text)
    return text


class Renderer:
    """Renders one page of markdown into themed HTML."""

    def __init__(self, book: Book, entry: Entry):
        self.book = book
        self.entry = entry
        self.entry_dir = str(Path(entry.file).parent)
        if self.entry_dir == ".":
            self.entry_dir = ""
        self.ids = set()
        self.sections = []
        self.section = None
        self.seen_h1 = False
        self.dek_done = False
        self.listings = 0
        self.tables = 0

    # -- links ----------------------------------------------------------

    def rewrite_link(self, target: str) -> str:
        if target.startswith(("http://", "https://", "mailto:", "#")):
            return target
        if target.startswith("repo:"):
            rest = target[len("repo:") :]
            path, _, anchor = rest.partition("#")
            bare = path.rstrip("/")
            if bare.startswith("book/") and bare.endswith(".md"):
                slug = Path(bare).name[:-3]
                if slug in {entry.slug for entry in self.book.entries}:
                    return f"{slug}.html" + (f"#{anchor}" if anchor else "")
            is_dir = path.endswith("/")
            kind = "tree" if is_dir else "blob"
            url = f"{self.book.repo}/{kind}/{self.book.branch}/{bare}"
            return f"{url}#{anchor}" if anchor else url
        if target.startswith("asset:"):
            return "assets/" + target[len("asset:") :].lstrip("/")
        repo_path = self.repo_relative(target)
        if repo_path is not None:
            path, _, anchor = repo_path.partition("#")
            is_dir = path.endswith("/") or (REPO_ROOT / path.rstrip("/")).is_dir()
            kind = "tree" if is_dir else "blob"
            url = f"{self.book.repo}/{kind}/{self.book.branch}/{path.rstrip('/')}"
            return f"{url}#{anchor}" if anchor else url
        if target.endswith(".md") or ".md#" in target:
            filepart, _, anchor = target.partition("#")
            slug = Path(filepart).name[:-3]
            return f"{slug}.html" + (f"#{anchor}" if anchor else "")
        return target

    def repo_relative(self, target: str) -> str | None:
        """Resolve a link to a repository file, however the author wrote it.

        Handles repo-root paths (`docs/admin/303-DENIAL_RESPONSE.md`), paths with a
        leading slash, and paths relative to the chapter (`../selinux/myapp.fc`).
        A bare `NN-slug.md` that names a chapter is left to the chapter-link path.
        """
        if not re.match(r"^/?[A-Za-z0-9_.][\w./+-]*(#[A-Za-z0-9_-]+)?$", target):
            return None
        path, _, anchor = target.partition("#")
        suffix = f"#{anchor}" if anchor else ""
        if path.endswith(".md") and "/" not in path:
            if Path(path).name[:-3] in {entry.slug for entry in self.book.entries}:
                return None
        candidates = [
            os.path.normpath(os.path.join("book", self.entry_dir, path)),
            os.path.normpath(path),
            os.path.normpath(path.lstrip("/")),
        ]
        for candidate in candidates:
            if candidate.startswith("..") or not candidate or candidate == ".":
                continue
            if (REPO_ROOT / candidate).exists():
                return candidate + suffix
        return None

    # -- inline ---------------------------------------------------------

    def inline(self, text: str) -> str:
        spans = []

        def stash(match: re.Match) -> str:
            spans.append(match.group(2))
            return CODE_TOKEN % (len(spans) - 1)

        text = re.sub(r"(`+)(.+?)\1", stash, text, flags=re.S)
        text = typography(text)
        text = html.escape(text, quote=False)

        def link(match: re.Match) -> str:
            label, target = match.group(1), match.group(2)
            href = html.escape(self.rewrite_link(target), quote=True)
            external = href.startswith(("http://", "https://"))
            rel = ' rel="noopener"' if external else ""
            return f'<a href="{href}"{rel}>{label}</a>'

        text = _LINK.sub(link, text)

        def autolink(match: re.Match) -> str:
            url = match.group(1)
            return f'<a href="{url}" rel="noopener">{url}</a>'

        text = _AUTOLINK.sub(autolink, text)
        text = _STRONG.sub(r"<strong>\1</strong>", text)
        text = _EM_STAR.sub(r"<em>\1</em>", text)
        text = _EM_UNDER.sub(r"<em>\1</em>", text)
        text = _STRIKE.sub(r"<del>\1</del>", text)

        for index, code in enumerate(spans):
            token = CODE_TOKEN % index
            text = text.replace(
                token, f"<code>{html.escape(code, quote=False)}</code>"
            )
        return text

    # -- anchors and search text ---------------------------------------

    def unique_id(self, raw: str) -> str:
        base = slugify(raw)
        candidate, counter = base, 1
        while candidate in self.ids:
            counter += 1
            candidate = f"{base}-{counter}"
        self.ids.add(candidate)
        return candidate

    def note(self, fragment: str) -> None:
        if self.section is None:
            return
        text = html.unescape(re.sub(r"<[^>]+>", " ", fragment))
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            self.section["text"].append(text)

    def start_section(self, anchor: str, title: str, level: int) -> None:
        self.sections.append({"anchor": anchor, "title": title, "level": level, "text": []})
        self.section = self.sections[-1]

    # -- block parsing --------------------------------------------------

    def block_start(self, line: str) -> bool:
        if not line.strip():
            return True
        if line.startswith(("#", ">", ":::", "|", "<")):
            return True
        if _FENCE.match(line):
            return True
        if _LIST_ITEM.match(line):
            return True
        if re.match(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$", line):
            return True
        return False

    def render(self, text: str, page: str) -> str:
        return self.blocks(text.split("\n"), page, 1)

    def blocks(self, lines: list, page: str, base: int) -> str:
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            if _FENCE.match(line):
                i = self.emit_fence(lines, i, page, base, out)
                continue
            if re.match(r"^:{3,}\s*$", line):
                raise fail(page, base + i, "unmatched ::: terminator")
            if line.startswith(":::"):
                i = self.emit_callout(lines, i, page, base, out)
                continue
            heading = re.match(r"^(#{1,6})\s+(.*?)\s*$", line)
            if heading:
                self.emit_heading(heading, page, base + i, out)
                i += 1
                continue
            if re.match(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$", line):
                out.append("<hr>")
                i += 1
                continue
            if line.startswith(">"):
                i = self.emit_quote(lines, i, page, base, out)
                continue
            if line.startswith("|"):
                i = self.emit_table(lines, i, page, base, out)
                continue
            if _LIST_ITEM.match(line):
                i = self.emit_list(lines, i, page, base, out)
                continue
            if line.startswith("<"):
                i = self.emit_raw(lines, i, out)
                continue
            if re.match(r"^ {4,}\S", line):
                i = self.emit_indented(lines, i, out)
                continue
            i = self.emit_paragraph(lines, i, page, base, out)
        return "\n".join(out)

    def emit_heading(self, match: re.Match, page: str, line_no: int, out: list) -> None:
        level = len(match.group(1))
        raw = match.group(2).strip()
        explicit = re.search(r"\s*\{#([A-Za-z0-9_-]+)\}\s*$", raw)
        if explicit:
            raw = raw[: explicit.start()].strip()
            anchor = explicit.group(1)
            if anchor in self.ids:
                raise fail(page, line_no, f"duplicate explicit anchor #{anchor}")
            self.ids.add(anchor)
        else:
            anchor = self.unique_id(re.sub(r"`([^`]*)`", r"\1", raw))

        rendered = self.inline(raw)
        if level == 1:
            if self.seen_h1:
                raise fail(page, line_no, "second level-1 heading on this page")
            self.seen_h1 = True
            self.entry.h1 = re.sub(r"<[^>]+>", "", rendered)
            out.append(f'<h1 id="{anchor}">{rendered}</h1>')
            self.start_section(anchor, self.entry.h1, 1)
            return
        out.append(f'<h{level} id="{anchor}">{rendered}</h{level}>')
        self.note(rendered)
        if level == 2:
            self.start_section(anchor, re.sub(r"<[^>]+>", "", rendered), level)

    def emit_fence(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        opener = _FENCE.match(lines[i])
        assert opener
        marker = opener.group(1)
        lang = opener.group(2) or ""
        title_match = re.search(r'title="([^"]*)"', opener.group(3))
        title = title_match.group(1) if title_match else ""
        opened_on = i

        body = []
        i += 1
        close = re.compile(r"^\s*" + re.escape(marker) + r"\s*$")
        while i < len(lines) and not close.match(lines[i]):
            body.append(lines[i])
            i += 1
        if i >= len(lines):
            raise fail(page, base + opened_on, "unclosed code fence")
        i += 1
        code = "\n".join(body).rstrip("\n")

        if lang == "mermaid":
            caption = f"<figcaption>{self.inline(title)}</figcaption>" if title else ""
            out.append(
                '<figure class="figure figure--diagram">'
                f'<div class="mermaid">{html.escape(code, quote=False)}</div>'
                f"{caption}</figure>"
            )
            return i

        self.listings += 1
        heading = f"Listing {self.listings}"
        if title:
            heading += ". " + self.inline(title)
        label = html.escape(lang or "text")
        out.append(
            '<figure class="listing">'
            f'<pre><code class="language-{label}">{html.escape(code, quote=False)}</code></pre>'
            f'<figcaption><span class="listing-number">{heading}</span>'
            f'<span class="listing-lang">{label}</span></figcaption></figure>'
        )
        return i

    def toc_grid(self) -> str:
        out = ['<div class="toc-grid">']
        front = [entry for entry in self.book.entries if not entry.number]
        if front:
            out.append('<div class="toc-part"><h3>Front matter</h3><ol>')
            for entry in front:
                out.append(
                    f'<li><a href="{entry.slug}.html">{html.escape(entry.title)}</a></li>'
                )
            out.append("</ol></div>")

        seen = []
        for entry in self.book.entries:
            if not (entry.number or entry.appendix) or entry.part in seen:
                continue
            seen.append(entry.part)
            out.append(f'<div class="toc-part"><h3>{html.escape(entry.part)}</h3><ol>')
            for sibling in self.book.entries:
                if sibling.part != entry.part or not (sibling.number or sibling.appendix):
                    continue
                marker = sibling.appendix or sibling.number
                out.append(
                    f'<li><span class="num">{marker}</span>'
                    f'<a href="{sibling.slug}.html">{html.escape(sibling.title)}</a></li>'
                )
            out.append("</ol></div>")
        out.append("</div>")
        return "\n".join(out)

    def emit_callout(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        opener = re.match(r"^(:{3,})\s*(.*)$", lines[i])
        assert opener
        closer = re.compile(r"^:{3,}\s*$")
        head = opener.group(2).strip()
        parts = head.split(None, 1)
        if not parts:
            raise fail(page, base + i, "a callout needs a type, e.g. ::: why Title")
        kind = parts[0].lower()
        if kind == "toc":
            i += 1
            while i < len(lines) and not closer.match(lines[i]):
                i += 1
            if i >= len(lines):
                raise fail(page, base + i, "unclosed ::: toc")
            out.append(self.toc_grid())
            return i + 1
        if kind not in CALLOUTS:
            raise fail(
                page,
                base + i,
                f"unknown callout type {kind!r}; use one of {', '.join(sorted(CALLOUTS))}",
            )
        title = parts[1].strip() if len(parts) > 1 else ""
        opened_on = i

        body = []
        i += 1
        while i < len(lines) and not closer.match(lines[i]):
            body.append(lines[i])
            i += 1
        if i >= len(lines):
            raise fail(page, base + opened_on, "unclosed ::: callout")
        i += 1

        inner = self.blocks(body, page, base + opened_on + 1)
        label = title or kind.capitalize()
        out.append(
            f'<aside class="callout callout--{kind}">'
            f'<p class="callout-title">{self.inline(label)}</p>'
            f'<div class="callout-body">\n{inner}\n</div></aside>'
        )
        return i

    def emit_quote(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        if not self.seen_h1:
            raise fail(page, base + i, "blockquote before the level-1 heading")
        opened_on = i
        body = []
        while i < len(lines):
            line = lines[i]
            if line.startswith(">"):
                body.append(re.sub(r"^>\s?", "", line))
                i += 1
                continue
            if not line.strip():
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and lines[j].startswith(">"):
                    body.append("")
                    i = j
                    continue
            break
        inner = self.blocks(body, page, base + opened_on)
        if not self.dek_done:
            self.dek_done = True
            out.append(f'<div class="dek">\n{inner}\n</div>')
        else:
            out.append(f"<blockquote>\n{inner}\n</blockquote>")
        self.note(inner)
        return i

    def emit_table(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        opened_on = i
        rows = []
        while i < len(lines) and lines[i].strip().startswith("|"):
            rows.append(lines[i].strip())
            i += 1
        if len(rows) < 2 or not re.match(r"^\|[\s:|-]+\|$", rows[1]):
            raise fail(
                page, base + opened_on, "a table needs a header row and a |---| rule row"
            )

        def cells(row: str) -> list:
            """Split a table row on pipes, honouring escaped and in-code pipes."""
            row = row.strip()
            if row.startswith("|"):
                row = row[1:]
            if row.endswith("|"):
                row = row[:-1]
            values = []
            current = []
            in_code = False
            index = 0
            while index < len(row):
                char = row[index]
                if char == "\\" and index + 1 < len(row) and row[index + 1] == "|":
                    current.append("|")
                    index += 2
                    continue
                if char == "`":
                    in_code = not in_code
                    current.append(char)
                    index += 1
                    continue
                if char == "|" and not in_code:
                    values.append("".join(current).strip())
                    current = []
                    index += 1
                    continue
                current.append(char)
                index += 1
            values.append("".join(current).strip())
            return values

        aligns = []
        for spec in cells(rows[1]):
            left, right = spec.startswith(":"), spec.endswith(":")
            aligns.append("center" if left and right else "right" if right else "left")

        header = cells(rows[0])
        self.tables += 1
        out.append('<div class="table-wrap">')
        out.append("<table>")
        out.append("<thead><tr>")
        for index, cell in enumerate(header):
            style = f' style="text-align:{aligns[index]}"' if index < len(aligns) else ""
            out.append(f"<th{style}>{self.inline(cell)}</th>")
        out.append("</tr></thead><tbody>")
        for row in rows[2:]:
            values = cells(row)
            if len(values) > len(header):
                raise fail(
                    page, base + opened_on, f"row has more cells than the header: {row}"
                )
            out.append("<tr>")
            for index, cell in enumerate(values):
                style = (
                    f' style="text-align:{aligns[index]}"' if index < len(aligns) else ""
                )
                out.append(f"<td{style}>{self.inline(cell)}</td>")
            out.append("</tr>")
        out.append("</tbody></table>")
        out.append(f'<p class="table-caption">Table {self.tables}</p>')
        out.append("</div>")
        self.note(" ".join(header))
        return i

    def emit_list(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        opened_on = i
        first = _LIST_ITEM.match(lines[i])
        assert first
        base_indent = len(first.group(1))
        ordered = first.group(2)[0].isdigit()
        items = []

        while i < len(lines):
            line = lines[i]
            match = _LIST_ITEM.match(line)
            if match and len(match.group(1)) == base_indent:
                content = match.group(3)
                task, checked = False, False
                task_match = re.match(r"^\[( |x|X)\]\s+(.*)$", content)
                if task_match:
                    task = True
                    checked = task_match.group(1).lower() == "x"
                    content = task_match.group(2)
                items.append({"body": [content], "task": task, "checked": checked})
                i += 1
                continue
            if match and len(match.group(1)) > base_indent and items:
                items[-1]["body"].append(line)
                i += 1
                continue
            if not line.strip():
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines):
                    nxt = _LIST_ITEM.match(lines[j])
                    if nxt and len(nxt.group(1)) >= base_indent:
                        i = j
                        continue
                break
            if len(line) - len(line.lstrip()) > base_indent and items:
                items[-1]["body"].append(line)
                i += 1
                continue
            break

        if not items:
            raise fail(page, base + opened_on, f"unparsed content: {lines[opened_on]!r}")

        task_list = any(item["task"] for item in items)
        tag = "ol" if ordered else "ul"
        out.append(f'<{tag} class="{"task-list" if task_list else ""}">')
        width = base_indent + 2
        for item in items:
            body = item["body"]
            dedented = [
                part[width:] if len(part) > width else part.lstrip() for part in body[1:]
            ]
            inner = self.blocks([body[0]] + dedented, page, base + opened_on).strip()
            if inner.startswith("<p>") and inner.count("<p>") == 1 and inner.endswith("</p>"):
                inner = inner[3:-4]
            box = ""
            if item["task"]:
                checked = " checked" if item["checked"] else ""
                box = f'<input type="checkbox" disabled{checked}>'
            out.append(f"<li>{box}{inner}</li>")
        out.append(f"</{tag}>")
        return i

    def emit_indented(self, lines: list, i: int, out: list) -> int:
        body = []
        while i < len(lines):
            if lines[i].startswith("    "):
                body.append(lines[i][4:])
                i += 1
                continue
            if not lines[i].strip():
                look = i + 1
                if look < len(lines) and lines[look].startswith("    "):
                    body.append("")
                    i += 1
                    continue
            break
        while body and not body[-1].strip():
            body.pop()
        self.listings += 1
        code = html.escape(chr(10).join(body), quote=False)
        out.append(
            '<figure class="listing listing--unlabeled">'
            f'<pre><code class="language-text">{code}</code></pre>'
            f'<figcaption><span class="listing-number">Listing {self.listings}</span>'
            '<span class="listing-lang">no language</span></figcaption></figure>'
        )
        return i

    def emit_raw(self, lines: list, i: int, out: list) -> int:
        block = []
        while i < len(lines) and lines[i].strip():
            block.append(lines[i])
            i += 1
        out.append("\n".join(block))
        return i

    def emit_paragraph(self, lines: list, i: int, page: str, base: int, out: list) -> int:
        opened_on = i
        body = []
        while i < len(lines) and lines[i].strip():
            if body and self.block_start(lines[i]):
                break
            body.append(lines[i])
            i += 1
        if not body:
            raise fail(page, base + opened_on, f"unparsed content: {lines[opened_on]!r}")
        pieces = re.split(r"[ \t]{2,}\n", "\n".join(body) + "\n")
        rendered = []
        for piece in pieces:
            if not piece.strip():
                continue
            joined = " ".join(part.strip() for part in piece.split("\n"))
            rendered.append(self.inline(joined))
        paragraph = "<br>".join(rendered)
        out.append(f"<p>{paragraph}</p>")
        self.note(paragraph)
        return i


# ---------------------------------------------------------------------------
# page shell
# ---------------------------------------------------------------------------


def nav_html(book: Book, current: Entry) -> str:
    parts = ['<p class="nav-label">Front matter</p>', '<ul class="nav-list">']
    for entry in book.entries:
        if not entry.number:
            parts.append(nav_item(entry, current))
    parts.append("</ul>")

    seen = []
    for entry in book.entries:
        if not (entry.number or entry.appendix) or entry.part in seen:
            continue
        seen.append(entry.part)
        parts.append(f'<p class="nav-label">{html.escape(entry.part)}</p>')
        parts.append('<ul class="nav-list">')
        for sibling in book.entries:
            if sibling.part == entry.part and (sibling.number or sibling.appendix):
                parts.append(nav_item(sibling, current))
        parts.append("</ul>")
    return "\n".join(parts)


def nav_item(entry: Entry, current: Entry) -> str:
    cls = ' class="is-current"' if entry.slug == current.slug else ""
    if entry.appendix:
        number = f'<span class="nav-num">{entry.appendix}</span>'
    elif entry.number:
        number = f'<span class="nav-num">{entry.number}</span>'
    else:
        number = ""
    return f'<li{cls}><a href="{entry.slug}.html">{number}{html.escape(entry.title)}</a></li>'


def toc_html(entry: Entry) -> str:
    items = [section for section in entry.sections if section["level"] == 2]
    if not items:
        return ""
    links = "\n".join(
        f'<li><a href="#{section["anchor"]}">{html.escape(section["title"])}</a></li>'
        for section in items
    )
    return (
        '<nav class="toc" aria-label="On this page">'
        '<p class="toc-title">On this page</p>'
        f"<ul>{links}</ul></nav>"
    )


def page_html(book: Book, entry: Entry, previous: Entry, following: Entry) -> str:
    is_cover = entry.slug == "index"
    title = book.cfg["title"] if is_cover else f"{entry.title} — {book.cfg['title']}"

    opener = ""
    if entry.appendix:
        opener = (
            f'<header class="chapter-head"><p class="chapter-part">'
            f"{html.escape(entry.part)}</p>"
            f'<p class="chapter-number">Appendix {entry.appendix}</p></header>'
        )
    elif entry.number:
        opener = '<header class="chapter-head">'
        opener += f'<p class="chapter-part">{html.escape(entry.part)}</p>'
        opener += f'<p class="chapter-number">Chapter {entry.number}</p></header>'
    elif entry.part:
        opener = (
            f'<header class="chapter-head"><p class="chapter-part">'
            f"{html.escape(entry.part)}</p></header>"
        )

    if (entry.number or entry.appendix) and entry.part and entry.part_first:
        opener += (
            '<aside class="part-note"><p class="part-note-title">In this part</p>'
            f"<p>{html.escape(entry.part_blurb)}</p></aside>"
        )

    pager = []
    if previous:
        pager.append(
            f'<a class="pager-prev" href="{previous.slug}.html">'
            '<span class="pager-dir">Previous</span>'
            f'<span class="pager-title">{html.escape(previous.title)}</span></a>'
        )
    if following:
        pager.append(
            f'<a class="pager-next" href="{following.slug}.html">'
            '<span class="pager-dir">Next</span>'
            f'<span class="pager-title">{html.escape(following.title)}</span></a>'
        )

    edit_url = f"{book.repo}/blob/{book.branch}/book/{entry.file}"
    repo = html.escape(book.repo, quote=True)
    edit = html.escape(edit_url, quote=True)
    body_class = "book book--cover" if is_cover else "book"

    return f"""<!doctype html>
<html lang="en" data-theme="paper">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(book.cfg.get('description', ''), quote=True)}">
<link rel="stylesheet" href="assets/book.css">
<script>
try {{
  var saved = localStorage.getItem("book-theme");
  if (saved) document.documentElement.dataset.theme = saved;
}} catch (e) {{}}
</script>
</head>
<body class="{body_class}" data-part="{entry.part_index}">
<a class="skip-link" href="#content">Skip to content</a>
<header class="topbar">
  <button class="icon-button" id="nav-toggle" aria-label="Toggle contents" aria-expanded="false">&#9776;</button>
  <a class="topbar-title" href="index.html">{html.escape(book.cfg['title'])}</a>
  <span class="topbar-sub">{html.escape(book.cfg.get('subtitle', ''))}</span>
  <span class="topbar-spacer"></span>
  <button class="icon-button" id="search-open" aria-label="Search the book">Search <kbd>/</kbd></button>
  <button class="icon-button" id="theme-toggle" aria-label="Toggle colour scheme">&#9680;</button>
  <a class="icon-button" href="{repo}" rel="noopener">Repo</a>
</header>
<div class="layout">
  <nav class="sidebar" id="sidebar" aria-label="Book contents">
    <div class="sidebar-inner">{nav_html(book, entry)}</div>
  </nav>
  <main class="content" id="content">
{opener}
    <article class="prose">
{entry.html}
    </article>
    <nav class="pager" aria-label="Page navigation">{"".join(pager)}</nav>
    <footer class="book-footer">
      <p>{html.escape(book.cfg['title'])} &mdash; {html.escape(book.cfg.get('edition', ''))}.
      <a href="{edit}" rel="noopener">Edit this page</a> &middot;
      <a href="{repo}" rel="noopener">selinux-pac</a>.
      Every example in this book runs against that repository.</p>
    </footer>
  </main>
  <aside class="marginalia">
{toc_html(entry)}
  </aside>
</div>
<div class="search" id="search" hidden>
  <div class="search-panel" role="dialog" aria-modal="true" aria-label="Search">
    <input id="search-input" type="search" placeholder="Search the book&#8230;" autocomplete="off">
    <ul id="search-results"></ul>
    <p class="search-hint">Enter to open &middot; Esc to close</p>
  </div>
</div>
<script src="assets/book.js"></script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# build and check
# ---------------------------------------------------------------------------


def render_all(book: Book, book_dir: Path, out_root: Path | None):
    """Render every page; write HTML when out_root is given."""
    problems: list = []
    warnings: list = []
    search_index: list = []

    for position, entry in enumerate(book.entries):
        source = book_dir / entry.file
        if not source.is_file():
            problems.append(f"{entry.file}: listed in book.toml but missing")
            continue
        renderer = Renderer(book, entry)
        try:
            entry.html = renderer.render(source.read_text(encoding="utf-8"), entry.file)
        except BookError as exc:
            problems.append(str(exc))
            continue
        entry.ids = renderer.ids
        entry.sections = renderer.sections

        if not entry.h1:
            problems.append(f"{entry.file}: missing a level-1 heading")
        elif entry.h1.strip() != entry.title.strip() and not (
            entry.slug == "index" and entry.h1.strip() == book.cfg["title"].strip()
        ):
            warnings.append(
                f"{entry.file}: h1 {entry.h1!r} differs from the book.toml title "
                f"{entry.title!r}"
            )

        if out_root is None:
            continue
        previous = book.entries[position - 1] if position else None
        following = book.entries[position + 1] if position + 1 < len(book.entries) else None
        (out_root / f"{entry.slug}.html").write_text(
            page_html(book, entry, previous, following), encoding="utf-8"
        )
        search_index.append(
            {
                "p": entry.slug,
                "t": entry.title,
                "n": entry.number,
                "part": entry.part,
                "s": [
                    {
                        "a": section["anchor"],
                        "h": section["title"],
                        "x": " ".join(section["text"])[:1200],
                    }
                    for section in entry.sections
                ],
            }
        )
    return problems, warnings, search_index


def build(book: Book, book_dir: Path, out_root: Path):
    out_root.mkdir(parents=True, exist_ok=True)
    problems, warnings, search_index = render_all(book, book_dir, out_root)

    assets_src = book_dir / "assets"
    if not assets_src.is_dir():
        problems.append(f"{assets_src}: missing assets directory")
    else:
        target = out_root / "assets"
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(assets_src, target)

    (out_root / "search.json").write_text(
        json.dumps(search_index, separators=(",", ":")), encoding="utf-8"
    )
    # GitHub Pages runs Jekyll unless told otherwise; the book needs no processing.
    (out_root / ".nojekyll").write_text("", encoding="utf-8")
    write_sitemap(book, out_root)
    return problems, warnings


def write_sitemap(book: Book, out_root: Path) -> None:
    base = book.cfg.get("site_url", "").rstrip("/")
    if not base:
        return
    urls = "\n".join(
        f"  <url><loc>{base}/{entry.slug}.html</loc></url>" for entry in book.entries
    )
    (out_root / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}\n</urlset>\n",
        encoding="utf-8",
    )


_SPAN = re.compile(r"`([^`]+)`")
_PY_CALL = re.compile(r"python3\s+(cli/[A-Za-z0-9_]+\.py)")
_CLI_MODULES = {}
_REPO_DIRS = (
    "ansible",
    "cli",
    "config",
    "demo",
    "docs",
    "packaging",
    "scripts",
    "selinux",
    "tests",
    "tools",
    "book",
    ".github",
)

# Paths the prose is allowed to name even though no such file is committed:
# build artefacts and runtime locations that live on a host or are gitignored.
_PATH_EXCEPTIONS = {
    "selinux/myapp.pp",
    "selinux/shopapi/shopapi.pp",
    "selinux/payments/payments.pp",
    "policy_out/avc.log",
    "policy_out/findings.json",
    "policy_out/myapp.te",
    "policy_out/myapp.fc",
    "ansible/inventory.dev.yml",
    "ansible/inventory.production.yml",
    "ansible/inventory.staging.yml",
    "packaging/internal.env",
    "cli/.env",
}


def looks_like_repo_path(token: str) -> bool:
    candidate = token.strip().rstrip(".,;:")
    if not candidate or "/" not in candidate:
        return False
    if candidate.startswith(("/", "~", "-", "http", "$")):
        return False
    # placeholders, globs and shell fragments are not paths
    if any(ch in candidate for ch in "<>*%{}|()$'\"`"):
        return False
    if candidate.endswith("/"):
        return False
    head = candidate.split("/", 1)[0]
    if head not in _REPO_DIRS:
        return False
    return bool(re.search(r"\.[A-Za-z0-9]+$", candidate))


def check(book: Book, book_dir: Path):
    problems, warnings, _ = render_all(book, book_dir, None)
    pages = {entry.slug: entry for entry in book.entries}

    for entry in book.entries:
        source = book_dir / entry.file
        if not source.is_file():
            continue
        linker = Renderer(book, entry)
        in_fence = False
        marker = ""
        for line_no, line in enumerate(source.read_text(encoding="utf-8").split("\n"), 1):
            for token in _SPAN.findall(line):
                if not looks_like_repo_path(token):
                    continue
                candidate = token.strip().rstrip(".,;:")
                if candidate in _PATH_EXCEPTIONS:
                    continue
                if not (REPO_ROOT / candidate).exists():
                    problems.append(
                        f"{entry.file}:{line_no}: names a repository path that does not "
                        f"exist: {candidate}"
                    )
            if in_fence:
                for called in _PY_CALL.findall(line):
                    if not (REPO_ROOT / called).is_file():
                        problems.append(
                            f"{entry.file}:{line_no}: invokes a missing module: {called}"
                        )
                        continue
                    if called not in _CLI_MODULES:
                        source = (REPO_ROOT / called).read_text(encoding="utf-8")
                        _CLI_MODULES[called] = '__name__ == "__main__"' in source
                    if not _CLI_MODULES[called]:
                        problems.append(
                            f"{entry.file}:{line_no}: {called} has no __main__ guard, so "
                            f"`python3 {called}` is not a command"
                        )
                if re.match(r"^\s*" + re.escape(marker) + r"\s*$", line):
                    in_fence = False
                continue
            fence = _FENCE.match(line)
            if fence:
                in_fence = True
                marker = fence.group(1)
                if not fence.group(2):
                    warnings.append(f"{entry.file}:{line_no}: code fence without a language")
                continue
            if re.match(r"^\s*=+\s*$", line):
                problems.append(
                    f"{entry.file}:{line_no}: setext headings (=== underline) are not supported"
                )
            for match in _LINK.finditer(line):
                target = match.group(2)
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if target.startswith("repo:"):
                    rest = target[len("repo:") :]
                    path = rest.split("#")[0].rstrip("/")
                    if path.startswith("book/") and path.endswith(".md"):
                        slug = Path(path).name[:-3]
                        if slug in pages:
                            continue
                    if not (REPO_ROOT / path).exists():
                        problems.append(
                            f"{entry.file}:{line_no}: repo: target does not exist: {path}"
                        )
                    continue
                if target.startswith("asset:"):
                    path = target[len("asset:") :].split("#")[0]
                    if not (book_dir / "assets" / path).exists():
                        problems.append(
                            f"{entry.file}:{line_no}: asset: target does not exist: {path}"
                        )
                    continue
                if linker.repo_relative(target) is not None:
                    continue
                if target.startswith("#"):
                    anchor = target[1:]
                    if anchor and anchor not in entry.ids:
                        problems.append(
                            f"{entry.file}:{line_no}: anchor not on this page: {target}"
                        )
                    continue
                if target.endswith(".md") or ".md#" in target:
                    filepart, _, anchor = target.partition("#")
                    other = pages.get(Path(filepart).name[:-3])
                    if other is None:
                        problems.append(
                            f"{entry.file}:{line_no}: link to a page not in book.toml: {target}"
                        )
                        continue
                    if anchor and anchor not in other.ids:
                        problems.append(
                            f"{entry.file}:{line_no}: anchor #{anchor} missing in {other.file}"
                        )
                    continue
                problems.append(
                    f"{entry.file}:{line_no}: link target must be http(s), repo:, asset:, "
                    f"#anchor or *.md: {target}"
                )

    listed = {entry.file for entry in book.entries}
    for path in sorted(book_dir.rglob("*.md")):
        relative = path.relative_to(book_dir).as_posix()
        if relative in listed or relative == "AUTHORING.md":
            continue
        warnings.append(f"{relative}: markdown file is not listed in book.toml")
    return problems, warnings


def serve(out_root: Path, port: int) -> None:
    import functools
    import http.server
    import socketserver

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(out_root)
    )
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"book: serving http://127.0.0.1:{port}/ (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nbook: stopped")


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description="Build the SELinux manual")
    parser.add_argument("--book", default=str(REPO_ROOT / "book"))
    parser.add_argument("--out", default=str(REPO_ROOT / "site"))
    parser.add_argument("--check", action="store_true", help="validate without writing")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--serve", type=int, metavar="PORT", help="serve the built site")
    args = parser.parse_args(argv)

    book_dir = Path(args.book).resolve()
    out_root = Path(args.out).resolve()
    book = load_book(book_dir)

    if args.check:
        problems, warnings = check(book, book_dir)
    else:
        problems, warnings = build(book, book_dir, out_root)

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)

    if problems or (args.strict and warnings):
        print(
            f"book: FAILED ({len(problems)} errors, {len(warnings)} warnings)",
            file=sys.stderr,
        )
        return 1

    if args.check:
        print(f"book: OK ({len(book.entries)} pages, {len(warnings)} warnings)")
    else:
        print(f"book: built {len(book.entries)} pages into {out_root}")

    if args.serve:
        serve(out_root, args.serve)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
