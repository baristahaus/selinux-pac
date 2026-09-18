# Authoring the book

How to add or change a chapter of *SELinux for Developers and Administrators*, and how the
generator will complain if you get it wrong. The book is built by `tools/book/build.py`
(standard library only) from `book/`.

```bash
make book        # build the site into site/ (gitignored)
make book-check  # validate: internal links, anchors, repo: targets, markdown subset
make book-serve  # build, then serve at http://127.0.0.1:8000
```

`make check` runs `book-check` too, so a broken link fails the repository health check.

## Adding a chapter

1. Write `book/<part>/<NN>-<slug>.md` with a single `# Title`.
2. Add it to `book/book.toml` — the file, the title, and the part it belongs to. The number in
   the filename is a convention; the chapter *number* comes from its position in `book.toml`.
3. Run `make book-check`. Every error names a file and a line.

## Read this before you write

1. `book/part1/01-the-default-answer.md` and `book/part1/02-what-selinux-actually-checks.md` —
   the voice and structure to match.
2. `book/lab.md` — the three lab paths every chapter refers to (laptop only, one RHEL host, two
   hosts plus a controller). Never tell a laptop-only reader to run something that needs a host.

## Markdown subset

The generator implements a deliberate subset and **fails the build** on anything else, rather
than silently dropping content. Stay inside this list.

- Exactly one `# Title` per file, matching the title in `book.toml`.
- The first `>` blockquote after the H1 becomes the chapter dek. Later blockquotes are quotes.
- `##` and `###` headings. `##` entries appear in the "On this page" margin and in search.
- Pipe tables with a `|---|---|` rule row. Pipes inside `` `code spans` `` are handled; escape a
  literal pipe as `\|`.
- Fenced code with a language, optionally titled:
  ```` ```bash title="Compile the module" ````. An empty info string is a warning: give it
  `text` if the listing is prose output or a directory tree. `mermaid` renders as a diagram; write
  it top-down (`flowchart TD`), because a left-to-right flow is wider than the text column and the
  reader has to scroll sideways to read it.
- Lists (`-`, `1.`, nested by indentation) and task items (`- [ ]`).
- Callouts, opened by three or more colons and closed by a line of three or more colons:

      ::: why Why this matters
      Body text, lists, tables and code all work inside.
      :::

  Types: `why`, `how`, `try`, `note`, `warn`, `good`, `story`. `::: toc` (any shape) expands to
  the generated table of contents on the cover page.
- Raw HTML blocks pass through, but prefer markdown.

Not supported: footnotes, setext headings (`===` under a line), HTML comments, definition lists.

## Links

| Target | Meaning | Validated |
|---|---|---|
| `NN-slug.md` or `NN-slug.md#anchor` | another chapter | the page exists in `book.toml`; the anchor exists in that page |
| `repo:path/to/file` | a file in this repository | the path must exist in the worktree |
| `../selinux/myapp.fc`, `../../cli/`, `selinux/` | repository paths written relative to the chapter | resolved and validated, then rendered as a GitHub URL |
| `asset:name.svg` | a file in `book/assets/` | the file must exist |
| `https://…` | external | not validated |

Cross-chapter anchors are validated, so if you rename a heading you must fix the links to it.
Prefer adding an explicit anchor (`## Heading {#stable-id}`) for anything another chapter cites.

## Voice and accuracy

- Second person, short paragraphs, why before how, then show it. No marketing, no emoji, no
  "simply", no filler openers.
- Every claim about this repository must match the file you read: real flags, real script names,
  real paths, real defaults, real fixture payloads.
- Every command is either present in this repository or a standard RHEL 9 / CentOS Stream /
  Fedora command used correctly. Root commands are prefixed `#` and name the host.
- Never guess a flag, a default or a path. Verify, or describe the behaviour without the
  specific.
- Composite or illustrative incidents must be labelled as such. Fixture logs and real command
  output may be quoted as-is.
- The book's hard rules: the host stays Enforcing (only an application domain is ever made
  permissive); production is never mutated by hand; `soak_min_days: 0` is lab-only; never
  endorse `audit2allow | semodule -i`.

## Chapter shape

H1 and dek; an opening section that states the problem; four to eight `##` sections that build
the how; at least one `::: why` and one `::: try` (the `try` says where it runs); and a closing
`## What you can do now` with three to five bullets of capability. Length: 1600–2400 words plus
code.

## Publishing

`.github/workflows/book.yml` validates every pull request that touches `book/` or
`tools/book/`, and deploys `main` to GitHub Pages. Enable it once under
*Settings → Pages → Build and deployment → Source: GitHub Actions*.
