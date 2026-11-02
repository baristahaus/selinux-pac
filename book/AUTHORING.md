# Authoring the book

How to add or change a chapter of *SELinux for Developers and Administrators*, and how the
generator will complain if you get it wrong. The book is built by `tools/book/build.py`
(standard library only) from `book/`.

```bash
make book        # build the site into site/ (gitignored)
make book-check  # validate: links, anchors, repo paths, the markdown subset, the chapter shape
make book-lint   # book-check, then the prose rules below, with file:line and the fix
make book-serve  # build, then serve at http://127.0.0.1:8080
BOOK_HOST=0.0.0.0 BOOK_PORT=9000 make book-serve  # reachable from your phone or another machine
```

`make check` runs `book-check` too, so a broken link fails the repository health check.

## Adding a chapter

1. Write `book/<part>/<NN>-<slug>.md` with a single `# Title`.
2. Add it to `book/book.toml`: the file, the title, and the part it belongs to. The number in
   the filename is a convention. The chapter *number* comes from its position in `book.toml`.
3. Run `make book-check`. Every error names a file and a line.

## Read this before you write

1. `book/part1/01-the-default-answer.md` and `book/part1/02-what-selinux-actually-checks.md`:
   the voice and structure to match.
2. `book/lab.md`: the three lab paths every chapter refers to (laptop only, one RHEL host, two
   hosts plus a controller). Never tell a laptop-only reader to run something that needs a host.

## Markdown subset

The generator implements a deliberate subset and fails the build on anything else, rather
than silently dropping content. Stay inside this list.

- Exactly one `# Title` per file, matching the title in `book.toml`. A different H1 is an error:
  the sidebar, the contents and the search index all read the `book.toml` title.
- The first `>` blockquote after the H1 becomes the chapter dek. Later blockquotes are quotes.
- `##` and `###` headings, and nothing deeper. A `####` is an error, because a fourth level
  reaches neither the "On this page" margin nor the search index.
- Pipe tables with a `|---|---|` rule row. Pipes inside `` `code spans` `` are handled. Escape a
  literal pipe as `\|`.
- Fenced code with a language, optionally titled:
  ```` ```bash title="Compile the module" ````. An empty info string is an error: give it
  `text` if the listing is prose output or a directory tree. `mermaid` renders as a diagram. Write
  it top-down (`flowchart TD`), because a left-to-right flow is wider than the text column and the
  reader has to scroll sideways to read it.
- Lists (`-`, `1.`, nested by indentation) and task items (`- [ ]`). Put a listing inside a step in
  a fenced block. Four spaces inside a list item is an indented listing, so the generator numbers
  it as one and the text is no longer part of the step.
- Images: `![alt](asset:name.svg)` or `![alt](repo:docs/diagram.png)`. The target validates like a
  link target, and the page gets a lazy `<img>` with the alt text.
- Inline links take an optional title: `[Label](https://example.test/a "Title")`.
- Unclosed markup is an error, not a stray character in the page: `` ` ``, `**`, and `~~` each
  need a partner on the same page.
- Callouts, opened by three or more colons and closed by a line of three or more colons:

      ::: why Why this matters
      Body text, lists, tables and code all work inside.
      :::

  Types: `why`, `how`, `try`, `note`, `warn`, `good`, `story`. `::: toc` (any shape) expands to
  the generated table of contents on the cover page. A `:::` inside a listing inside a callout is
  listing text, not the end of the callout.
- Raw HTML blocks pass through, but prefer markdown. A line that starts with `<` opens a raw block
  that runs to the next blank line, so put a blank line after one. Every block-level tag a raw
  block opens must close in that block, or the build fails: an unclosed `<div>` otherwise swallows
  the rest of the page.

Not supported: footnotes, setext headings (`===` under a line), HTML comments, definition lists.

## Links

| Target | Meaning | Validated |
|---|---|---|
| `NN-slug.md` or `NN-slug.md#anchor` | another chapter | the page exists in `book.toml`; the anchor exists in that page |
| `repo:path/to/file` | a file in this repository | the path must exist in the worktree |
| `../selinux/myapp/myapp.fc`, `../../cli/`, `selinux/` | repository paths written relative to the chapter | resolved and validated, then rendered as a GitHub URL |
| `asset:name.svg` | a file in `book/assets/` | the file must exist |
| `https://…` | external | not validated |
A link to another chapter written as a repository path (`../part2/09-file-contexts-and-the-label-lifecycle.md`)
resolves to that chapter's **page**, not to the GitHub copy. Any `.md` target whose basename is a
page in `book.toml` is treated as a chapter link, and its anchor is validated like one.

Cross-chapter anchors are validated, so if you rename a heading you must fix the links to it.
Prefer adding an explicit anchor (`## Heading {#stable-id}`) for anything another chapter cites.

A code span that names a repository path is also a claim: `` `scripts/dev_generate_policy.sh` ``,
`` `selinux/myapp/myapp.fc` `` and `` `config/myapp.manifest.yml` `` must exist in the worktree, or
`make book-check` fails. Write a claimed path from the repository root, or relative to the chapter
(`part4/19-canary-soak-enforce.md`). A shorthand (`tasks/rollback.yml`,
`01-mislabeled-var-lib/expected.json`) claims nothing, so it is never checked and a reader cannot
find the file. A host path (`/var/log/audit/audit.log`) and a distro path (`system/init.if`) are
not repository claims. A path inside a listing is evidence, and the check does not read listings.
Two paths are exempt because they are gitignored: `ansible/inventory.dev.yml` and
`packaging/internal.env`. See `_PATH_EXCEPTIONS` in `tools/book/build.py`.

## Voice and accuracy

- Second person, short paragraphs, why before how, then show it. No marketing, no emoji, no
  "simply", no filler openers.
- Every claim about this repository must match the file you read: real flags, real script names,
  real paths, real defaults, real fixture payloads.
- Every command is either present in this repository or a standard RHEL 9 / CentOS Stream /
  Fedora command used correctly. Root commands are prefixed `#` and name the host.
- Never guess a flag, a default, or a path. Check, or describe the behavior without the
  specific.
- Composite or illustrative incidents must be labeled as such. Fixture logs and real command
  output may be quoted as-is.
- The book's hard rules: the host stays Enforcing (only an application domain is ever made
  permissive). Production is never mutated by hand. `soak_min_days: 0` is lab-only. Never
  endorse `audit2allow | semodule -i`.

## Prose rules

The book follows the `simple-english` skill (ASD-STE100 in spirit, Plain mode). Read
the `simple-english` skill at <https://github.com/AminBlg/SimpleEnglish> before you write a chapter. The build checks links and structure. These rules are what it cannot see.

- One sentence, one fact. Twenty words in a step, twenty-five in a description.
- No em-dash and no semicolon in prose. Write two sentences, or name the relation: because,
  but, so, for example.
- Simple tenses, active voice, and the actor named. No present perfect, and no `-ing` clause
  after a comma.
- Only `can`, `will`, and `must`. Never `should`, `would`, `may`, `might`, or `could`.
- No contractions. Keep articles, and keep "that".
- Condition before command: "If the build fails, read the log."
- One word for one thing inside a chapter. `check` covers verify, confirm, validate, and
  ensure. `configuration` covers config and settings. Keep `option` for a command-line flag.
- Delete the words that carry no fact: simply, seamlessly, robust, powerful, comprehensive,
  crucial, leverage, "in order to", "it is worth noting".
- American spelling: behavior, summarize, labeled, recognize, analyze.
- A warning gives the command or the condition first, then the risk.
- Define a concept term in under ten words at its first use in a chapter. Do not define a
  product name or the tool the chapter is about.

Three exceptions exist because the structure carries information:

| Exception | Why it stays |
|---|---|
| Heading text does not change | Anchors link to it. See Links above. |
| Bold in a table's first column, and a bold label on a list item | Those are keys and labels, not emphasis |
| Text inside a code block, a code span, a quotation, or an italic run | It is evidence, a term, or someone else's wording. The correctness passes compare it byte for byte, and the lint skips all four, so quote a manual instead of rewriting its hedge. |
| An identifier keeps its real name | `validate_app_manifest.sh` is never called `check_...` in prose. Say "check the manifest", then show the command. |

## Chapter shape

`tools/book/build.py` enforces this contract for every numbered chapter, and the build fails
without it:

1. An H1, a dek, and an opening section that states the problem.
2. At least one `::: why` and at least one `::: try`. The `try` says where it runs, either by
   naming the lab path (Path A, B, or C from `lab.md`) or by naming the host it needs. The check
   enforces that the callout is present, not the wording.
3. It closes with `## What you can do now` and a short list of capabilities, usually three to five
   items, as bullets, a table, or a paragraph.

The front matter and the appendices keep their own shape. Length is not enforced. A chapter runs
between 1000 and 2700 words outside code, and the short ones are short on purpose. Add a section
when the reader has a question left, not to reach a count.

## Publishing

The book is built and served from a checkout. No CI workflow publishes it, so `make book` and
`make book-serve` are the whole path from source to a page in a browser. `make check` runs
`book-check` with the rest of the repository health checks, so a broken link still fails the
build before it reaches a reader.

`book.toml` carries `repo`, `branch` and `site_url`: the URLs a built book prints. They point
at the upstream repository, so a preview built from a fork prints links that 404 until the change
merges. Overwrite them for a preview without editing the file:

```bash
BOOK_REPO=https://github.com/your-fork/selinux-pac BOOK_BRANCH=preview make book
BOOK_SITE_URL=https://your-fork.github.io/selinux-pac make book
```
