# Authors

Git holds the author of every commit. This page names the people and the tools behind that
history, says what each side works on, and explains where the GitHub numbers differ from the
git numbers.

## People

| Name | Work in this repository | Commits on `main` |
|---|---|---|
| **anurag-saran** | Started the project. Writes the running parts: `cli/`, `selinux/`, `ansible/`, `packaging/`, `scripts/`, `tests/`, `config/`, `demo/`, and the numbered pages in `docs/`. Holds `/selinux/` and `/ansible/` in `.github/CODEOWNERS`. | 74 (2026-09-12 to 2026-09-18) |
| **baristahaus** | Wrote the book and its tooling: `book/`, `tools/book/build.py`, the `book`, `book-check` and `book-serve` targets in `Makefile`, and `.github/workflows/book.yml`. Rewrote the manual and the docs pages in plain English, then corrected the book against the sources it quotes. | 27 (2026-09-18 to 2026-09-19) |

Run [Count it yourself](#count-it-yourself) to repeat every number above.

## AI help

Both sides wrote this code with an AI coding agent. The tree records that fact in two different
ways.

| Fact | Effect |
|---|---|
| 25 commits from anurag-saran end with the trailer `Co-authored-by: Cursor <cursoragent@cursor.com>`. | GitHub links that address to the `cursoragent` account, so the Contributors graph names it as a third contributor. |
| None of the 27 commits from baristahaus carries a trailer. | The Contributors graph shows that work under one human name. This page is the record instead. |

The agent produced text. A person read it and merged it. Each person owns the result of the
commits they authored.

## GitHub numbers and git numbers

The Contributors page counts on its own rules. It says them at the top of the page: contributions
per week to the default branch, excluding merge commits.

| Difference | Reason |
|---|---|
| The page shows 73 commits for anurag-saran. `git shortlog` shows 74. | `main` holds one merge commit, `da0af9c`. The page drops it. |
| The page shows 24 commits for `cursoragent`. The trailer appears 25 times. | `da0af9c` carries the trailer and is a merge commit. |
| The page showed nothing right after a history rewrite. | GitHub rebuilds the graph in the background. The rebuild for this fork finished about ten minutes after the push that rewrote the 27 commits. |

The graph also covers a fixed window. The page opens on the last three months, so work older than
that window needs a wider range in the URL.

## Count it yourself

```bash
git shortlog -sne HEAD                                     # commits per author and email
git log --grep='Co-authored-by: Cursor' --oneline | wc -l  # commits that carry the Cursor trailer
git rev-list --merges --count HEAD                         # merge commits the graph drops
git log --oneline upstream/main..HEAD | wc -l              # commits unique to the fork
```
