# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`disconnect3d.pl` — a personal Jekyll blog (security / low-level / CTF writeups) hosted on GitHub Pages. The site is built by GitHub Pages from `master`; there is no separate build/deploy pipeline in this repo.

## Local preview

`local.sh` runs the site at `http://localhost:4000` via a containerized Jekyll:

```sh
./local.sh   # podman run -it --rm -v `pwd`:/site -p 4000:4000 bretfisher/jekyll-serve
```

The generated `_site/` directory is gitignored — never commit it.

## Authoring posts

- Posts live in `_posts/` and must be named `YYYY-MM-DD-slug.markdown`. GitHub Pages will not publish a post whose filename date is in the future.
- Required front matter: `layout: post`, `title`, `date` (with timezone-aware time, site timezone is `Europe/Warsaw` per `_config.yml`), and `tags` (a YAML flow-sequence list, e.g. `tags: [ctf, pwn]` — match existing posts). Some posts also set `excerpt_separator: <!--more-->` and place a `<!--more-->` marker to control where the index excerpt is cut.
- The post layout (`_layouts/post.html`) embeds Utterances comments keyed by `pathname`, scoped to the `disconnect3d/disconnect3d.github.io` repo's issues. Renaming or moving a published post breaks its existing comment thread.
- Permalinks use `permalink: pretty` (`/YYYY/MM/DD/slug/`), so the URL is derived from filename + date — changing either after publish breaks inbound links.

## Blog post writing style

When drafting or editing posts, match the voice of the existing `_posts/`. Characteristics:

### Voice and tone
- First person, conversational and informal. Singular ("I found", "I wondered", "I have decided") for personal investigation; plural ("we can see", "let's look", "lets first see") when walking the reader through steps or crediting a team effort.
- Friendly and light — occasional emoticons/emoji at the end of sentences or sections (`:)`, `:P`, `:D`, `o/`, "heh"). Don't overdo it; roughly one per section at most.
- Honest and self-deprecating. Document dead ends and failed ideas, not just the winning path (e.g. the race-condition and path-traversal ideas that *didn't* work in the Insomni'hack writeup; the capability-flag guesses that failed in the Docker reboot post). Own mistakes plainly ("I forgot to filter flag_2", "I really should have passed `--`").
- Curiosity-driven framing: posts often start from a question ("I wondered why this happened", "whether one can reboot their PC from a docker container", "But what if I tell you that a null pointer can point to valid memory?").

### Structure
- Open with 1–2 sentences stating what the post is and where it came from. Writeups name the CTF, task, category, and team up front (e.g. "This is a writeup from Confidence CTF Teaser 2016 - GoBox and GoBox2 tasks from pwn category.").
- Longer posts get a `### TL;DR` / `### TLDR` bullet summary near the top, and CTF writeups often a `### Task info` block (CTF, Task, Category, Solved by, Points, Task description as a blockquote).
- Use `##`/`###` headings to break up the walkthrough. Progress in the order you actually worked: recon → static/dynamic analysis → idea(s) → solution → final script.
- Close with a `## Summary` / `## Conclusion` / `## Final thoughts` section — often bulleted takeaways or lessons ("We should never trust libs without checking the implementation...").
- Frequently end with an acknowledgements line thanking friends/collaborators/reviewers, linking their sites/handles. Some posts add a "Some random stuff" section of miscellaneous notes, or a "share this post / related reading" list.

### Explaining technical content
- Teach from first principles — assume a reader who may not know the underlying concept. Expand acronyms on first use (NX = Non-eXecutable, RELRO, PIE, ASLR, ROP, SMAP/SMEP) and link the first mention to Wikipedia, a man page, a spec, OWASP, or StackOverflow.
- Quote authoritative sources (man pages via `man 2 reboot`, glibc/RedHat bug trackers, PEPs, CPython source on GitHub) in blockquotes, and link to the exact line/section when possible.
- Show the reasoning, including arithmetic (stack-frame offset calculations, gadget address math) inline in comments.

### Code and command blocks
- Use fenced code blocks with a language tag: ```c```, ```python```/```py```, ```bash```/```sh```, ```go```, ```php```, ```javascript```, ```sql```, ```html```, ```dockerfile```.
- Show real, reproducible shell sessions: include the prompt (`$`), the command, and its actual verbatim output (`file`, `checksec`, `strace`, `objdump`, `gdb`, `curl -v`, ...). Don't paraphrase output.
- Annotate exploit scripts and assembly heavily with inline comments explaining each step.
- Inline-code (backticks) for commands, function names, filenames, registers, flags, syscalls, and env vars.
- Illustrate with screenshots (`![alt]({{ site.url }}assets/...)`) and asciinema embeds for terminal recordings where helpful.

### Reproducibility
- Make it possible for the reader to follow along: link to challenge files/repos, give the exact commands to build and run things locally (Docker commands, compiler invocations), and mention how you found something (e.g. "this can also be found with `strace`").

### Formatting conventions
- **Bold** for key warnings or the load-bearing claim; *italics* for asides and "Fun fact:" / "Note:" tangents.
- Ellipses ("...") for suspense/transitions ("And... it turns out there is such a case").
- When adding info after publishing, append a dated **EDIT:** / "NOTE:" inline or an `### Edits` / "Edits" list at the end (`2025.03.04: Added ...`) and credit who pointed it out — don't silently rewrite, since permalinks and comment threads are stable.

### Language
- Default to English. (One older post is entirely in Polish — that's fine for Polish-audience content, but new posts are English unless there's a reason.)
- Keep the casual register; don't over-formalize into corporate/marketing tone.

## Non-post pages

`about.md`, `talks.md`, `links.md` are top-level pages with `layout: page` and explicit `permalink:` values. `talks.md` is updated frequently (recent commits are almost all talk-list edits) — keep its reverse-chronological grouping by event date.

## Plugins / themes

`Gemfile` only pulls `github-pages`, so only the [plugins whitelisted by GitHub Pages](https://pages.github.com/versions/) are available. Don't add gems that aren't on that list — the site will still build locally but fail on Pages. There is no theme gem; layouts/includes/CSS are all vendored under `_layouts/`, `_includes/`, `css/`.
