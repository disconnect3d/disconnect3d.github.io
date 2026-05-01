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
- Required front matter: `layout: post`, `title`, `date` (with timezone-aware time, site timezone is `Europe/Warsaw` per `_config.yml`), and `tags` (comma-separated string, not a YAML list — match existing posts).
- The post layout (`_layouts/post.html`) embeds Utterances comments keyed by `pathname`, scoped to the `disconnect3d/disconnect3d.github.io` repo's issues. Renaming or moving a published post breaks its existing comment thread.
- Permalinks use `permalink: pretty` (`/YYYY/MM/DD/slug/`), so the URL is derived from filename + date — changing either after publish breaks inbound links.

## Non-post pages

`about.md`, `talks.md`, `links.md` are top-level pages with `layout: page` and explicit `permalink:` values. `talks.md` is updated frequently (recent commits are almost all talk-list edits) — keep its reverse-chronological grouping by event date.

## Plugins / themes

`Gemfile` only pulls `github-pages`, so only the [plugins whitelisted by GitHub Pages](https://pages.github.com/versions/) are available. Don't add gems that aren't on that list — the site will still build locally but fail on Pages. There is no theme gem; layouts/includes/CSS are all vendored under `_layouts/`, `_includes/`, `css/`.
