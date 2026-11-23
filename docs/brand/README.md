# Lockly brand assets

Lockly follows the [Full-Stack-Spectrum](https://fullstackspectrum.com) design system.

- `lockly-icon.svg`: the mark on a 64×64 `#0a0d12` tile (radius 14), for avatars and app icons. The HTML report inlines it as its tab icon (`_FAVICON_SVG` in `lockly/html.py`) and draws the tile-less mark in its header (`lockly/assets/report.html`); keep all three in sync.
- `lockly-mark.svg`: the mark alone, for dark grounds only (its layers are filled `#0a0d12`).
- `readme-banner.png`: 2560×640, shown at 1280×320 at the top of the README.
- `github-social-preview.png`: 1280×640, uploaded under the repository's Settings → Social preview.
- `src/brand.html` and `src/render.sh`: the source for both PNGs. Edit the HTML, then run `./docs/brand/src/render.sh` (needs Google Chrome).

The mark is Layered Core with the red core replaced by a padlock: a shackle over a body, a 3-unit `#ff4d5e` stroke with round caps and joins, matching GitPulse's pulse, Sbomly's ± and Basely's chevron.

In the banner's lockfile diff, upgrades take blue-soft, additions blue, removals the faint text colour, and the change worth a look (a new install script) the red marker and node.

The wordmark is written Lockly in prose and headings, and `lockly` in mono contexts (the command, eyebrows).
