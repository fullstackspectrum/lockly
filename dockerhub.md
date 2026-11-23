# Lockly

**What changed in the lockfile, and why it matters.**

Lockly compares two versions of a lockfile and flags the changes a reviewer should stop for: new install scripts, a release by an account new to the package, lost provenance, fresh releases, changed contents or sources, known vulnerabilities and licence changes. It reads npm, Yarn, pnpm, uv, Poetry, Pipenv, Go and Cargo lockfiles.

Source, docs and issues: https://github.com/fullstackspectrum/lockly

## Usage

The image has no git, so it compares two lockfile files. For `--base` (every lockfile changed on a branch), use `pip install lockly`, Homebrew or the GitHub Action.

```bash
docker run --rm -t -v "$PWD:/data" fullstackspectrum/lockly diff old/package-lock.json package-lock.json
docker run --rm -t -v "$PWD:/data" fullstackspectrum/lockly diff old/uv.lock uv.lock --html report.html
```

The `-t` flag gives you colour in the terminal. Drop it in CI logs.

## Tags

| Tag | Points to |
| --- | --- |
| `latest` | The newest stable release |
| `X` (e.g. `0`) | The newest release in that major series |
| `X.Y` (e.g. `0.1`) | The newest patch release in that minor series |
| `X.Y.Z` (e.g. `0.1.0`) | One exact release |

Every tag is built for `linux/amd64` and `linux/arm64`.

## Image

Built on Docker Hardened Images' Python 3.14 Alpine runtime: no shell, no package manager, and it runs as the non-root user 65532.
