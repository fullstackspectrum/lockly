# Changelog

## 0.1.0 (2026-11-24)

First release.

- `lockly diff OLD NEW` compares two lockfiles; `lockly diff --base REF` compares every lockfile changed since REF's merge base, in the working tree or at `--head`.
- Reads npm (`package-lock.json` v1–v3), Yarn classic and Berry, pnpm 5.4–9, uv, Poetry, Pipenv, Go modules (`go.mod` with `go.sum`) and Cargo lockfiles, telling direct from transitive dependencies where the lockfile or its manifest says.
- Flags same-version hash changes, new install scripts, sources other than the registry, licence changes and new copyleft terms from the lockfiles alone.
- Looks up the changed packages in the npm registry, PyPI, crates.io, the Go module proxy and OSV, to flag releases by an account new to the package or no longer through trusted publishing, lost provenance, fresh releases and packages, deprecations and yanks, and known vulnerabilities, and to credit the vulnerabilities an upgrade fixes. `--offline` skips the lookups.
- Output: terminal, Markdown for a pull request comment (kept under GitHub's size limit), JSON, and a self-contained offline HTML report.
- `--fail-on` turns any finding type into a CI gate, and a composite GitHub Action posts the review as one pull request comment that updates in place.
