# xssurls

Passive recon tool that collects historical URLs for a domain (or list of
domains) from public archives and filters them down to the ones most likely
to be worth testing for reflected XSS.

It wraps three well-known tools into one pipeline:

- [`gau`](https://github.com/lc/gau) — pulls known URLs for a domain from the
  Wayback Machine, AlienVault OTX, Common Crawl and URLScan. This step is
  passive: it queries third-party archives and never sends requests to the
  target itself.
- [`gf`](https://github.com/tomnomnom/gf) (`xss` pattern) — keeps only URLs
  whose query parameters commonly lead to reflected XSS (`q`, `search`,
  `redirect`, `url`, `callback`, `return`, ...).
- [`uro`](https://github.com/s0md3v/uro) — removes duplicate/near-duplicate
  URLs so you aren't re-testing the same injection point over and over.

## Why

A rewrite of two earlier scripts (a bash one-liner and a Python batch
version) that did the same thing, combined into a single Go tool with a
real process pipeline, concurrent fetching for multiple domains, and basic
input validation.

## Install

Requires Go 1.21+, and `gau`, `gf` (with the `xss` pattern installed) and
`uro` on your `PATH`.

```sh
go build -o xssurls .
```

## Usage

```sh
./xssurls          # prompts interactively
./xssurls -t 10     # fetch up to 10 domains in parallel (default 5)
```

It asks whether you're checking one domain or multiple:

- **One domain** — type it directly (a bare domain or a full URL; the host
  is extracted automatically).
- **Multiple domains** — give the path to a file with one domain per line.
  Blank lines and `#` comments are skipped, duplicates are removed.

It then asks for an output file, runs `gau` on the domain(s), and writes the
`gf xss | uro` filtered result to `<output>_xss.txt`.

## Scope and authorization

This only collects and filters **already-public, archived** URLs — it does
not scan, fuzz, or send requests to the target's own infrastructure. Still,
use it only against domains you are authorized to test (your own assets, or
in-scope bug bounty / pentest targets), and don't assume a filtered URL is
actually vulnerable — verify by hand or with a dedicated scanner before
reporting anything.
