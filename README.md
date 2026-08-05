# open-dependency-risk

A free, daily-updated dataset of 1,500 widely-used npm and PyPI packages,
selected by the method described below and ranked by weekly downloads, each
enriched with registry metadata and known vulnerabilities from
[OSV.dev](https://osv.dev).

Current snapshot: **PLACEHOLDER_TOTAL rows** (PLACEHOLDER_NPM npm,
PLACEHOLDER_PYPI PyPI); **PLACEHOLDER_VULN** carry at least one known
vulnerability; **PLACEHOLDER_DEP** are flagged deprecated (last full run:
PLACEHOLDER_DATE, ~PLACEHOLDER_TIME). Numbers move daily — see
`data/summary.json` for the current count.

Data lives in [`data/`](data/):

- [`data/packages.json`](data/packages.json) — every package, as JSON
- [`data/packages.csv`](data/packages.csv) — same data as CSV
- [`data/summary.json`](data/summary.json) — counts by ecosystem, run stats
- [`data/README.md`](data/README.md) — full schema doc, including exact
  `riskFlags` computation

A GitHub Actions workflow (`.github/workflows/update.yml`) re-runs the
fetcher every day and commits whatever changed. No manual updates.

## Why this exists

Checking whether a package is stale, deprecated, or has a known CVE means
either paying for a dependency-scanning platform or writing your own glue
code against three separate public APIs (npm registry, PyPI JSON API,
OSV.dev). This repo does that glue work once a day for the packages most
people actually depend on, and commits the result as plain JSON/CSV — no
account, no API key, no rate limit to manage yourself.

## Schema

| Field | Type | Notes |
|---|---|---|
| `ecosystem` | string | `npm` or `pypi` |
| `name` | string | Package name |
| `found` | boolean | `false` if the registry lookup failed at fetch time |
| `latestVersion` | string \| null | Latest published version |
| `description` | string \| null | Short description from the registry |
| `license` | string \| null | Free-text license string, not normalized to SPDX |
| `repositoryUrl` | string \| null | Source repository, when published |
| `weeklyDownloads` | number \| null | **npm only.** Always `null` for PyPI — its public JSON API has no download-count field |
| `publishedAt` | string \| null | ISO timestamp of the latest release |
| `deprecated` | boolean \| null | npm: `true` if the latest version (or the package as a whole) carries a `deprecated` message. PyPI: whether the release is `yanked` — not the same concept, see Limitations |
| `deprecationReason` | string \| null | The actual deprecation/yank message, when `deprecated` is `true`. `null` otherwise |
| `vulnerabilityCount` | number \| null | Known vulnerabilities from OSV.dev affecting some published version. `null` (not `0`) if the OSV lookup itself failed |
| `vulnerabilities` | array | `{ id, severity }` — OSV/GHSA/CVE id and severity label |
| `riskFlags` | array of strings | Mechanical signals only — see below |
| `maintainerCount` | number \| null | npm only; PyPI exposes no account list |
| `scrapedAt` | string | ISO timestamp of this fetch |

Full field-by-field documentation, including how every `riskFlags` value is
computed, is in [`data/README.md`](data/README.md).

### `riskFlags`

Five mechanical, defensible signals — no invented composite score:

- `stale` — no release in over 2 years
- `deprecated` — registry-reported deprecation/yank
- `has-known-vulns` — `vulnerabilityCount > 0`
- `no-repository` — no repository URL published
- `single-maintainer` — npm only, exactly one registered maintainer

This dataset does not compute a combined "risk score." Weighting a CVE
against staleness against maintainer count is a judgment call, and a made-up
number would be exactly the kind of confidently-wrong output this project
refuses to ship. Combine the flags yourself, weighted for what you actually
care about.

### Sample row (from the live run above)

```json
{
  "ecosystem": "npm",
  "name": "semver",
  "found": true,
  "latestVersion": "7.8.5",
  "description": "The semantic version parser used by npm.",
  "license": "ISC",
  "repositoryUrl": "https://github.com/npm/node-semver",
  "weeklyDownloads": 832884422,
  "publishedAt": "2026-06-19T18:32:48.972Z",
  "deprecated": false,
  "deprecationReason": null,
  "vulnerabilityCount": 2,
  "vulnerabilities": [
    { "id": "GHSA-c2qf-rxjj-qqgw", "severity": "HIGH" },
    { "id": "GHSA-x6fg-f45m-jf5q", "severity": "HIGH" }
  ],
  "riskFlags": ["has-known-vulns"],
  "maintainerCount": 3,
  "scrapedAt": "2026-08-04T04:55:42.966Z"
}
```

```json
{
  "ecosystem": "pypi",
  "name": "boto3",
  "found": true,
  "latestVersion": "1.43.63",
  "description": "The AWS SDK for Python",
  "license": "Apache-2.0",
  "repositoryUrl": "https://github.com/boto/boto3",
  "weeklyDownloads": null,
  "publishedAt": "2026-08-03T19:55:03.400422Z",
  "deprecated": false,
  "deprecationReason": null,
  "vulnerabilityCount": 0,
  "vulnerabilities": [],
  "riskFlags": [],
  "maintainerCount": null,
  "scrapedAt": "2026-08-04T04:55:44.012Z"
}
```

Note `weeklyDownloads` and `maintainerCount` are `null` for the PyPI row —
that's an ecosystem gap in PyPI's public API, not a failed lookup.

## Using the data

### curl

```bash
curl -s https://raw.githubusercontent.com/ConorsCode/open-dependency-risk/main/data/packages.json | jq '.[0]'
```

### pandas

```python
import pandas as pd
df = pd.read_json("https://raw.githubusercontent.com/ConorsCode/open-dependency-risk/main/data/packages.json")
df[df["riskFlags"].apply(lambda f: "has-known-vulns" in f)].sort_values("weeklyDownloads", ascending=False)
```

### JavaScript

```js
const packages = await fetch(
  "https://raw.githubusercontent.com/ConorsCode/open-dependency-risk/main/data/packages.json"
).then((r) => r.json());

const risky = packages.filter((p) => p.riskFlags.includes("has-known-vulns"));
console.log(`${risky.length} of ${packages.length} packages have a known vulnerability`);
```

## How packages were selected

npm publishes no public global download ranking — there is no endpoint,
official or unofficial, that returns "every npm package sorted by
downloads." Any dataset claiming to give you "the top N npm packages" by
downloads is, at best, approximating that ranking from something else. This
one is upfront about exactly what it approximates from and how:

- **npm** — the registry's public search endpoint
  (`registry.npmjs.org/-/v1/search`) supports ranking by popularity
  (`popularity=1.0&quality=0&maintenance=0`), but it requires a non-empty
  `text` query and ranks by relevance to that query, not by a global
  ranking — it is a keyword search with a popularity tiebreak, not a
  popularity list. `scripts/fetch.mjs` runs that search across ~30 short,
  generic terms (`a`, `the`, `js`, `react`, `http`, `test`, `sdk`, and
  about two dozen more) and unions the results. Because search-by-keyword
  can miss famous packages whose name doesn't match any query term well
  (this happened: `lodash` and `request` — both single, keyword-poor
  names — were absent from the first run), the candidate pool is also
  seeded with a hand-curated list of ~100 unambiguously major packages
  (`NPM_CORE_PACKAGES` in `scripts/fetch.mjs`) that no credible "widely
  used npm packages" list could omit — `lodash`, `request`, `react`,
  `express`, `axios`, `webpack`, `jest`, and similar. The curated names are
  guaranteed inclusion; the merged pool is then **ranked by each package's
  own actual `weeklyDownloads`**, fetched live from
  `api.npmjs.org/downloads/point/last-week` for every candidate, and the
  top 1,000 by that real download count make the final cut. The curation
  step decides *inclusion*, not *rank* — rank always comes from real
  download numbers, fetched after the fact.
- **PyPI** — PyPI's registry has no public search-by-popularity API at all.
  This repo uses
  [`hugovk/top-pypi-packages`](https://github.com/hugovk/top-pypi-packages),
  a daily-refreshed public JSON file
  (`https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json`)
  ranking PyPI packages by 30-day download count, sourced from the public
  PyPI download-stats BigQuery dataset. It's MIT licensed and widely used
  as a public reference list in the Python packaging community. This repo
  fetches it live on every run rather than vendoring a stale copy, and
  keeps that source's own download-based ordering — PyPI rows are not
  re-ranked by this repo.

Both lists are capped below the full ~1,000 npm / ~500 PyPI target so a
daily GitHub Actions run finishes in reasonable time — see
`scripts/fetch.mjs`'s `NPM_TARGET` / `PYPI_TARGET` constants for the exact
numbers currently in use.

**Bottom line: this is not an authoritative top-N-by-downloads list for
npm** — no such list can be built from public data, because npm doesn't
publish one. It's a documented approximation: a curated set of packages no
one would dispute belong, merged with a real (if imperfect) keyword-search
sample, ranked by real download counts. The PyPI list is closer to
authoritative, since its upstream source is itself download-ranked.

## Limitations (read before relying on this for anything important)

- **OSV.dev matches are package-level, not version-pinned.** A query with no
  version returns every vulnerability with an affected-range that includes
  at least one published version — not necessarily whatever version you
  actually have installed. Check the linked advisory for per-version detail.
- **PyPI has no download counts or maintainer list in this dataset.**
  `weeklyDownloads` and `maintainerCount` are always `null` for PyPI rows —
  its public JSON API doesn't expose either signal. This is a gap in what
  PyPI publishes, not something this repo failed to fetch.
- **`riskFlags` are mechanical, not judgments.** Each flag is a literal
  threshold check on fields already in the row (see `data/README.md` for
  the exact condition on every flag). None of them, alone or combined, is a
  claim about how risky a package actually is to use — that depends on your
  own exposure, and this dataset deliberately does not compute a single
  score pretending otherwise.
- **Snapshot timing.** Each row reflects the moment `scrapedAt` records — a
  new CVE or release can land minutes later. Don't treat a day-old row as
  current without checking the registry directly for anything that matters.
- **The npm package list is a documented approximation, not an
  authoritative top-N.** npm publishes no public global download ranking.
  The npm set is a curated "unambiguously major" seed list merged with a
  keyword-search sample, then ranked by real `weeklyDownloads` — see "How
  packages were selected" above. Don't cite this repo as "the top 1,000 npm
  packages"; cite it as what it is, a documented, downloads-ranked
  approximation.
- **License strings are not normalized to SPDX.** Passed through as
  reported by the registry.
- **`deprecated` means different things per ecosystem.** npm: the latest
  version (or the package as a whole) carries an explicit deprecation
  message, surfaced verbatim in `deprecationReason`. PyPI: whether the
  release was yanked — PyPI has no separate "deprecated" concept, so an
  unmaintained-but-not-yanked PyPI package will show `deprecated: false`,
  not `true`, even though it may be effectively abandoned.

## If you need this for an arbitrary package list, on demand

This repo's fetcher is deliberately narrow: a fixed, popularity-ranked
package list, refreshed once a day, via GitHub Actions. That's what keeps it
free and easy to audit.

If you want the same npm + PyPI + OSV enrichment run against **your own**
arbitrary list of package names — your `package.json` or
`requirements.txt`, a candidate list you're evaluating, whatever — on
demand, with no daily-cron limitation, that's a separate, paid tool: the
[Package Intel Scraper on Apify](https://apify.com/studious_allergy_mig/package-intel-scraper).
It's pay-per-result (one result = one package looked up) and adds a
cross-ecosystem name-ambiguity check this free dataset doesn't need (a
fixed popularity list has no ambiguous user input to resolve).

This repo and that actor share no code — the actor is a TypeScript project
with input validation and test coverage; this repo is a single
dependency-free Node script meant to be read in one sitting.

## License

MIT — see [`LICENSE`](LICENSE). The code is MIT licensed; the package
metadata and vulnerability data themselves are republished from each
registry's own public API and from OSV.dev, and belong to their respective
sources.

## Related open datasets

Part of a small set of free, daily-refreshed datasets built the same way:
zero-dependency Node fetcher, GitHub Actions refresh, public endpoints only.

- **[Open Jobs Data](https://github.com/ConorsCode/open-jobs-data)** — 15,919 open job postings from 90 companies across nine applicant tracking systems.
- **[Open FedSpend Data](https://github.com/ConorsCode/open-fedspend-data)** — 28,092 recent US federal contract awards from USAspending.gov, with recipient and agency aggregates.
