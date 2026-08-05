# data/

This directory holds the current snapshot of the dataset, regenerated daily by
`.github/workflows/update.yml` running `scripts/fetch.mjs`.

## Files

- `packages.json` — every package, as a JSON array.
- `packages.csv` — the same data as CSV (`vulnerabilityIds` and `riskFlags` are
  joined with `; `).
- `summary.json` — counts by ecosystem, how many packages carry known
  vulnerabilities, how many are flagged stale/deprecated, and run stats
  (`generatedAt`, `elapsedMs`).

## Schema

Every row, regardless of ecosystem, has this shape:

| Field | Type | Notes |
|---|---|---|
| `ecosystem` | string | `npm` or `pypi` |
| `name` | string | Package name as registered |
| `found` | boolean | `false` if the package could not be resolved on its registry at fetch time (rare — the candidate list comes from live registry/download data) |
| `latestVersion` | string \| null | Latest published version |
| `description` | string \| null | Short description from the registry |
| `license` | string \| null | Free-text license string as reported by the registry, not normalized to SPDX |
| `repositoryUrl` | string \| null | Source repository URL, when the registry publishes one |
| `weeklyDownloads` | number \| null | npm only, from `api.npmjs.org/downloads/point/last-week`. Always `null` for PyPI — its public JSON API has no download-count field |
| `publishedAt` | string \| null | ISO timestamp of the *latest* release (npm: `dist-tags.latest`'s entry in the `time` map; PyPI: most recent upload across all releases) |
| `deprecated` | boolean \| null | npm: `true` if `versions[latestVersion].deprecated` (or the package-level `deprecated` field) is a non-empty string. PyPI: whether the latest release is `yanked`. These are not the same concept — see Limitations in the top-level README |
| `deprecationReason` | string \| null | The verbatim deprecation message (npm) or yank reason (PyPI, when the registry provides one). `null` when `deprecated` is `false` |
| `vulnerabilityCount` | number \| null | Count of vulnerabilities OSV.dev reports as affecting *some* published version of this package. `null` (not `0`) if the OSV lookup itself failed |
| `vulnerabilities` | array | `{ id, severity }` objects. `id` is the OSV/GHSA/CVE-style identifier; `severity` is GitHub's human label (LOW/MODERATE/HIGH/CRITICAL) when available, else a raw CVSS vector string, else `null` |
| `riskFlags` | array of strings | Derived, mechanical flags — see below. Never a composite score |
| `maintainerCount` | number \| null | npm: size of the `maintainers` array. Always `null` for PyPI, which exposes only a single free-text maintainer field, not an account list |
| `scrapedAt` | string | ISO timestamp of this fetch |

## riskFlags — exact computation

Each flag is a mechanical check against fields already in the row. No flag is
a judgment call, a weighted score, or a guess. A package can carry any
combination of these, including none.

| Flag | Condition |
|---|---|
| `deprecated` | `deprecated === true` |
| `no-repository` | `repositoryUrl === null` |
| `has-known-vulns` | `vulnerabilityCount` is a number greater than 0 |
| `stale` | `publishedAt` is set and more than 2 years (730.5 days) before the fetch ran |
| `single-maintainer` | npm only: `maintainerCount === 1`. Never set for PyPI, since `maintainerCount` is always `null` there — there's no reliable signal to check |

There is deliberately no combined "risk score." Turning these mechanical
flags into a single number requires weighting judgments (is one CVE worse
than being 3 years stale?) that this dataset refuses to make on your behalf.
Combine the flags yourself according to what your own risk tolerance
actually is.

## Known gaps, by design

- **OSV.dev matches are package-level, not version-pinned.** A query with no
  version returns every vulnerability with an affected-range that includes
  at least one published version of the package — not necessarily
  `latestVersion`. Cross-reference the linked advisory if you need
  per-version precision.
- **PyPI `weeklyDownloads` and `maintainerCount` are always `null`.** Not a
  failed lookup — PyPI's public JSON API doesn't expose either signal.
- **License strings are not normalized to SPDX.** Passed through as reported
  (PyPI classifiers used as a fallback when the free-text field is empty).
- **The npm package set is not an authoritative top-N by downloads** — npm
  publishes no such public ranking. It's a curated "unambiguously major"
  seed list (`NPM_CORE_PACKAGES` in `scripts/fetch.mjs`) merged with a
  keyword-search sample, then ranked by each package's real
  `weeklyDownloads`. See "How packages were selected" in the top-level
  README for the exact method and why it exists (a first run using only
  keyword search silently omitted `lodash` and `request`).

See the top-level README for the full methodology, including how the
package lists themselves are built.
