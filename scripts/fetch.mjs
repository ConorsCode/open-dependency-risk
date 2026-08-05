#!/usr/bin/env node
// Standalone, zero-dependency fetcher for the open-dependency-risk dataset.
//
// Builds a popularity-ranked list of npm and PyPI packages, then enriches each
// one with registry metadata (npm registry / PyPI JSON API) and known
// vulnerabilities (OSV.dev). Writes data/packages.json, data/packages.csv,
// and data/summary.json.
//
// Zero npm dependencies — uses Node's built-in fetch. Bounded concurrency,
// retry with backoff, and per-package error isolation so one bad package or
// one flaky request never kills the run.

import { writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// How many packages to pull per ecosystem. Kept below the spec's "~1000 npm /
// ~500 PyPI" ceiling so a full run (list-building + per-package metadata +
// OSV lookups, several thousand HTTP calls total) completes in well under 30
// minutes against public, rate-limited endpoints. Bump these if you have more
// time budget.
const NPM_TARGET = 1000;
const PYPI_TARGET = 500;

const CONCURRENCY = 10;
const REQUEST_DELAY_MS = 80;
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 600;
const FETCH_TIMEOUT_MS = 20000;
const USER_AGENT = 'open-dependency-risk/1.0 (+https://github.com/) polite-bot';
const STALE_YEARS = 2;

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(url, options = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json', ...(options.headers || {}) },
      });
      if (res.status === 404) {
        clearTimeout(timeout);
        return { notFound: true, status: res.status };
      }
      if (res.status === 429 || res.status >= 500) {
        const retryAfter = Number(res.headers.get('retry-after'));
        throw new Error(`HTTP ${res.status}${retryAfter ? ` retry-after=${retryAfter}` : ''}`);
      }
      if (!res.ok) {
        clearTimeout(timeout);
        return { notFound: true, status: res.status };
      }
      // Read the body BEFORE clearing the abort timer. Clearing it as soon as
      // headers arrive leaves the body read with no timeout and a disarmed
      // controller, so a server that sends headers and then stalls mid-body
      // hangs this call forever — no error, no retry, no progress. That cost
      // a 19-hour silent stall on 2026-08-03.
      const text = await res.text();
      clearTimeout(timeout);
      return { text };
    } catch (err) {
      clearTimeout(timeout);
      lastErr = err;
      if (attempt < MAX_RETRIES) {
        const backoff = RETRY_BASE_MS * 2 ** attempt + Math.random() * 300;
        await sleep(backoff);
        continue;
      }
    }
  }
  throw lastErr ?? new Error('fetch failed');
}

async function getJson(url) {
  const { text, notFound, status } = await fetchWithRetry(url);
  if (notFound) return { notFound: true, status };
  try {
    return { data: JSON.parse(text) };
  } catch {
    return { notFound: true, status: 'bad-json' };
  }
}

async function postJson(url, body) {
  const { text, notFound, status } = await fetchWithRetry(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (notFound) return { notFound: true, status };
  try {
    return { data: JSON.parse(text) };
  } catch {
    return { notFound: true, status: 'bad-json' };
  }
}

function nowIso() {
  return new Date().toISOString();
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
      done++;
      if (done % 100 === 0 || done === items.length) {
        console.log(`  ...${done}/${items.length}`);
      }
      await sleep(REQUEST_DELAY_MS);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------------------
// Step 1: build popularity-ranked package name lists
// ---------------------------------------------------------------------------

// npm's registry search endpoint (`registry.npmjs.org/-/v1/search`) requires
// a non-empty `text` query — there is no "give me everything sorted by
// downloads" mode. So we run it with `popularity=1.0&quality=0&maintenance=0`
// (rank almost entirely by popularity) across a broad set of short, generic
// query terms, union the results, and re-rank the union by each package's
// own reported weekly download count. This is an approximation of "top npm
// packages by downloads," not an authoritative registry-wide ranking — see
// data/README.md for the exact methodology.
const NPM_SEARCH_TERMS = [
  'a', 'the', 'is', 'js', 'ts', 'to', 'of', 'in', 'for', 'and',
  'react', 'node', 'cli', 'api', 'util', 'test', 'http', 'json', 'css', 'core',
  'aws', 'sdk', 'log', 'lib', 'app', 'dom', 'sql', 'data', 'build', 'plugin',
];

// npm's search endpoint ranks by keyword match against `text`, not by a
// global popularity ranking — there is no such ranking published anywhere,
// by npm or anyone else. Running it across generic terms (above) misses
// famous packages whose name/description just doesn't happen to match any
// of those terms well (lodash and request are the two that got caught: both
// are one-word, keyword-poor package names). To avoid silently dropping
// packages that no credible "widely used npm packages" list would omit, we
// seed the candidate pool with a hand-curated set of unambiguously major
// packages and merge it with the search-derived pool before ranking by each
// package's own weekly download count. This list is a judgment call, not a
// ranking — see data/README.md for exactly how it's used.
const NPM_CORE_PACKAGES = [
  'lodash', 'request', 'react', 'react-dom', 'express', 'axios', 'chalk',
  'commander', 'debug', 'typescript', 'webpack', 'jest', 'vue', 'next',
  'moment', 'uuid', 'dotenv', 'eslint', 'prettier', 'babel-core',
  '@babel/core', 'mocha', 'jquery', 'underscore', 'async', 'bluebird',
  'rxjs', 'redux', 'react-redux', 'vuex', 'angular', '@angular/core',
  'socket.io', 'ws', 'body-parser', 'cors', 'morgan', 'helmet',
  'passport', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'nodemon', 'pm2',
  'winston', 'pino', 'yargs', 'inquirer', 'minimist', 'fs-extra',
  'glob', 'rimraf', 'mkdirp', 'chokidar', 'semver', 'chai', 'sinon',
  'nock', 'supertest', 'cypress', 'puppeteer', 'playwright', 'nyc',
  'istanbul', 'tslint', 'node-sass', 'sass', 'less', 'postcss',
  'autoprefixer', 'tailwindcss', 'bootstrap', 'vite', 'rollup',
  'parcel', 'gulp', 'grunt', 'browserify', 'core-js', 'regenerator-runtime',
  'classnames', 'prop-types', 'styled-components', 'emotion',
  'graphql', 'apollo-server', 'mongoose', 'sequelize', 'knex', 'pg',
  'mysql', 'mysql2', 'redis', 'ioredis', 'aws-sdk', 'firebase',
  'stripe', 'nodemailer', 'multer', 'sharp', 'formidable', 'axios-retry',
  'node-fetch', 'cross-fetch', 'form-data', 'qs', 'query-string',
  'date-fns', 'dayjs', 'validator', 'joi', 'zod', 'yup', 'ajv',
];

async function buildNpmCandidateList(target) {
  console.log(`Building npm candidate list from ${NPM_SEARCH_TERMS.length} search terms + ${NPM_CORE_PACKAGES.length} curated core packages...`);
  const seen = new Map(); // name -> weekly downloads (0 = not yet known, filled in during enrichment)
  for (const name of NPM_CORE_PACKAGES) {
    seen.set(name, 0);
  }
  for (const term of NPM_SEARCH_TERMS) {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(term)}&size=250&popularity=1.0&quality=0&maintenance=0`;
    try {
      const { data, notFound } = await getJson(url);
      if (notFound || !data?.objects) continue;
      for (const o of data.objects) {
        const name = o.package?.name;
        const weekly = o.downloads?.weekly ?? 0;
        if (!name) continue;
        if (!seen.has(name) || seen.get(name) < weekly) seen.set(name, weekly);
      }
    } catch (err) {
      console.log(`  search term "${term}" failed: ${err.message}`);
    }
    await sleep(REQUEST_DELAY_MS * 2);
  }
  // Curated names always make the cut; search-derived names beyond that are
  // capped by target. Actual ranking (including the curated names, whose
  // weekly downloads aren't known yet) happens after enrichment, by real
  // weeklyDownloads — see main().
  const curated = NPM_CORE_PACKAGES.filter((n) => seen.has(n));
  const searchDerived = [...seen.entries()]
    .filter(([name]) => !NPM_CORE_PACKAGES.includes(name))
    .sort((a, b) => b[1] - a[1])
    .map(([name]) => name);
  const merged = [...new Set([...curated, ...searchDerived])].slice(0, target);
  console.log(`  npm candidate pool: ${seen.size} unique names (${curated.length} curated), taking ${merged.length}`);
  return merged;
}

// PyPI has no equivalent public search-by-popularity API. hugovk/top-pypi-packages
// (https://github.com/hugovk/top-pypi-packages) publishes a daily-refreshed JSON
// of the top PyPI packages by 30-day download count, sourced from the public
// PyPI download-stats BigQuery dataset. It's a well-known, widely used public
// artifact in the Python packaging community (used by pip, packaging tooling
// docs, etc.) — MIT licensed. We fetch it live rather than vendoring a copy.
const PYPI_TOP_URL = 'https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json';

async function buildPypiCandidateList(target) {
  console.log('Fetching PyPI top-packages list from hugovk/top-pypi-packages...');
  // Routed through getJson so this call gets the same abort-timeout and retry
  // protection as every other request — a bare fetch here could stall forever.
  const { data, notFound } = await getJson(PYPI_TOP_URL);
  if (notFound || !data) throw new Error('Failed to fetch PyPI top-packages list');
  const rows = data.rows ?? [];
  console.log(`  source last_update=${data.last_update}, ${rows.length} rows available, taking top ${target}`);
  return rows.slice(0, target).map((r) => r.project);
}

// ---------------------------------------------------------------------------
// Step 2: per-package enrichment
// ---------------------------------------------------------------------------

function licenseToString(license) {
  if (!license) return null;
  if (typeof license === 'string') return license;
  return license.type ?? null;
}

function repoToUrl(repo) {
  if (!repo) return null;
  const raw = typeof repo === 'string' ? repo : repo.url;
  if (!raw) return null;
  return raw
    .replace(/^git\+/, '')
    .replace(/\.git$/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^git@github\.com:/, 'https://github.com/');
}

async function fetchNpmPackage(name) {
  const { data: packument, notFound } = await getJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (notFound || !packument) return null;

  const latestTag = packument['dist-tags']?.latest ?? null;
  const versions = packument.versions ?? {};
  const latestMeta = latestTag ? versions[latestTag] : undefined;
  const time = packument.time ?? {};

  let weeklyDownloads = null;
  try {
    const { data: dl } = await getJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
    weeklyDownloads = typeof dl?.downloads === 'number' ? dl.downloads : null;
  } catch {
    weeklyDownloads = null;
  }

  // `deprecated` lives on the individual VERSION object in the packument
  // (`versions[latestTag].deprecated`), as a human-readable message string
  // when set, absent/undefined otherwise. A minority of packages also carry
  // a package-level `deprecated` field. Either counts: any non-empty string
  // means deprecated, and we keep the message for the record.
  const versionDeprecation = typeof latestMeta?.deprecated === 'string' ? latestMeta.deprecated : null;
  const packageDeprecation = typeof packument.deprecated === 'string' ? packument.deprecated : null;
  const deprecationReason = versionDeprecation || packageDeprecation || null;

  return {
    ecosystem: 'npm',
    name: packument.name ?? name,
    latestVersion: latestTag,
    description: latestMeta?.description ?? packument.description ?? null,
    license: licenseToString(latestMeta?.license ?? packument.license ?? null),
    repositoryUrl: repoToUrl(latestMeta?.repository ?? packument.repository),
    weeklyDownloads,
    publishedAt: latestTag ? (time[latestTag] ?? null) : null,
    deprecated: deprecationReason !== null,
    deprecationReason,
    maintainerCount: Array.isArray(packument.maintainers) ? packument.maintainers.length : null,
  };
}

function licenseFromPypiInfo(info) {
  if (info.license_expression) return info.license_expression;
  if (info.license && info.license.trim() && info.license.trim().toLowerCase() !== 'unknown') {
    return info.license.trim();
  }
  const classifierLicense = (info.classifiers ?? []).find((c) => c.startsWith('License ::'));
  if (classifierLicense) {
    const parts = classifierLicense.split('::').map((p) => p.trim());
    return parts[parts.length - 1] ?? null;
  }
  return null;
}

function repositoryFromPypiInfo(info) {
  const urls = info.project_urls ?? {};
  for (const [key, value] of Object.entries(urls)) {
    if (/source|repository|code|github|gitlab/i.test(key) && value) return value;
  }
  if (info.home_page && /github\.com|gitlab\.com|bitbucket\.org/i.test(info.home_page)) return info.home_page;
  return null;
}

async function fetchPypiPackage(name) {
  const { data, notFound } = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (notFound || !data) return null;
  const info = data.info ?? {};

  const versionEntries = Object.entries(data.releases ?? {}).filter(([, files]) => files.length > 0);
  let lastPublishAt = null;
  const releaseTimes = versionEntries
    .map(([version, files]) => ({ version, time: files[0]?.upload_time_iso_8601 ?? files[0]?.upload_time ?? null }))
    .filter((r) => r.time !== null)
    .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());
  if (releaseTimes.length > 0) {
    lastPublishAt = releaseTimes[releaseTimes.length - 1].time;
  } else if (data.urls?.[0]) {
    lastPublishAt = data.urls[0].upload_time_iso_8601 ?? data.urls[0].upload_time ?? null;
  }

  return {
    ecosystem: 'pypi',
    name: info.name ?? name,
    latestVersion: info.version ?? null,
    description: info.summary || null,
    license: licenseFromPypiInfo(info),
    repositoryUrl: repositoryFromPypiInfo(info),
    weeklyDownloads: null, // PyPI's JSON API exposes no download-count field
    publishedAt: lastPublishAt,
    // PyPI has no "deprecated" concept — only per-release "yanked", which
    // means "don't install this specific version," not "this package is
    // deprecated." We surface it under the same field for a uniform schema,
    // but see data/README.md/Limitations: it is not the same concept as npm's.
    deprecated: info.yanked === true,
    deprecationReason: info.yanked === true ? (info.yanked_reason || null) : null,
    maintainerCount: null, // PyPI exposes only a free-text maintainer field, not an account list
  };
}

const OSV_ECOSYSTEM = { npm: 'npm', pypi: 'PyPI' };

function severityFromVuln(vuln) {
  if (vuln.database_specific?.severity) return vuln.database_specific.severity;
  const cvss = vuln.severity?.find((s) => s.type === 'CVSS_V3' || s.type === 'CVSS_V4');
  return cvss?.score ?? null;
}

async function fetchVulnerabilities(name, ecosystem) {
  const body = { package: { name, ecosystem: OSV_ECOSYSTEM[ecosystem] } };
  const { data, notFound } = await postJson('https://api.osv.dev/v1/query', body);
  if (notFound || !data) return [];
  return (data.vulns ?? []).map((v) => ({
    id: v.id,
    severity: severityFromVuln(v),
  }));
}

function computeRiskFlags(row) {
  const flags = [];
  if (row.deprecated) flags.push('deprecated');
  if (row.repositoryUrl === null) flags.push('no-repository');
  if (typeof row.vulnerabilityCount === 'number' && row.vulnerabilityCount > 0) flags.push('has-known-vulns');
  if (row.publishedAt) {
    const ageMs = Date.now() - new Date(row.publishedAt).getTime();
    if (ageMs > STALE_YEARS * 365.25 * 24 * 60 * 60 * 1000) flags.push('stale');
  }
  if (row.ecosystem === 'npm' && row.maintainerCount === 1) flags.push('single-maintainer');
  return flags;
}

async function enrichPackage(name, ecosystem) {
  const base = {
    ecosystem,
    name,
    found: false,
    latestVersion: null,
    description: null,
    license: null,
    repositoryUrl: null,
    weeklyDownloads: ecosystem === 'pypi' ? null : null,
    publishedAt: null,
    deprecated: null,
    deprecationReason: null,
    vulnerabilityCount: null,
    vulnerabilities: [],
    riskFlags: [],
    scrapedAt: nowIso(),
  };

  try {
    const meta = ecosystem === 'npm' ? await fetchNpmPackage(name) : await fetchPypiPackage(name);
    if (!meta) {
      return { ...base, error: 'not-found' };
    }
    Object.assign(base, meta, { found: true });
  } catch (err) {
    return { ...base, error: `metadata fetch failed: ${err.message}` };
  }

  try {
    const vulns = await fetchVulnerabilities(base.name, ecosystem);
    base.vulnerabilityCount = vulns.length;
    base.vulnerabilities = vulns;
  } catch (err) {
    base.vulnerabilityCount = null; // genuinely unknown, distinct from "checked, found 0"
    base.osvError = `OSV lookup failed: ${err.message}`;
  }

  base.riskFlags = computeRiskFlags(base);
  base.scrapedAt = nowIso();
  return base;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function toCsv(rows) {
  const headers = [
    'ecosystem', 'name', 'found', 'latestVersion', 'description', 'license',
    'repositoryUrl', 'weeklyDownloads', 'publishedAt', 'deprecated', 'deprecationReason',
    'vulnerabilityCount', 'vulnerabilityIds', 'riskFlags', 'scrapedAt',
  ];
  const escape = (v) => {
    if (v === null || v === undefined) return '';
    const s = String(v);
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [headers.join(',')];
  for (const row of rows) {
    const vulnerabilityIds = (row.vulnerabilities ?? []).map((v) => v.id).join('; ');
    const riskFlags = (row.riskFlags ?? []).join('; ');
    const record = { ...row, vulnerabilityIds, riskFlags };
    lines.push(headers.map((h) => escape(record[h])).join(','));
  }
  return lines.join('\n') + '\n';
}

async function main() {
  const startedAt = Date.now();

  const [npmNames, pypiNames] = await Promise.all([
    buildNpmCandidateList(NPM_TARGET),
    buildPypiCandidateList(PYPI_TARGET),
  ]);

  const requests = [
    ...npmNames.map((name) => ({ name, ecosystem: 'npm' })),
    ...pypiNames.map((name) => ({ name, ecosystem: 'pypi' })),
  ];

  console.log(`Enriching ${requests.length} packages (${npmNames.length} npm, ${pypiNames.length} pypi)...`);

  let rows = await mapWithConcurrency(requests, CONCURRENCY, (req) => enrichPackage(req.name, req.ecosystem));

  // Final ranking: npm rows by their actual weeklyDownloads (now that we've
  // fetched it for every package, including the curated seeds whose rank
  // wasn't known up front); PyPI rows preserve hugovk/top-pypi-packages'
  // own 30-day-download ordering, since that source is already a real
  // downloads-based ranking and this dataset doesn't refetch download
  // counts for PyPI. npm rows sort first (by download count, nulls last),
  // then PyPI rows follow in their source order.
  const npmRows = rows.filter((r) => r.ecosystem === 'npm')
    .sort((a, b) => (b.weeklyDownloads ?? -1) - (a.weeklyDownloads ?? -1));
  const pypiRows = rows.filter((r) => r.ecosystem === 'pypi');
  rows = [...npmRows, ...pypiRows];

  const elapsedMs = Date.now() - startedAt;

  await mkdir(path.join(ROOT, 'data'), { recursive: true });
  await writeFile(path.join(ROOT, 'data', 'packages.json'), JSON.stringify(rows, null, 2) + '\n');
  await writeFile(path.join(ROOT, 'data', 'packages.csv'), toCsv(rows));

  const byEcosystem = {};
  const withVulns = {};
  const stale = {};
  const deprecated = {};
  for (const row of rows) {
    byEcosystem[row.ecosystem] = (byEcosystem[row.ecosystem] ?? 0) + 1;
    if ((row.vulnerabilityCount ?? 0) > 0) withVulns[row.ecosystem] = (withVulns[row.ecosystem] ?? 0) + 1;
    if (row.riskFlags?.includes('stale')) stale[row.ecosystem] = (stale[row.ecosystem] ?? 0) + 1;
    if (row.deprecated) deprecated[row.ecosystem] = (deprecated[row.ecosystem] ?? 0) + 1;
  }

  const notFound = rows.filter((r) => !r.found).length;

  const summary = {
    generatedAt: nowIso(),
    total: rows.length,
    byEcosystem,
    withKnownVulnerabilities: withVulns,
    staleFlagged: stale,
    deprecatedFlagged: deprecated,
    notFound,
    elapsedMs,
  };
  await writeFile(path.join(ROOT, 'data', 'summary.json'), JSON.stringify(summary, null, 2) + '\n');

  console.log(`Done in ${(elapsedMs / 1000).toFixed(1)}s. Total rows: ${rows.length}`);
  console.log('By ecosystem:', byEcosystem);
  console.log('With known vulnerabilities:', withVulns);
  console.log('Not found:', notFound);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
