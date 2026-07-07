# GEO Audit Report: cs-routeros-bouncer

**Audit Date:** 2026-07-07
**URL:** <https://jmrplens.github.io/cs-routeros-bouncer/>
**Business Type:** Open-source software documentation (Astro + Starlight, GitHub Pages). Free/MIT-licensed — no pricing, no login, no commercial funnel. Closest audit template: SaaS documentation, adapted for an OSS project.
**Pages Analyzed:** 54 sitemap URLs (27 English + 27 Spanish, all HTTP 200); ~18 pages deep-fetched across five parallel analysis passes.
**Previous Audit:** 2026-07-02 — 62/100 (before the GEO fix-list of PR #60/#61 and the Spanish locale of PR #63).

---

## Executive Summary

### Overall GEO Score: 72/100 (Fair, borderline Good) — up from 62 (+10)

On-site GEO is now essentially done: technical infrastructure scores 96/100 (fully static HTML, 14 AI crawlers explicitly welcomed, Content-Signal, compliant `llms.txt`, reciprocal en↔es hreflang), the July 2 critical issue (site-wide phantom `FAQPage`) is fixed — the FAQ block now matches visible content verbatim in both languages — and there is direct evidence that AI search summaries **already quote the docs nearly verbatim** (the "~1–3 ms per operation" figure and pool-size defaults were reproduced in AI answers during this audit). The new Spanish tree doubles the citable surface and none of the competing MikroTik bouncers have localized docs.

What holds the score at 72 is almost entirely **off-site brand authority (32/100)**: zero community footprint (no Reddit, no forum.mikrotik.com, no CrowdSec Discourse threads), absence from the `awesome-crowdsec` directory while a direct competitor is listed, and a young repo (12 stars, Feb 2026). Second-order gaps: the author remains invisible in rendered content (rich `Person` JSON-LD, but no byline/About page), and the entry pages (quickstart/installation) are the least citation-shaped pages on the site.

### Score Breakdown

| Category | Score | Prev | Δ | Weight | Weighted Score |
|---|---|---|---|---|---|
| AI Citability | 87/100 | 82 | +5 | 25% | 21.75 |
| Brand Authority | 32/100 | 30 | +2 | 20% | 6.40 |
| Content E-E-A-T | 70/100 | 57 | +13 | 20% | 14.00 |
| Technical GEO | 96/100 | 89 | +7 | 15% | 14.40 |
| Schema & Structured Data | 84/100 | 43 | +41 | 10% | 8.40 |
| Platform Optimization | 74/100 | 60 | +14 | 10% | 7.40 |
| **Overall GEO Score** | | | | | **72.35 ≈ 72/100** |

---

## Critical Issues (Fix Immediately)

None. The July 2 critical issue (site-wide `FAQPage` matching zero visible content) is resolved: the block now exists only where the FAQ is visible, matches word-for-word, and is properly localized on `/es/`.

---

## High Priority Issues

**1. Not listed in `awesome-crowdsec` while direct competitor `cs-mikrotik-bouncer-alt` is.**
Verified against the raw directory README. Curated "awesome" lists feed LLM training data and RAG corpora directly; this is the cheapest high-leverage authority action available.
**Fix:** submit a PR adding cs-routeros-bouncer with a one-line description.

**2. Zero community footprint on the venues AI models weight most for this niche.**
No threads mention the project on forum.mikrotik.com (existing CrowdSec threads t=187449/t=189948 reference competitor scripts), r/mikrotik, r/crowdsec, or discourse.crowdsec.net. Perplexity answering "best CrowdSec bouncer for MikroTik" today draws on competitor sources. Reddit is empty for all competitors too — a first-mover opportunity.
**Fix:** one substantive announcement on discourse.crowdsec.net; genuine participation in the existing MikroTik-forum CrowdSec threads; an r/mikrotik write-up. (Human action — cannot be automated honestly.)

**3. Author invisible in rendered content.**
`Person` JSON-LD with 6 `sameAs` links and 7 `rel=me` head links exist site-wide, but no byline, no "maintained by" footer credit, no About page. "Requena", "jmrp.io", and "LinkedIn" appear nowhere in visible body text. AI systems reading rendered text (and human trust) miss the strongest expertise signal the site has.
**Fix:** add "Maintained by [José Manuel Requena Plens](https://jmrp.io)" to the custom footer (both locales) and/or an About/Credits page.

**4. `WebSite.inLanguage` still `["en"]` on the live site.** ✅ *Fixed locally during this audit — pending commit/deploy.*
The `/es/` pages serve the English-only site-wide graph while their `TechArticle` declares `"es"` — an entity-graph contradiction that dilutes the bilingual signal for Gemini/AIO. The one-line fix (`["en", "es"]`) is applied in `docs/astro.config.mjs` and ships with the next deploy.

---

## Medium Priority Issues

1. **Quickstart & Installation are the least citable pages** (68 and 65 vs 82–90 elsewhere): no direct-answer intro paragraph, no question-form headings, no prerequisites block at the top, fragment-style headings ("Basic setup"). Fix: add a 40–60-word definition-first lead per page, a visible Requirements block on quickstart, and convert 2–3 key headings to question form.
2. **`TechArticle` missing `image` and `datePublished`** — `image` disqualifies Article rich results; both are cheap to add in the Head override (og-image.png exists; derive `datePublished` from first git commit like `dateModified`).
3. **No tested-versions/hardware matrix** — "RouterOS 7.x" is the only compatibility claim outside the benchmarking page. A "Tested with" table (RouterOS versions, hardware, CrowdSec versions, date) is a cheap, high-value Experience signal.
4. **Outbound citations are thin** — most pages link only the boilerplate footer set. Add deep links to docs.crowdsec.net (LAPI/CAPI/bouncer registration) on config pages and RouterOS filter/raw docs on firewall/architecture pages.
5. **Wikidata Q140393352 is minimal** — 8 claims, no external identifiers, no sitelinks. Enrich (depends-on CrowdSec, keep P348 version current, add identifiers); bot credentials exist from prior GEO work.
6. **Short meta descriptions on key pages** (quickstart: 45 chars). Expand to ~120–155 chars including the problem solved — these seed AI snippets.
7. **Vague qualifiers weaken stat density** — "defaults work well for most setups", "~97× faster" without a methodology anchor. Quantify or link each to the benchmarking page.
8. **No Google-ecosystem content** (weakest platform: Gemini 55/100). A single 3–5-min YouTube setup walkthrough linked from quickstart covers the biggest gap.
9. **No third-party coverage** — pitch the CrowdSec blog (they feature community bouncers); the CfgMgmtCamp 2026 Ghent talk "Crowdsec and Mikrotik integration" is worth investigating as a mention vehicle.

---

## Low Priority Issues

1. CSP includes `'unsafe-eval'` alongside `'wasm-unsafe-eval'`; if Pagefind only needs WASM, drop the former (test search after).
2. Sitemap hreflang blocks omit `x-default` (present in HTML heads); add for consistency.
3. Missing `twitter:title`/`twitter:description` and `og:image:width/height/alt` (falls back to og:, cosmetic).
4. `FAQPage` block not linked into the entity graph (`@id`, `inLanguage`, `isPartOf`).
5. `SoftwareApplication.screenshot` duplicates og-image — point at a real screenshot (Grafana dashboard PNG exists); add `softwareHelp` (docs URL) and `softwareRequirements` ("CrowdSec 1.5+ (LAPI), RouterOS 7.x with API enabled").
6. `Person` missing `jobTitle`/`worksFor`/`description`.
7. `llms-full.txt` is a curated config reference (9 KB), not the full flattened corpus the emerging convention implies (provenance note mitigates; optionally generate a true dump).
8. Benchmark "Example output" is illustrative, not a captured run; no screenshots site-wide (WinBox/terminal captures with alt text would help router-setup/troubleshooting).
9. No Docker Hub listing (GHCR only) — Docker Hub search is itself an AI-cited discovery surface.
10. IndexNow acceptance only visible in CI logs as non-fatal warnings; surface the HTTP response as a job-summary annotation so silent key-mismatch regressions are noticed.
11. github.io project path caps domain authority; a custom domain (e.g. `routeros-bouncer.jmrp.io`) would tie the docs to the established author entity (weigh against losing accumulated signals).
12. `APIReference` (TechArticle subtype) would type `/configuration/` reference pages more precisely; consider a small `Dataset` node for the RB5009 benchmark numbers.

---

## Category Deep Dives

### AI Citability (87/100, +5)

Best pages: troubleshooting (90 — question-form H3s, exact error strings paired with numbered fixes), prometheus reference (90 — one H3 per metric, definition-first, PromQL examples), homepage (88 — visible 5-question FAQ). Weakest: installation (65), quickstart (68) — step-dumps without self-contained summaries. **Direct evidence of extraction:** AI search summaries for both branded and unbranded queries reproduced the "~1–3 ms per operation" figure and reconciliation defaults nearly verbatim during the audit. Rewrite suggestions delivered for the four weakest passages (decision-rule phrasing for install-method choice, quantified defaults, self-contained API-key step, methodology anchor for the 97× claim).

### Brand Authority (32/100, +2)

Present: CrowdSec Hub listing (ranks #1 for the unbranded remediation-component query), GitHub (12★, active, good topics), Wikidata Q140393352 (minimal). Absent: awesome-crowdsec, Reddit, MikroTik forum, CrowdSec Discourse, YouTube, Wikipedia (unrealistic for the niche — CrowdSec itself has none), blogs (only a self-published Mastodon post). Branded queries resolve correctly; unbranded queries are owned by funkolab (archived), nvtkaszpir-alt, and tuxtof. Every remaining GEO point is off-site.

### Content E-E-A-T (70/100, +13)

Experience 19/25 (real RB5009 benchmarks with honest data-source attribution — rare first-hand asset), Expertise 15/25 (deep and accurate, but author invisible on page), Authoritativeness 15/25 (canonical source; thin outbound citations; github.io subdomain), Trust 21/25 (MIT license in footer, security policy with PGP + 48h commitment, changelog, honest hedged claims). Freshness excellent (visible last-updated everywhere, lastmod = audit day). Spanish translation assessed as complete, idiomatic, and professional — a genuine trust signal. Zero AI-slop patterns; assessment "Highly Likely Human".

### Technical GEO (96/100, +7)

Near-reference implementation: fully static SSG (100% content in raw HTML), robots.txt with 14 explicit AI-crawler allows + Content-Signal, spec-compliant llms.txt (now including the `## Languages` section for `/es/`), reciprocal hreflang triplets (en/es/x-default) in HTML, correct `lang` attributes, single-hop redirects, real 404, HSTS, system fonts (zero webfont requests), CLS-safe images, 54-URL sitemap with plausible per-page lastmod. Remaining gaps are cosmetic or GitHub Pages platform constraints (no custom headers possible).

### Schema & Structured Data (84/100, +41 — biggest gain)

All JSON-LD server-rendered and syntactically valid on every audited page; `@id` graph integrity passes (Person/WebSite/SoftwareApplication/SoftwareSourceCode all resolve). FAQPage now content-faithful word-for-word in both languages (July's critical issue). HowTo matches visible Steps, localized Spanish steps verified. BreadcrumbList sequential, resolving, localized ("Inicio"). `speakable` selectors verified in the DOM. SoftwareApplication carries git-derived `softwareVersion`/`dateModified` and `sameAs` → Hub + Wikidata. Deductions: live `inLanguage` staleness (fixed locally), TechArticle missing `image`/`datePublished`, minor enrichment opportunities.

### Platform Optimization (74/100, +14)

Bing Copilot 86 (verified Bing indexation via DDG proxy, msvalidate tag, IndexNow-per-deploy confirmed in CI, GitHub/Microsoft ecosystem strength) · ChatGPT 82 (crawler access 25/25, exemplary llms.txt, Wikidata anchoring; thin third-party corroboration) · Google AI Overviews 75 (FAQ block is ideal snippet material; quickstart lacks a direct-answer lead; `/es/` doubles AIO surface for Spanish queries) · Perplexity 72 (source directness and freshness strong; community validation 8/30 is the drag) · Gemini 55 (no YouTube/News presence; Knowledge Graph ingestion needs corroborating sources).

---

## Quick Wins (Implement This Week)

1. **Submit the `awesome-crowdsec` PR** — one line, feeds AI training corpora, closes a competitor asymmetry. (High)
2. **Footer byline "Maintained by José Manuel Requena Plens" (both locales) + minimal About page** — converts existing machine-readable identity into visible E-E-A-T. (High)
3. **Deploy the `inLanguage: ["en","es"]` fix** (already applied locally) and add `image` + `datePublished` to TechArticle, `softwareHelp` + `softwareRequirements` to SoftwareApplication. (High/Medium)
4. **Quickstart lead paragraph + Requirements block + 2–3 question-form headings**; expand key-page meta descriptions to 120–155 chars. (Medium)
5. **Enrich Wikidata Q140393352** with the existing bot credentials (depends-on, identifiers, current version). (Medium)

## 30-Day Action Plan

### Week 1: On-site quick wins (schema + authorship + entry pages)
- [ ] Commit/deploy `inLanguage` fix; add TechArticle `image`/`datePublished`; SoftwareApplication `softwareHelp`/`softwareRequirements`; link FAQPage into the graph
- [ ] Footer byline (en+es) + About/Credits page
- [ ] Quickstart/Installation: direct-answer intros, Requirements block, question-form headings, meta descriptions

### Week 2: Entity & directory presence
- [ ] awesome-crowdsec PR
- [ ] Wikidata enrichment (properties + identifiers, keep P348 current)
- [ ] CrowdSec Hub badge/link visible on the homepage
- [ ] Tested-with matrix (RouterOS versions/hardware/CrowdSec versions/date)

### Week 3: Community seeding (human actions)
- [ ] Announcement thread on discourse.crowdsec.net
- [ ] Participate in forum.mikrotik.com CrowdSec threads (t=187449 is the natural home)
- [ ] r/mikrotik write-up (first-mover — no competitor presence there either)

### Week 4: Content depth & media
- [ ] Deep outbound links: docs.crowdsec.net on config pages, RouterOS filter/raw docs on firewall/architecture pages
- [ ] Capture one real timestamped benchmark run; 1–2 annotated screenshots with alt text
- [ ] Optional: 3–5-min YouTube setup walkthrough linked from quickstart (biggest Gemini lever)
- [ ] Pitch the CrowdSec blog; follow up on the CfgMgmtCamp 2026 talk

---

## Appendix: Pages Analyzed

54 sitemap URLs verified HTTP 200 (27 en + 27 es, reciprocal hreflang). Deep-fetched sample:

| URL | Citability | Notable issues |
|---|---|---|
| `/` (en + es) | 88 | FAQ block exemplary; hero version badge now git-derived |
| `/getting-started/quickstart/` (en + es) | 68 | No direct-answer lead, no prerequisites block, noun-phrase headings |
| `/getting-started/installation/` | 65 | Weakest page: fragment headings, no tables/summary paragraphs |
| `/getting-started/router-setup/` | — | Best-cited page (8 external links incl. help.mikrotik.com) |
| `/configuration/` | 85 | Key/Env/Default tables highly extractable |
| `/configuration/capi-blocklists/` | 78 | Unique scale numbers; some hedged qualifiers |
| `/configuration/performance-tuning/` | — | Oldest lastmod (2026-05-09), still fine |
| `/architecture/` | 82 | Unique benchmark asset; 97× claim needs methodology anchor |
| `/development/benchmarking/` | — | RB5009 first-hand data; example output is illustrative |
| `/development/security/` | — | PGP + 48h response commitment — above-average trust signal |
| `/monitoring/prometheus/` | 90 | Reference-grade metric documentation |
| `/troubleshooting/` | 90 | Best GEO shape on the site |

Site-level files verified: `robots.txt` (root-level, 14 AI-crawler allows, Content-Signal), `llms.txt` (spec-compliant, 33 links, Languages section), `llms-full.txt`, `sitemap-index.xml` → `sitemap-0.xml` (54 URLs, lastmod, hreflang). No fetch failures.
