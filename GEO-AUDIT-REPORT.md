# GEO Audit Report: cs-routeros-bouncer

**Audit Date:** 2026-07-02
**URL:** <https://jmrplens.github.io/cs-routeros-bouncer/>
**Business Type:** Open-source software documentation (Astro + Starlight, GitHub Pages). Free/MIT-licensed — no pricing, no login, no commercial funnel. Closest audit template: SaaS documentation, adapted for an OSS project.
**Pages Analyzed:** 27 (full sitemap coverage, all HTTP 200)

---

## Executive Summary

### Overall GEO Score: 62/100 (Fair)

This site has an unusually strong technical and AI-crawler foundation for a small OSS project — a best-in-class `llms.txt`/`llms-full.txt` implementation, every major AI crawler explicitly allowed in `robots.txt`, 100% server-rendered content with no JS dependency, and a genuinely excellent proprietary-benchmark content asset on `/architecture/`. The score is pulled down by two things: an identical `FAQPage` JSON-LD block injected on all 27 pages that matches visible content on **none** of them (a real structured-data trust problem, not a cosmetic one), and weak external brand-authority signals (no Reddit/YouTube/Wikipedia presence, thin backlink profile, site doesn't yet rank in general search for its own name). Content quality is technically excellent but invisible-to-humans on authorship, and links out to zero authoritative third-party sources despite being a bridge product between two other systems (CrowdSec and MikroTik).

### Score Breakdown

| Category | Score | Weight | Weighted Score |
|---|---|---|---|
| AI Citability | 82/100 | 25% | 20.5 |
| Brand Authority | 30/100 | 20% | 6.0 |
| Content E-E-A-T | 57/100 | 20% | 11.4 |
| Technical GEO | 89/100 | 15% | 13.35 |
| Schema & Structured Data | 43/100 | 10% | 4.3 |
| Platform Optimization | 60/100 | 10% | 6.0 |
| **Overall GEO Score** | | | **61.55 ≈ 62/100** |

---

## Critical Issues (Fix Immediately)

**1. `FAQPage` structured data matches visible content on zero pages, sitewide.**
An identical 4-Q&A `FAQPage` JSON-LD block ("What is cs-routeros-bouncer?", version support, license, IPv6 support) is injected on **all 27 pages**. Independent verification (stripping the `<script type="application/ld+json">` blocks and searching remaining body text) confirmed the matching visible FAQ accordion does **not exist anywhere on the site, including the homepage** — the `<details>` elements found there are Starlight sidebar/TOC widgets, not an FAQ section. This is a direct violation of Google's structured-data content-matching policy and the kind of sitewide, zero-match pattern that risks a manual action on the `FAQPage` type and reduced crawler trust in the site's *other* (accurate) structured data.

- **Affected:** all 27 pages
- **Fix:** Either (a) build one real, visible FAQ accordion on the homepage using this exact copy and remove the `FAQPage` block from the other 26 pages, or (b) simply delete the `FAQPage` JSON-LD sitewide — `FAQPage` rich results have been restricted to government/health sites since Aug 2023, so there is no rich-result upside to keeping it, only downside risk.

---

## High Priority Issues

**2. No visible author/maintainer attribution anywhere on the site.**
A rich `Person` entity (name, `knowsAbout`, 6 `sameAs` links) exists in every page's JSON-LD `<head>`, but never surfaces in rendered UI — no byline, no "maintained by," no About page, no author name in the footer (footer only says "Built with Starlight · Powered by CrowdSec"). AI systems that weight visible E-E-A-T signals over hidden schema will miss this entirely.

- **Fix:** Add a footer line ("Maintained by José Manuel Requena Plens") linking to jmrp.io/GitHub, or a short `/about/` page mirroring the JSON-LD `Person` data.

**3. Zero contextual outbound citations to authoritative third-party sources, sitewide.**
Verified identical `external_domains: [github.com, starlight.astro.build, www.crowdsec.net]` on every sampled page (including the 3,570-word firewall config page and the 1,307-word troubleshooting page) — all boilerplate footer/head links, no in-content citations. For a project whose entire purpose is bridging CrowdSec and MikroTik RouterOS, never linking to either system's official docs (`docs.crowdsec.net`, `help.mikrotik.com`) is a real trust and verifiability gap.

- **Fix:** Add contextual links to CrowdSec's official docs from `/configuration/crowdsec/` and `/configuration/capi-blocklists/`, and to MikroTik's RouterOS API docs from `/configuration/mikrotik/`, `/configuration/firewall/`, and `/getting-started/router-setup/`.

**4. `/development/benchmarking/` is a generic template with no real numbers, while genuine benchmark data exists elsewhere.**
The dedicated benchmarking page (310 words) has no actual results, while `/architecture/` independently documents real, quotable figures (~28,700 CAPI entries processed in ~35–36s; cache-first add "~97× faster" than sequential API calls; ~400ms/IP for check-first). This is the site's best citability asset and it's stranded on the wrong page.

- **Fix:** Pull the real benchmark figures from `/architecture/` into `/development/benchmarking/` with hardware/RouterOS-version context.

**5. No Reddit, forum, or Q&A community presence.**
Confirmed via targeted search (`site:reddit.com`, MikroTik forum, CrowdSec Discourse) — zero hits specific to the project. This is the single largest gap for Perplexity, which heavily surfaces community discussion, and a missed backlink source that would also help Google AI Overviews ranking.

- **Fix:** A genuine (non-promotional) post in r/mikrotik, r/CrowdSec, r/selfhosted, or the CrowdSec Discourse forum, linking to specific docs pages rather than just the repo.

**6. No YouTube or video content.**
No video presence found for the project or author in this context — a real gap for Gemini's multi-format preference and for "how do I install X" queries generally.

- **Fix:** A short (5–10 min) screen-recorded quickstart walkthrough, linked from `/getting-started/quickstart/`.

**7. No per-page `Article`/`TechArticle`/`WebPage` schema — all 27 pages share identical, page-agnostic JSON-LD.**
Every page ships the exact same `Person`/`WebSite`/`SoftwareApplication`/`SoftwareSourceCode` graph regardless of its own content. There is no machine-readable per-page signal (headline, summary, `dateModified`) despite each page already having a unique, well-written title and meta description.

- **Fix:** Add a `TechArticle` (or `WebPage`) JSON-LD block per page using the existing unique title/description, plus `dateModified` sourced from the already-rendered "Last updated" timestamp (see also Medium #9 below).

---

## Medium Priority Issues

**8. Question-phrased headings appear on only 1 of 27 pages (the homepage).** All procedural/reference pages use declarative headings, reducing snippet-extraction odds for AI Overviews and ChatGPT. *Fix:* add a handful of question-style subheadings with direct 40–60 word answers on high-traffic pages (e.g. "How do I enable IPv6 filtering?" on `/configuration/firewall/`).

**9. No `dateModified` in any JSON-LD, despite every page visibly rendering a "Last updated" `<time>` element.** The freshness signal is human-visible but not machine-readable. *Fix:* wire the existing per-page timestamp into the new `TechArticle`/`SoftwareApplication` schema.

**10. Every one of 8 spot-checked pages shows the identical "Last updated" timestamp down to the second (`2026-07-01T19:44:10.000Z`).** This suggests Starlight's `lastUpdated` is resolving from a single bulk commit rather than true per-file git history — as configured, this will always show "just updated" sitewide regardless of which page actually changed, undermining it as a trust/freshness signal going forward. *Fix:* verify Starlight's git-history-based `lastUpdated` config is reading true per-file history, not build/deploy time.

**11. No `HowTo` schema on clearly step-by-step pages** (`/getting-started/quickstart/`, `/getting-started/installation/`, `/getting-started/router-setup/`). *Fix:* add `HowTo`/`HowToStep` JSON-LD mirroring the existing numbered instructions.

**12. No `BreadcrumbList` schema anywhere**, despite Starlight's sidebar already encoding the needed hierarchy (Getting Started / Configuration / Architecture / Monitoring / Development). *Fix:* generate `BreadcrumbList` from the existing sidebar group data.

**13. GitHub repository has zero topics/tags set.** Flagged independently by three subagents as a discoverability and entity-recognition gap. *Fix:* add topics such as `crowdsec`, `mikrotik`, `routeros`, `firewall`, `bouncer`, `network-security`, `go`.

**14. Sitemap has no `<lastmod>` dates on any of the 27 URLs**, despite every page displaying one in its UI — this is the default `@astrojs/sitemap` output unless explicitly wired. *Fix:* configure the sitemap integration's `serialize()` to emit `lastmod` from each page's frontmatter/git history.

**15. `/architecture/` is disproportionately heavy (~230KB raw HTML vs. 60–130KB sitewide average)** because two Mermaid diagrams are inlined as `data:image/svg+xml` URIs. Good for zero-JS crawler visibility, but a real payload cost. *Fix:* extract to static `.svg` files referenced via `<img src>` if diagram count grows, keeping `<title>`/`<desc>` inside the SVG for text-extractability.

**16. Security policy page (`/development/security/`) has no inline contact method.** It instructs "email the maintainer directly" but includes no actual email address or the PGP key link that already exists sitewide via `rel="pgpkey"`. *Fix:* inline the maintainer's contact email or PGP key link directly on the security page.

**17. `SoftwareApplication` schema is missing `softwareVersion`**, despite the homepage visibly showing "v1.4.5". *Fix:* add `softwareVersion` (and ideally `dateModified` for the release) to the existing block.

**18. No `speakable` property anywhere.** A low-effort, direct AI-assistant-readability signal. *Fix:* add `SpeakableSpecification` to the homepage `WebSite`/`TechArticle` targeting the hero description and "How it works" section.

---

## Low Priority Issues

**19.** No `Content-Signal:` directive in `robots.txt` (site already explicitly welcomes AI crawlers by name — this is the machine-readable complement per contentsignals.org).
**20.** 2 images on `/architecture/` and 1 on the homepage missing/empty `alt` text (likely diagrams and a decorative duplicate logo — verify intent, add real alt text to the diagrams).
**21.** HSTS header present but missing `includeSubDomains`.
**22.** No `<link rel="preload">` for the main render-blocking CSS bundle (marginal impact given ~40–60ms TTFB already).
**23.** No CSP via `<meta http-equiv>` — the only CSP option available under GitHub Pages' no-custom-response-headers constraint (no `X-Frame-Options`/`X-Content-Type-Options` equivalent exists via meta tag; this is a platform limitation, not fixable without a hosting change).
**24.** `Person` schema missing `jobTitle`.
**25.** No dedicated LinkedIn company/project page (only the author's personal profile is linked).
**26.** Homepage feature-card headers ("Zero Manual Configuration," "Self-Healing State") are marketing phrasing that isn't independently quotable — front-load the supporting number/fact into the header itself.
**27.** Minor entity-ambiguity risk: a similarly-purposed third-party project (`funkolab/cs-mikrotik-bouncer`) surfaces alongside this one in generic "CrowdSec MikroTik bouncer" searches. Reinforce distinctive positioning ("RouterOS API-based, real-time" vs. address-list/script-based alternatives) in meta descriptions/homepage copy.
**28.** No Wikipedia article for the project — confirmed absent via direct MediaWiki API search. At ~4 months old, the project likely doesn't yet meet notability guidelines; deprioritize this and continue investing in the already-strong Wikidata entry (Q140393352) instead.

---

## Category Deep Dives

### AI Citability (82/100)

Strong. The `/architecture/` page's proprietary benchmark data (RB5009 pool sizing, ms-level per-IP latency, ~97× speedup claims) is genuinely citation-ready — self-contained, quotable, backed by specific numbers not found elsewhere. `/configuration/firewall/` parameter tables (key/env-var/default/notes) are exactly the shape AI systems quote verbatim. `/troubleshooting/` reuses real benchmark data in support-answer format effectively. Weakest spots: homepage feature-card headers standing alone without their supporting sentence, and `/configuration/examples/` (12 code blocks, thin surrounding prose — valuable but not directly quotable as prose). `llms.txt` (5,690 bytes) and `llms-full.txt` (9,004 bytes) are both spec-compliant and genuinely complete (not stubs), including a self-declared trust note ("if it looks stale, trust the live docs") — a best-in-class implementation requiring no fixes.

### Brand Authority (30/100)

The weakest category. Wikidata (Q140393352) is a strong, high-quality knowledge-graph node updated the same day as this audit. CrowdSec Hub listing is live and functioning well (v1.4.5, 316 downloads, mirrors GitHub star count) — the single most relevant niche-authority signal available for this exact product category. Mastodon shows genuine project-specific activity (a real announcement post), not just a dormant profile link. Google Scholar confirms the author is a real credentialed researcher, though in an unrelated field (acoustics), so it adds general author-trust rather than topical authority. Everything else is absent: no Reddit, no YouTube, no Wikipedia (reasonably, given project age), and LinkedIn is present but not independently verifiable as AI-crawlable (platform blocks bots).

### Content E-E-A-T (57/100)

Technical substance is genuinely strong — real error strings, exact RouterOS commands, quantified benchmarks, correct domain vocabulary throughout, and the content reads as authentically human-written (no generic AI filler detected). What's missing is everything that makes that expertise *legible*: no visible author attribution, zero contextual external citations despite the product's entire value proposition being a bridge between two other systems, and the one page specifically meant to showcase performance (`/development/benchmarking/`) is a template. Trust signals are otherwise solid: HTTPS, clear MIT licensing, a genuine security policy with a supported-versions matrix and 48-hour SLA, and "Edit on GitHub" provenance links on every page.

### Technical GEO (89/100)

The strongest category by far. This is a fully static Astro build — verified that 100% of visible text is present in the raw server-delivered HTML with zero JS execution required, meaning every major AI crawler (GPTBot, ClaudeBot, PerplexityBot, etc., all of which the site explicitly allows) sees the complete content. `robots.txt` is clean and comprehensive. Meta tags, canonical URLs, mobile responsiveness, and URL structure are all correct across all 27 pages. TTFB measured at 38–63ms via Fastly CDN. The only real gaps are platform-imposed (GitHub Pages doesn't support custom security headers) or minor (`<lastmod>` missing from the sitemap, one heavy page from inlined diagrams).

### Schema & Structured Data (43/100)

The weakest technical category, driven mostly by the sitewide `FAQPage` mismatch (see Critical #1) and the absence of any page-specific structured data — all 27 pages share identical `Person`/`WebSite`/`SoftwareApplication`/`SoftwareSourceCode` JSON-LD regardless of what the page actually contains. What exists is well-formed (100% JSON-LD, correct `@id` linking between entities, no Microdata/RDFa cruft) and the `Person`/`SoftwareApplication` entities themselves are reasonably complete (`sameAs` to 6+ platforms, Wikidata link, CrowdSec Hub link). `BreadcrumbList`, `speakable`, `dateModified`, and `softwareVersion` are all absent but low-effort to add given the underlying data already exists on-page.

### Platform Optimization (60/100)

Bing Copilot is the standout (77/100) — Bing Webmaster verification tag confirmed live, and IndexNow submission is already wired into CI, posting to the API after every deploy. ChatGPT web search (69/100) benefits from explicit `OAI-SearchBot`/`ChatGPT-User` allowance and the Wikidata-anchored entity. Perplexity (63/100) has ideal technical access (zero-JS, explicit crawler allowance, accurate freshness signals) but is held back by the same zero-community-presence gap noted in Brand Authority. Google AI Overviews (50/100) is limited by the fact that the docs site doesn't yet rank in general search for its own project name — AIO fundamentally favors already-ranking pages. Gemini (39/100) is weakest, reflecting minimal Google-ecosystem presence (no YouTube, no Knowledge Panel, only 2 images sitewide).

---

## Quick Wins (Implement This Week)

1. **Delete or scope the `FAQPage` JSON-LD** — removing it sitewide is a 10-minute fix that eliminates the single largest structured-data risk on the site (Critical #1).
2. **Add GitHub repo topics** (`crowdsec`, `mikrotik`, `routeros`, `firewall`, `bouncer`, `network-security`, `go`) — a 2-minute change flagged by three independent subagents (Medium #13).
3. **Add a "Maintained by [name]" footer line** linking to jmrp.io/GitHub — makes the existing `Person` schema legible to human readers, not just crawlers (High #2).
4. **Add `softwareVersion` to the `SoftwareApplication` JSON-LD** — the version is already displayed visibly ("v1.4.5"), just not in structured data (Medium #17).
5. **Add 2–3 contextual links to CrowdSec's and MikroTik's official docs** on `/configuration/crowdsec/`, `/configuration/mikrotik/`, and `/configuration/firewall/` — the site currently links to zero authoritative external sources despite being a bridge product (High #3).

## 30-Day Action Plan

### Week 1: Fix the Trust-Breaking Schema Issue

- [ ] Remove `FAQPage` JSON-LD from all pages, or build a real homepage FAQ accordion and scope the schema to only that page (Critical #1)
- [ ] Add GitHub repo topics (Medium #13)
- [ ] Add visible author/maintainer attribution — footer line + link (High #2)
- [ ] Add `softwareVersion` to `SoftwareApplication` schema (Medium #17)

### Week 2: Close the Content Authority Gap

- [ ] Fill `/development/benchmarking/` with real figures already documented on `/architecture/` (High #4)
- [ ] Add contextual outbound links to CrowdSec and MikroTik official docs across configuration pages (High #3)
- [ ] Inline a real contact method (email or PGP link) on `/development/security/` (Medium #16)
- [ ] Investigate and fix the identical per-second "Last updated" timestamp across all pages (Medium #10)

### Week 3: Structured Data Depth

- [ ] Add per-page `TechArticle`/`WebPage` JSON-LD with `dateModified` (High #7)
- [ ] Add `BreadcrumbList` generated from the Starlight sidebar hierarchy (Medium #12)
- [ ] Add `HowTo` schema to quickstart/installation/router-setup pages (Medium #11)
- [ ] Add `<lastmod>` to the sitemap (Medium #14)

### Week 4: Off-Site Authority

- [ ] Publish one genuine, non-promotional Reddit post (r/mikrotik or r/CrowdSec) linking to specific docs pages (High #5)
- [ ] Record and publish a short YouTube quickstart walkthrough (High #6)
- [ ] Add a handful of question-phrased subheadings with direct answers to 3–4 high-traffic pages (Medium #8)
- [ ] Sweep remaining Low-priority items: alt text on `/architecture/` images, `Content-Signal:` directive, HSTS `includeSubDomains`, CSP meta tag

---

## Appendix: Pages Analyzed

| URL | Title | GEO Issues |
|---|---|---|
| `/` | CrowdSec Bouncer for MikroTik RouterOS \| cs-routeros-bouncer | FAQ schema mismatch, no author attribution, 1 img missing alt |
| `/architecture/` | Architecture \| cs-routeros-bouncer | FAQ schema mismatch, heavy HTML (inlined SVGs), 2 imgs missing alt |
| `/architecture/decisions/` | Decision Processing \| cs-routeros-bouncer | FAQ schema mismatch |
| `/architecture/firewall-rules/` | Firewall Rules \| cs-routeros-bouncer | FAQ schema mismatch |
| `/architecture/reconciliation/` | Reconciliation \| cs-routeros-bouncer | FAQ schema mismatch |
| `/configuration/` | Configuration Overview \| cs-routeros-bouncer | FAQ schema mismatch |
| `/configuration/capi-blocklists/` | CAPI Blocklists \| cs-routeros-bouncer | FAQ schema mismatch, no external citation |
| `/configuration/crowdsec/` | CrowdSec Configuration \| cs-routeros-bouncer | FAQ schema mismatch, no link to CrowdSec docs |
| `/configuration/examples/` | Examples \| cs-routeros-bouncer | FAQ schema mismatch, thin prose around code |
| `/configuration/firewall/` | Firewall \| cs-routeros-bouncer | FAQ schema mismatch, no MikroTik doc citation |
| `/configuration/logging-metrics/` | Logging & Metrics \| cs-routeros-bouncer | FAQ schema mismatch |
| `/configuration/mikrotik/` | MikroTik Configuration \| cs-routeros-bouncer | FAQ schema mismatch, no MikroTik doc citation |
| `/configuration/performance-tuning/` | Performance Tuning \| cs-routeros-bouncer | FAQ schema mismatch |
| `/development/benchmarking/` | Benchmarking \| cs-routeros-bouncer | FAQ schema mismatch, generic template (High #4) |
| `/development/building/` | Building \| cs-routeros-bouncer | FAQ schema mismatch |
| `/development/contributing/` | Contributing \| cs-routeros-bouncer | FAQ schema mismatch |
| `/development/security/` | Security \| cs-routeros-bouncer | FAQ schema mismatch, no inline contact method |
| `/development/structure/` | Project Structure \| cs-routeros-bouncer | FAQ schema mismatch |
| `/development/testing-guide/` | Testing Guide \| cs-routeros-bouncer | FAQ schema mismatch |
| `/getting-started/cli-reference/` | CLI Reference \| cs-routeros-bouncer | FAQ schema mismatch |
| `/getting-started/installation/` | Installation \| cs-routeros-bouncer | FAQ schema mismatch, no HowTo schema |
| `/getting-started/quickstart/` | Quick Start \| cs-routeros-bouncer | FAQ schema mismatch, no HowTo schema |
| `/getting-started/router-setup/` | Router Setup \| cs-routeros-bouncer | FAQ schema mismatch, no HowTo schema |
| `/monitoring/grafana/` | Grafana Dashboard \| cs-routeros-bouncer | FAQ schema mismatch |
| `/monitoring/health/` | Health Endpoint \| cs-routeros-bouncer | FAQ schema mismatch |
| `/monitoring/prometheus/` | Prometheus Metrics \| cs-routeros-bouncer | FAQ schema mismatch |
| `/troubleshooting/` | Troubleshooting \| cs-routeros-bouncer | FAQ schema mismatch |

**Fetch failures:** none — all 27 sitemap URLs returned HTTP 200.

**Prior work note:** this site received a comprehensive GEO pass on 2026-07-01 (PR #58 — `robots.txt`/`llms.txt`/`llms-full.txt`, JSON-LD `@graph`, `rel=me` identity links, Wikidata entity Q140393352) that is directly responsible for the strong Technical GEO and AI Citability scores in this audit. This audit's findings represent the next iteration, not a first pass.
