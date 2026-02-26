---
goal: Improve Starlight documentation site design, UX, accessibility, and visual identity
version: 1.0
date_created: 2026-02-26
last_updated: 2026-02-26
owner: jmrplens
status: 'Planned'
tags: [design, documentation, starlight, accessibility, frontend, ux]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

Comprehensive redesign of the cs-routeros-bouncer Starlight documentation site (`docs/`) to improve visual identity, user experience, accessibility (WCAG 2.2 AA), responsive design, and overall design quality. The current site uses default Starlight styling with minimal customization (only table font-size). This plan transforms it into a polished, branded, accessible, and performant documentation site.

**Current state summary:**
- **Framework**: Starlight v0.37.6 + Astro v5.6.1 (pnpm)
- **Content**: 17 MDX pages in 5 sections + index + troubleshooting
- **Custom CSS**: 3 lines (table font-size only)
- **Components**: All built-in Starlight (Card, CardGrid, LinkCard, Badge, Steps, Tabs, FileTree, Aside)
- **No custom component overrides** (Header, Footer, Hero, etc.)
- **Mermaid code blocks exist** in architecture pages but are NOT rendered (missing integration)
- **Logo**: Simple SVG (#3F51B5 indigo), not aligned with site theme colors
- **No OG image** (referenced in config but file missing)
- **No custom fonts, no dark/light theme customization**
- **Deployed at**: `https://jmrplens.github.io/cs-routeros-bouncer`

## 1. Requirements & Constraints

- **REQ-001**: Maintain all existing content and page structure unchanged
- **REQ-002**: All design changes must work within Starlight's component override system — no forking the framework
- **REQ-003**: Support both dark and light mode with consistent branding
- **REQ-004**: Mermaid diagrams in architecture pages must render correctly
- **REQ-005**: OG image must exist and be correctly referenced for social sharing
- **REQ-006**: Site must remain statically deployable to GitHub Pages
- **REQ-007**: Custom CSS must use Starlight's CSS custom property system (`--sl-*`) for theme integration
- **SEC-001**: No external font/CDN dependencies that could be blocked or introduce privacy concerns — prefer self-hosted or system fonts
- **ACC-001**: WCAG 2.2 AA compliance — color contrast ratio ≥ 4.5:1 for normal text, ≥ 3:1 for large text
- **ACC-002**: All interactive elements must have visible focus indicators
- **ACC-003**: Support `prefers-reduced-motion`, `prefers-color-scheme`, `prefers-contrast`
- **ACC-004**: Skip-to-content link must be functional and visible on focus
- **ACC-005**: All images must have descriptive alt text
- **ACC-006**: Keyboard navigation must work without traps
- **PER-001**: Lighthouse Performance score ≥ 90
- **PER-002**: No render-blocking external resources
- **PER-003**: Images must use modern formats (WebP via Sharp, already configured)
- **CON-001**: Must use pnpm as package manager (existing setup)
- **CON-002**: Starlight version ^0.37.6 — check compatibility of all plugins before adding
- **CON-003**: Base URL is `/cs-routeros-bouncer` — all assets and links must respect this
- **GUD-001**: Follow Starlight's official customization patterns — CSS custom properties > component overrides > custom integrations
- **GUD-002**: Prefer Starlight built-in components over custom ones when functionality is equivalent
- **GUD-003**: Keep custom CSS minimal and maintainable — use design tokens, not hard-coded values
- **PAT-001**: Use CSS `clamp()` for fluid typography where applicable
- **PAT-002**: Use CSS custom properties for all color and spacing values
- **PAT-003**: Use Starlight's `customCss` array in `astro.config.mjs` for all style imports

## 2. Implementation Steps

### Implementation Phase 1: Visual Identity & Theme System

- GOAL-001: Establish a cohesive color palette and typography system aligned with the project's brand identity (CrowdSec security + MikroTik networking) using Starlight's CSS custom property override system.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-001 | **Define color palette as CSS custom properties** in `docs/src/styles/custom.css`. Override Starlight's `--sl-color-accent-*` (5 shades: low, high, and 3 intermediates) for both `:root` (light) and `:root[data-theme="dark"]` selectors. Base accent on logo's indigo (#3F51B5) with accessible contrast: accent-high for text on white (≥4.5:1), accent-low for backgrounds. Also set `--sl-color-text-accent` to ensure link readability. | | |
| TASK-002 | **Define semantic color tokens** in `docs/src/styles/custom.css` for callouts/asides. Override `--sl-color-green-*` (tip), `--sl-color-orange-*` (caution), `--sl-color-red-*` (danger), `--sl-color-blue-*` (note) for both light and dark themes. Ensure ≥3:1 contrast ratio for callout border/icon against background. | | |
| TASK-003 | **Configure typography** in `docs/src/styles/custom.css`. Override `--sl-font` (body) to use a system font stack: `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`. Override `--sl-font-mono` to `'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'SF Mono', Consolas, monospace`. Use `clamp()` for `--sl-text-h1` through `--sl-text-h4` for fluid heading sizes (e.g., `--sl-text-h1: clamp(1.75rem, 4vw, 2.25rem)`). | | |
| TASK-004 | **Refine spacing and border radius** in `docs/src/styles/custom.css`. Set `--sl-border-radius` to `0.5rem` for softer card/callout corners. Adjust `--sl-content-width` to `55rem` (from default 50rem) for better readability on wide screens. Add `--sl-sidebar-width: 18rem` for slightly wider sidebar. | | |
| TASK-005 | **Enhance the SVG logo** (`docs/src/assets/logo.svg`). Update fill colors to match the new accent palette. Ensure the logo renders well at small sizes (sidebar: ~24px) with sufficient contrast in both dark and light modes. Consider adding a `currentColor` approach for theme-adaptive coloring. | | |
| TASK-006 | **Add subtle background texture/gradient** to hero section only via CSS targeting `.hero` class in `docs/src/styles/custom.css`. Use a subtle radial gradient using accent colors at low opacity (5-10%). Must work in both dark and light mode. | | |

### Implementation Phase 2: Component Overrides & Custom Components

- GOAL-002: Enhance the site's UI with custom Starlight component overrides and additional MDX components for richer documentation content.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-007 | **Create custom Footer override** at `docs/src/components/overrides/Footer.astro`. Override Starlight's default footer (via `components: { Footer: ... }` in `astro.config.mjs`). Include: project version badge, link to GitHub repo, link to CrowdSec website, MIT license notice, and "Built with Starlight" attribution. Use semantic `<footer>` element with `role="contentinfo"`. Style with Starlight CSS vars for consistency. | | |
| TASK-008 | **Create custom Header override** at `docs/src/components/overrides/Header.astro`. Extend default Starlight header by adding a subtle top banner/announcement bar for important notices (e.g., "v2.0 released!" or empty by default). Use Starlight's `<Header>` as base and wrap with custom content. Register via `components: { Header: ... }` in `astro.config.mjs`. | | |
| TASK-009 | **Create custom Hero override** at `docs/src/components/overrides/Hero.astro`. Override the default hero to add: (a) animated terminal preview showing a sample bouncer startup log, (b) version badge pulled from package.json or hardcoded, (c) feature highlights as icon pills below the CTA buttons. Register via `components: { Hero: ... }` in `astro.config.mjs`. | | |
| TASK-010 | **Create `<Architecture>` MDX component** at `docs/src/components/Architecture.astro`. A styled diagram wrapper with caption support, border, and subtle shadow. Usage: `<Architecture caption="Data flow">...</Architecture>`. This wraps the mermaid diagrams with consistent styling. | | |
| TASK-011 | **Create `<Version>` MDX component** at `docs/src/components/Version.astro`. Displays a styled version badge with optional link to GitHub release. Props: `version: string`, `date?: string`, `href?: string`. Usage: `<Version version="1.2.0" date="2026-01-15" />`. | | |

### Implementation Phase 3: Mermaid Diagram Integration

- GOAL-003: Enable rendering of Mermaid diagrams that currently exist as code blocks in architecture pages (`docs/src/content/docs/architecture/index.mdx`, `decisions.mdx`, `reconciliation.mdx`, `firewall-rules.mdx`).

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-012 | **Install `@astrojs/starlight-mermaid`** (or `remark-mermaidjs` if Starlight plugin unavailable). Run `pnpm add -D @astrojs/starlight-mermaid` in `docs/` directory. Verify compatibility with Starlight ^0.37.6. If `@astrojs/starlight-mermaid` doesn't exist, use alternative: install `rehype-mermaid` + `playwright` (for server-side rendering) or `mermaid` client-side. | | |
| TASK-013 | **Configure mermaid integration** in `docs/astro.config.mjs`. Add the mermaid plugin to the Starlight config or Astro's markdown config (`remarkPlugins` / `rehypePlugins`). Configure mermaid theme to match site colors: dark theme for `data-theme="dark"`, default/neutral for light mode. | | |
| TASK-014 | **Verify all mermaid diagrams render** in `docs/src/content/docs/architecture/index.mdx` (2 diagrams: flowchart + sequence). Test both dark and light modes. Ensure diagrams are accessible (wrapped in `<figure>` with `<figcaption>` or have `aria-label`). Verify mobile rendering with horizontal scroll if needed. | | |
| TASK-015 | **Add mermaid CSS overrides** in `docs/src/styles/custom.css` to style mermaid output to match site theme. Target `.mermaid` container: set `max-width: 100%`, `overflow-x: auto`, add subtle border/shadow matching card style. Style text nodes to use `--sl-font` and color nodes to use accent palette. | | |

### Implementation Phase 4: Enhanced Landing Page (index.mdx)

- GOAL-004: Transform the index page into a more visually engaging landing page with improved layout, visual hierarchy, and social proof elements.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-016 | **Enhance hero section** in `docs/src/content/docs/index.mdx`. Add `banner` frontmatter field if supported, or add a version badge component below the hero tagline. Update hero actions: add a third action "View Documentation" linking to `/cs-routeros-bouncer/getting-started/installation/`. | | |
| TASK-017 | **Style the comparison table** in `docs/src/styles/custom.css`. Add custom CSS for the comparison table on the index page: sticky first column on mobile scroll, highlight the "cs-routeros-bouncer" column with accent background, add hover row highlighting, improve emoji checkmark/cross visibility with color. Target via `.sl-markdown-content table` selectors. | | |
| TASK-018 | **Add "How it works" section** to `docs/src/content/docs/index.mdx` between the features CardGrid and the comparison table. Use a `<Steps>` component with 3 steps: (1) "CrowdSec detects threats" → (2) "Bouncer receives decisions" → (3) "MikroTik blocks the IP". Keep it concise, 1-2 sentences per step. | | |
| TASK-019 | **Add GitHub stars badge and version badge** to `docs/src/content/docs/index.mdx` hero section using Shields.io badges as `<img>` elements with appropriate alt text. Badges: GitHub stars, latest release version, Go version, license. Place in a flex container below the hero tagline. | | |
| TASK-020 | **Create an OG image** at `docs/public/og-image.png`. Generate a 1200×630 PNG with: project name, tagline "CrowdSec bouncer for MikroTik RouterOS", logo, accent color background gradient. This fixes the broken `og:image` meta tag already configured in `astro.config.mjs`. | | |

### Implementation Phase 5: Accessibility Audit & Fixes

- GOAL-005: Ensure full WCAG 2.2 AA compliance across the documentation site, building on Starlight's accessible defaults.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-021 | **Audit and fix color contrast** in `docs/src/styles/custom.css`. After applying the new color palette (Phase 1), verify all text/background combinations meet WCAG AA contrast ratios using DevTools or axe. Fix any failures by adjusting CSS custom property values. Key areas: accent-colored links, callout text, badge text, table header text, sidebar active item. | | |
| TASK-022 | **Enhance focus indicators** in `docs/src/styles/custom.css`. Add custom `:focus-visible` styles for all interactive elements: `outline: 2px solid var(--sl-color-accent-high); outline-offset: 2px; border-radius: var(--sl-border-radius)`. Apply to `a`, `button`, `input`, `select`, `[tabindex]`. Ensure focus ring is visible in both dark and light modes. | | |
| TASK-023 | **Add `prefers-reduced-motion` support** in `docs/src/styles/custom.css`. Wrap any custom animations or transitions in `@media (prefers-reduced-motion: no-preference) { ... }`. Add `@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }` as safety net. | | |
| TASK-024 | **Add `prefers-contrast` support** in `docs/src/styles/custom.css`. Add `@media (prefers-contrast: more) { ... }` to increase border widths to 2px, increase text weight, remove subtle gradients/shadows, increase callout border contrast. | | |
| TASK-025 | **Audit all images for alt text** in all MDX files under `docs/src/content/docs/`. Verify: `grafana-dashboard-dark.png` and `grafana-dashboard-light.png` in `monitoring/grafana.mdx` have descriptive alt text (currently "Grafana dashboard dark/light theme" — improve to describe content). Verify logo in hero has meaningful alt text. | | |
| TASK-026 | **Verify keyboard navigation** across the built site. Test: Tab through all pages, verify no focus traps, verify sidebar navigation, verify search dialog (`Ctrl+K`), verify mobile menu, verify code block copy buttons, verify Tabs components. Document any issues found and fix them in `docs/src/styles/custom.css` or via component overrides. | | |
| TASK-027 | **Add ARIA landmarks** to custom component overrides (Footer, Header from Phase 2). Ensure Footer has `aria-label="Site footer"`, any custom nav has `aria-label`, announcement banner has `role="status"` or `aria-live="polite"`. Verify existing Starlight landmarks with browser DevTools. | | |

### Implementation Phase 6: Responsive Design Enhancements

- GOAL-006: Improve the responsive behavior of the documentation site on all viewport sizes (320px–2560px), with special attention to tables, code blocks, and the comparison table.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-028 | **Make tables responsive** in `docs/src/styles/custom.css`. Wrap all content tables in a scrollable container: `.sl-markdown-content table { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; }`. Add `scrollbar-width: thin` for Firefox. Add `::-webkit-scrollbar` styles for Chrome. Set `white-space: nowrap` on `th` elements to prevent header wrapping. | | |
| TASK-029 | **Improve code blocks on mobile** in `docs/src/styles/custom.css`. Ensure code blocks have `overflow-x: auto` with smooth scrolling. Reduce `font-size` to `0.8rem` on viewports < 640px. Ensure copy button stays visible and tappable (min 44×44px touch target). Add `word-break: break-all` for very long strings in inline code. | | |
| TASK-030 | **Optimize hero on mobile** in `docs/src/styles/custom.css`. At viewport < 640px: stack hero image above text, reduce hero title font-size, stack action buttons vertically with full-width, reduce hero padding. Use `@media (max-width: 40rem) { ... }` targeting `.hero` class. | | |
| TASK-031 | **Add fluid spacing** in `docs/src/styles/custom.css`. Use `clamp()` for `--sl-content-pad-x` and content vertical spacing. Example: `--sl-content-pad-x: clamp(1rem, 3vw, 2rem)`. This ensures comfortable reading on all screen sizes without abrupt breakpoint jumps. | | |
| TASK-032 | **Test and fix print styles** in `docs/src/styles/custom.css`. Add `@media print { ... }` rules: hide sidebar, header, footer, ToC, search, theme toggle. Expand content to full width. Ensure code blocks don't overflow. Set body to white background with black text. Add URL display after links: `a[href^="http"]::after { content: " (" attr(href) ")"; }`. | | |

### Implementation Phase 7: Performance & SEO Optimization

- GOAL-007: Optimize site performance and SEO to achieve Lighthouse scores ≥90 in all categories, with proper meta tags and structured data for social sharing and search engines.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-033 | **Add comprehensive meta tags** in `docs/astro.config.mjs` `head` array. Add: `og:type` (website), `og:site_name`, `twitter:card` (summary_large_image), `twitter:image`, `theme-color` (matching accent for browser chrome). Verify existing `og:image` path is correct after creating the OG image in TASK-020. | | |
| TASK-034 | **Add JSON-LD structured data** in `docs/astro.config.mjs` `head` array as a `<script type="application/ld+json">` tag. Include: `@type: SoftwareApplication`, `name`, `description`, `url`, `applicationCategory: NetworkSecurity`, `operatingSystem`, `offers: { price: 0, priceCurrency: USD }`, `author`. | | |
| TASK-035 | **Verify and optimize images**. Check that Sharp (already in dependencies) is processing images. Verify the 2 Grafana screenshots in `docs/src/assets/` are being optimized to WebP in the build output. Check image dimensions are reasonable (not oversized). Add explicit `width` and `height` to `<img>` tags or Astro `<Image>` components to prevent layout shift. | | |
| TASK-036 | **Add favicon set** to `docs/public/`. Currently favicon is referenced as `/favicon.svg` but the file is in `docs/src/assets/favicon.svg` (via Starlight config). Verify the favicon is correctly served. Add `apple-touch-icon.png` (180×180) to `docs/public/` and reference in `head` config. Add `<link rel="icon" type="image/svg+xml" href="/cs-routeros-bouncer/favicon.svg" />` if not already handled by Starlight. | | |
| TASK-037 | **Run Lighthouse audit** on the built site. Build the site (`pnpm build` in `docs/`), serve it locally (`pnpm preview`), and run Lighthouse. Document scores for Performance, Accessibility, Best Practices, SEO. Fix any critical issues found. Target: all scores ≥ 90. | | |

### Implementation Phase 8: Code Quality & Documentation Config

- GOAL-008: Finalize the configuration, clean up, and ensure all changes are properly integrated and the site builds without errors.

| Task | Description | Completed | Date |
| --- | --- | --- | --- |
| TASK-038 | **Update `docs/astro.config.mjs`** to register all component overrides from Phase 2. Add `components` key to Starlight config: `{ Footer: './src/components/overrides/Footer.astro', Hero: './src/components/overrides/Hero.astro' }`. Add any new `customCss` entries if additional CSS files were created. | | |
| TASK-039 | **Organize CSS into logical files**. If `docs/src/styles/custom.css` exceeds ~200 lines, split into: `custom.css` (imports), `theme.css` (colors, typography), `components.css` (component-specific styles), `responsive.css` (media queries), `print.css` (print styles). Import all via `customCss` array in astro config. | | |
| TASK-040 | **Build and verify** the complete site. Run `cd docs && pnpm install && pnpm build`. Fix any build errors. Verify all pages render correctly in both dark and light mode. Check that mermaid diagrams render. Check mobile responsiveness. Check accessibility with browser DevTools. | | |
| TASK-041 | **Update `docs/README.md`** with notes about the design system: color palette values, component override locations, how to add new custom components, and how to modify the theme. This ensures future contributors understand the design architecture. | | |

## 3. Alternatives

- **ALT-001**: **Use a completely custom Astro theme instead of Starlight** — Rejected because Starlight provides excellent defaults for documentation (search, sidebar, i18n, dark mode) and the content is already structured for it. Building from scratch would be more work for equivalent functionality.
- **ALT-002**: **Use Tailwind CSS for styling** — Rejected because Starlight's CSS custom property system is well-designed and adding Tailwind would introduce unnecessary complexity, larger bundle, and potential conflicts with Starlight's internal styles.
- **ALT-003**: **Use external Google Fonts (Inter, JetBrains Mono)** — Rejected in favor of system font stack (SEC-001) to avoid external dependencies, privacy concerns, and render-blocking requests. System fonts provide near-identical appearance with zero performance cost.
- **ALT-004**: **Client-side Mermaid rendering** — Considered but server-side rendering (via rehype-mermaid or astro-mermaid) is preferred for performance (no JS bundle) and accessibility (SVG output). Client-side rendering adds ~200KB to the bundle.
- **ALT-005**: **Use Starlight's built-in `<Image>` component for all images** — Considered, but the Grafana screenshots are already imported via standard Markdown image syntax and Astro/Sharp handles optimization. Only worth changing if Lighthouse flags issues.
- **ALT-006**: **Switch to MkDocs Material** — The project already migrated FROM MkDocs (legacy `site/` directory contains the old MkDocs output). Reverting would lose the Starlight migration work already done.

## 4. Dependencies

- **DEP-001**: `@astrojs/starlight` ^0.37.6 — Already installed. Core framework.
- **DEP-002**: `astro` ^5.6.1 — Already installed. Build system.
- **DEP-003**: `sharp` ^0.34.2 — Already installed. Image optimization.
- **DEP-004**: Mermaid rendering plugin — **NEW**. One of: `@astrojs/starlight-mermaid`, `rehype-mermaid`, or `remark-mermaidjs`. Must be compatible with Starlight ^0.37.6 and Astro ^5.6.1. Research required in TASK-012.
- **DEP-005**: `pnpm` — Package manager (already in use, lockfile exists).
- **DEP-006**: Node.js — Required for Astro build. Version must match project's requirements (check `.node-version` or `engines` field).

## 5. Files

- **FILE-001**: `docs/astro.config.mjs` — Main Starlight configuration. Modified to add component overrides, meta tags, mermaid plugin, and structured data.
- **FILE-002**: `docs/src/styles/custom.css` — Primary custom stylesheet. Expanded from 3 lines to comprehensive theme system.
- **FILE-003**: `docs/src/styles/theme.css` — **NEW** (optional). Color palette and typography tokens if CSS split is needed.
- **FILE-004**: `docs/src/styles/responsive.css` — **NEW** (optional). Responsive and print media queries if CSS split is needed.
- **FILE-005**: `docs/src/components/overrides/Footer.astro` — **NEW**. Custom footer component override.
- **FILE-006**: `docs/src/components/overrides/Header.astro` — **NEW** (optional). Custom header with announcement banner.
- **FILE-007**: `docs/src/components/overrides/Hero.astro` — **NEW**. Enhanced hero component override.
- **FILE-008**: `docs/src/components/Architecture.astro` — **NEW**. Diagram wrapper MDX component.
- **FILE-009**: `docs/src/components/Version.astro` — **NEW**. Version badge MDX component.
- **FILE-010**: `docs/src/content/docs/index.mdx` — Landing page. Enhanced with new sections and badges.
- **FILE-011**: `docs/src/content/docs/architecture/index.mdx` — Architecture overview. Mermaid diagrams should render after Phase 3.
- **FILE-012**: `docs/src/content/docs/monitoring/grafana.mdx` — Grafana page. Alt text improvements for images.
- **FILE-013**: `docs/src/assets/logo.svg` — Logo. Color updates to match new palette.
- **FILE-014**: `docs/public/og-image.png` — **NEW**. Open Graph image for social sharing (1200×630).
- **FILE-015**: `docs/public/apple-touch-icon.png` — **NEW** (optional). Apple touch icon.
- **FILE-016**: `docs/package.json` — Updated with new mermaid dependency.
- **FILE-017**: `docs/README.md` — Updated with design system documentation.

## 6. Testing

- **TEST-001**: **Build verification** — `cd docs && pnpm build` completes without errors or warnings.
- **TEST-002**: **Visual regression — dark mode** — All pages render correctly in dark mode. Check: hero, cards, code blocks, tables, callouts, mermaid diagrams.
- **TEST-003**: **Visual regression — light mode** — All pages render correctly in light mode. Same checks as TEST-002.
- **TEST-004**: **Mermaid rendering** — All `mermaid` code blocks in architecture pages render as SVG diagrams, not raw code. Verify in both dark and light mode.
- **TEST-005**: **Responsive — 320px** — All pages are usable at 320px viewport. Tables scroll horizontally. Code blocks scroll. Hero stacks vertically. Sidebar menu works.
- **TEST-006**: **Responsive — 768px** — Tablet layout works. Sidebar is accessible.
- **TEST-007**: **Responsive — 1440px+** — Wide screen layout. Content doesn't stretch excessively.
- **TEST-008**: **Accessibility — Lighthouse** — Run Lighthouse accessibility audit. Score ≥ 90.
- **TEST-009**: **Accessibility — keyboard** — Tab through all pages. Verify: no focus traps, visible focus indicators, sidebar navigation, search dialog, mobile menu.
- **TEST-010**: **Accessibility — screen reader** — Verify heading hierarchy (H1→H2→H3, no skips). Verify ARIA landmarks. Verify image alt text.
- **TEST-011**: **SEO — Lighthouse** — Run Lighthouse SEO audit. Score ≥ 90.
- **TEST-012**: **Performance — Lighthouse** — Run Lighthouse performance audit. Score ≥ 90.
- **TEST-013**: **OG image** — Verify `<meta property="og:image">` points to existing file. Test with social media preview tools (e.g., Twitter Card Validator, Facebook Sharing Debugger).
- **TEST-014**: **Print** — Print preview (`Ctrl+P`) shows content without navigation chrome. Links show URLs.
- **TEST-015**: **Favicon** — Verify favicon appears in browser tab. Verify apple-touch-icon.

## 7. Risks & Assumptions

- **RISK-001**: **Mermaid plugin compatibility** — The chosen mermaid plugin may not be compatible with Starlight ^0.37.6 or Astro ^5.6.1. **Mitigation**: Research plugin compatibility before installation (TASK-012). Fallback: use `rehype-mermaid` with Playwright for server-side SVG rendering, or embed pre-rendered SVG images.
- **RISK-002**: **Component override breaking changes** — Starlight component overrides depend on internal APIs that may change between minor versions. **Mitigation**: Pin Starlight version, test after updates, keep overrides minimal (extend rather than replace).
- **RISK-003**: **CSS custom property name changes** — Starlight may rename `--sl-*` variables between versions. **Mitigation**: Reference Starlight's source code for exact variable names, pin version.
- **RISK-004**: **OG image generation** — Creating a good-looking OG image programmatically requires either a design tool or a code-based generator. **Mitigation**: Use a simple Canvas/SVG-based approach or generate manually with Figma/Canva.
- **RISK-005**: **Build time increase** — Server-side mermaid rendering (Playwright) can significantly increase build time. **Mitigation**: Measure build time before and after. If too slow, switch to pre-rendered SVG images or client-side rendering as fallback.
- **ASSUMPTION-001**: The project maintainer (jmrplens) has access to modify the GitHub Pages deployment configuration if needed.
- **ASSUMPTION-002**: The existing content quality is good and doesn't need rewriting — only presentation improvements.
- **ASSUMPTION-003**: pnpm is available in the CI/CD environment for building the docs.
- **ASSUMPTION-004**: The `site/` directory (old MkDocs output) will eventually be removed and is not part of this plan's scope.
- **ASSUMPTION-005**: The system font stack will be visually acceptable without installing specific fonts — this can be upgraded to self-hosted fonts later if needed.

## 8. Related Specifications / Further Reading

- [Starlight Customization Guide](https://starlight.astro.build/guides/customization/)
- [Starlight CSS & Styling](https://starlight.astro.build/guides/css-and-tailwind/)
- [Starlight Component Overrides](https://starlight.astro.build/guides/overriding-components/)
- [Starlight Sidebar Configuration](https://starlight.astro.build/guides/sidebar/)
- [WCAG 2.2 Quick Reference](https://www.w3.org/WAI/WCAG22/quickref/)
- [Astro Image Optimization](https://docs.astro.build/en/guides/images/)
- [Mermaid.js Documentation](https://mermaid.js.org/)
- [Web Content Accessibility Guidelines (WCAG) 2.2](https://www.w3.org/TR/WCAG22/)
- [Open Graph Protocol](https://ogp.me/)
- [Lighthouse Scoring Guide](https://developer.chrome.com/docs/lighthouse/overview/)
