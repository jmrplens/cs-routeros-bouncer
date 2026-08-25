# cs-routeros-bouncer — Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

Documentation site for **cs-routeros-bouncer**, the CrowdSec bouncer for MikroTik RouterOS.
Live at: <https://jmrplens.github.io/cs-routeros-bouncer>

## Project Structure

```text
docs/
├── public/              # Static assets (og-image, favicon)
├── src/
│   ├── assets/          # Logo, images
│   ├── components/
│   │   └── overrides/   # Starlight component overrides (Header, Footer)
│   ├── content/docs/    # MDX documentation pages
│   └── styles/          # Custom CSS theme system
├── astro.config.mjs     # Starlight + Astro configuration
└── package.json
```

### Key customizations

- **Theme system** — Single-concern stylesheets under `src/styles/`, registered in order in `astro.config.mjs`: `theme.css` (palette tokens, both themes) first so the rest can reference it, then `typography.css`, `chrome.css`, `code.css`, `tables.css`, `home.css` and `a11y.css` (high-contrast, reduced motion, print). Colour tokens are gated by `scripts/check-contrast.mjs`
- **Mermaid diagrams** — Server-side rendering via `rehype-mermaid` (requires Playwright)
- **Component overrides** — Custom Header (announcement bar) and Footer
- **SEO** — Open Graph/Twitter meta tags, JSON-LD structured data, sitemap
- **Accessibility** — WCAG focus indicators, reduced-motion support, proper ARIA landmarks

## Commands

| Command        | Action                                 |
| :------------- | :------------------------------------- |
| `pnpm install` | Install dependencies                   |
| `pnpm dev`     | Start dev server at `localhost:4321`   |
| `pnpm analyze` | Run all docs checks                    |
| `pnpm lint`    | Run ESLint                             |
| `pnpm format`  | Format docs sources                    |
| `pnpm build`   | Build production site to `./dist/`     |
| `pnpm preview` | Preview build locally before deploying |

> **Note:** First install requires `pnpm approve-builds` to approve esbuild/sharp post-install scripts, and Playwright's Chromium browser (`npx playwright install chromium`).
