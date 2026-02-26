# cs-routeros-bouncer — Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

Documentation site for **cs-routeros-bouncer**, the CrowdSec bouncer for MikroTik RouterOS.
Live at: <https://jmrplens.github.io/cs-routeros-bouncer>

## Project Structure

```
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

- **Theme system** — Full design system in `src/styles/custom.css` (color palette, typography, dark/high-contrast modes, responsive tables, print styles)
- **Mermaid diagrams** — Server-side rendering via `rehype-mermaid` (requires Playwright)
- **Component overrides** — Custom Header (announcement bar) and Footer
- **SEO** — Open Graph/Twitter meta tags, JSON-LD structured data, sitemap
- **Accessibility** — WCAG focus indicators, reduced-motion support, proper ARIA landmarks

## Commands

| Command          | Action                                      |
| :--------------- | :------------------------------------------ |
| `pnpm install`   | Install dependencies                        |
| `pnpm dev`       | Start dev server at `localhost:4321`         |
| `pnpm build`     | Build production site to `./dist/`           |
| `pnpm preview`   | Preview build locally before deploying       |

> **Note:** First install requires `pnpm approve-builds` to approve esbuild/sharp post-install scripts, and Playwright's Chromium browser (`npx playwright install chromium`).
