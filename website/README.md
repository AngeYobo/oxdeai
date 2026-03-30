# OxDeAI Website

Static, single-page technical site for [OxDeAI](https://github.com/AngeYobo/oxdeai).

Plain HTML + CSS. No build step. No dependencies.

## Run locally

Serve the `website/` directory with any static file server:

```bash
# From repo root
pnpm --filter website serve

# Or directly
cd website && pnpm dlx serve .
# open http://localhost:3000
```

## Deploy

### Vercel

1. Import the repo.
2. Set **Root Directory** to `website`.
3. Framework preset: **Other** (static).
4. Deploy. Done.

### Netlify

1. Connect the repo.
2. Set **Publish directory** to `website`.
3. Leave Build command empty.
4. Deploy.

### GitHub Pages

```bash
# From repo root — publish the website/ subdirectory as a subtree
git subtree push --prefix website origin gh-pages
```

Or configure GitHub Pages in Settings → Pages → Source: `website/` folder on `main`.

## Assets

- `assets/demo.gif` — copied from `docs/media/demo.gif` at build time.

To refresh the demo GIF after regenerating it:

```bash
cp docs/media/demo.gif website/assets/demo.gif
```

## Structure

```
website/
├── index.html      # Single-page site
├── style.css       # All styles
├── assets/
│   └── demo.gif    # Terminal demo
└── README.md       # This file
```

## Content changes

All content lives in `index.html`. Sections follow the page order:
`#hero` → `#how` → `#architecture` → `#why` → `#proof` → `#demo` → `#code` → `#trust` → `#ecosystem`

The site uses no external dependencies — no CDN, no analytics, no tracking.
